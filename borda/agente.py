# agente do no de borda
# - recebe telemetria dos dispositivos pelo broker local (mTLS)
# - aplica as regras locais (funciona mesmo sem internet)
# - guarda tudo num buffer sqlite e manda pra nuvem quando o link volta (store-and-forward)
# - busca comandos/agendamento na nuvem e valida antes de obedecer
import hashlib
import hmac
import json
import os
import sqlite3
import ssl
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import paho.mqtt.client as mqtt
import psutil
import requests

ESPACO = os.environ["ESPACO"]                       # escola ou ubs
CN = os.environ.get("BORDA_CN", f"borda-{ESPACO}")
NUVEM = os.environ.get("NUVEM_URL", "https://10.10.0.1")
PKI = os.environ.get("PKI_DIR", "/pki")
DB_PATH = os.environ.get("BUFFER_DB", "/dados/buffer.db")
LOG_PATH = os.environ.get("LOG_PATH", f"/logs/borda-{ESPACO}.log")
MODO_LEGADO = os.environ.get("MODO_LEGADO", "0") == "1"   # usado so pra reproduzir o incidente
CHAVE_PSEUDO = os.environ.get("PSEUDO_CHAVE", "troque-isso").encode()
GW_PUB = os.environ.get("WG_GW_PUB", "")
ENDPOINT_PRINCIPAL = os.environ.get("ENDPOINT_PRINCIPAL", "gw-fibra:51820")
ENDPOINT_RESERVA = os.environ.get("ENDPOINT_RESERVA", "")      # vazio = sem 4g
SYNC_SEG = float(os.environ.get("SYNC_SEG", "5"))
TZ = ZoneInfo(os.environ.get("TZ_LOCAL", "America/Sao_Paulo"))

# limites que a borda NAO aceita mudar pela nuvem (defesa contra o que aconteceu no INC-VA-0712)
PISO_NIVEL = 25.0          # abaixo disso liga a bomba de qualquer jeito
TETO_NIVEL = 97.0          # acima disso desliga (nao transbordar)
BOMBA_MAX_MIN = 45         # tempo maximo ligada direto
CAMARA_MIN, CAMARA_MAX = 2.0, 8.0   # faixa das vacinas
JANELA_PADRAO = (6, 22)    # comando manual so das 6h as 22h sem aprovacao

lock = threading.Lock()
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.execute("""CREATE TABLE IF NOT EXISTS buffer(
    msg_id TEXT PRIMARY KEY, ts TEXT, dispositivo TEXT, tipo TEXT,
    payload TEXT, prioridade INTEGER DEFAULT 0, enviado INTEGER DEFAULT 0)""")
db.execute("CREATE TABLE IF NOT EXISTS config(chave TEXT PRIMARY KEY, valor TEXT)")
db.execute("CREATE INDEX IF NOT EXISTS idx_pend ON buffer(enviado, prioridade)")
db.commit()

st = {
    "link": "desconhecido",       # ok / caiu
    "via": "principal",           # principal (fibra) ou reserva (4g)
    "falhas": 0,
    "caiu_em": None,
    "bomba": False,
    "bomba_desde": None,
    "bomba_cmd_ts": 0,
    "temp_fora": 0,
    "alarme_camara": False,
    "bytes_env": 0,
    "ultimo_teste_principal": 0,
}
cli = None


def agora():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log(evento, **extra):
    linha = json.dumps({"ts": agora(), "servico": CN, "espaco": ESPACO, "evento": evento, **extra},
                       ensure_ascii=False)
    print(linha, flush=True)
    with open(LOG_PATH, "a") as f:
        f.write(linha + "\n")


def guardar(dispositivo, tipo, payload, prioridade=0, msg_id=None):
    msg_id = msg_id or str(uuid.uuid4())
    with lock:
        db.execute("INSERT OR IGNORE INTO buffer(msg_id, ts, dispositivo, tipo, payload, prioridade) "
                   "VALUES (?,?,?,?,?,?)",
                   (msg_id, payload.get("ts", agora()), dispositivo, tipo, json.dumps(payload), prioridade))
        db.commit()


def cfg_get(chave, padrao=None):
    with lock:
        r = db.execute("SELECT valor FROM config WHERE chave=?", (chave,)).fetchone()
    return json.loads(r[0]) if r else padrao


def cfg_set(chave, valor):
    with lock:
        db.execute("INSERT OR REPLACE INTO config VALUES (?,?)", (chave, json.dumps(valor)))
        db.commit()


def pseudonimo(cracha):
    # LGPD: o id do cracha nunca sai da borda em claro
    return "P-" + hmac.new(CHAVE_PSEUDO, cracha.encode(), hashlib.sha256).hexdigest()[:16]


def alerta(tipo, msg, **extra):
    a = {"ts": agora(), "tipo_alerta": tipo, "mensagem": msg, "origem": "regra_local", **extra}
    log("alerta_local", tipo_alerta=tipo, mensagem=msg, **extra)
    guardar(CN, "alerta", a, prioridade=2)
    if cli:
        cli.publish(f"vilaaurora/alertas/{ESPACO}", json.dumps(a), qos=1)


def mandar_cmd(dispositivo, acao, origem, **extra):
    if cli:
        cli.publish(f"vilaaurora/{dispositivo}/comando",
                    json.dumps({"acao": acao, "origem": origem, "ts": agora(), **extra}), qos=1)


# ---------- regras locais ----------

def set_bomba(ligar, motivo):
    if ligar == st["bomba"]:
        return
    st["bomba"] = ligar
    st["bomba_desde"] = time.time() if ligar else None
    st["bomba_cmd_ts"] = time.time()
    mandar_cmd("escola-bomba-01", "ligar" if ligar else "desligar", motivo)
    # o sensor de nivel precisa saber pra simular o enchimento
    if cli:
        cli.publish("vilaaurora/escola-nivel-01/comando", json.dumps({"bomba_ligada": ligar}), qos=1)
    log("bomba_" + ("ligada" if ligar else "desligada"), motivo=motivo)


def regra_nivel(nivel):
    ag = cfg_get("agendamento", {"ativo": True, "nivel_liga": 40, "nivel_desliga": 90})

    if MODO_LEGADO:
        # comportamento antigo: so obedece a agenda da nuvem, sem limite local nenhum
        if not ag.get("ativo", True):
            set_bomba(False, "agenda_nuvem")
        elif nivel < ag["nivel_liga"]:
            set_bomba(True, "agenda_nuvem")
        elif nivel > ag["nivel_desliga"]:
            set_bomba(False, "agenda_nuvem")
        return

    if nivel < PISO_NIVEL and not st["bomba"]:
        set_bomba(True, "regra_local_piso")
        alerta("nivel_critico", f"Reservatorio da escola em {nivel:.0f}%, bomba ligada pela regra local",
               nivel=nivel)
    elif nivel >= TETO_NIVEL:
        set_bomba(False, "regra_local_teto")
    elif ag.get("ativo", True):
        if nivel < ag["nivel_liga"]:
            set_bomba(True, "agenda")
        elif nivel > ag["nivel_desliga"]:
            set_bomba(False, "agenda")


def regra_camara(temp):
    if MODO_LEGADO:
        return   # antes do projeto o alarme so existia na nuvem
    if temp > CAMARA_MAX or temp < CAMARA_MIN:
        st["temp_fora"] += 1
    else:
        st["temp_fora"] = 0
        if st["alarme_camara"]:
            st["alarme_camara"] = False
            log("alarme_normalizado", temperatura=temp)
            guardar(CN, "alerta", {"ts": agora(), "tipo_alerta": "camara_fria_normalizada", "temperatura": temp}, 2)
    # 2 leituras seguidas fora da faixa pra nao disparar a toa
    if st["temp_fora"] >= 2 and not st["alarme_camara"]:
        st["alarme_camara"] = True
        alerta("camara_fria", f"Camara fria da UBS em {temp:.1f} C, fora da faixa 2-8 C. Verificar a porta e as vacinas.",
               temperatura=temp)


def regra_tempo_bomba():
    if MODO_LEGADO or not st["bomba"] or not st["bomba_desde"]:
        return
    if time.time() - st["bomba_desde"] > BOMBA_MAX_MIN * 60:
        set_bomba(False, "regra_local_tempo_max")
        alerta("bomba_tempo_max", f"Bomba ligada mais de {BOMBA_MAX_MIN} min, desligada por seguranca")


# ---------- mqtt ----------

def on_connect(c, u, flags, rc, props=None):
    log("broker_local_conectado", rc=str(rc))
    c.subscribe("vilaaurora/+/telemetria", qos=1)


def on_message(c, u, msg):
    try:
        p = json.loads(msg.payload)
    except ValueError:
        log("payload_invalido", topico=msg.topic)
        return
    disp = msg.topic.split("/")[1]
    if p.get("dispositivo") != disp:
        # o topico ja e protegido pela ACL, mas confere de novo
        log("dispositivo_divergente", topico=msg.topic, declarado=p.get("dispositivo"))
        return
    d = p.get("dados", {})
    tipo = p.get("tipo")
    prioridade = 0

    if tipo == "fechadura" and "cracha" in d:
        d["cracha"] = pseudonimo(d["cracha"])
        prioridade = 1
    if tipo == "nivel":
        regra_nivel(d.get("nivel_pct", 50))
    if tipo == "camara_fria":
        regra_camara(d.get("temperatura_c", 5))
        prioridade = 1
    if tipo == "bomba" and d.get("ligada") != st["bomba"] and time.time() - st["bomba_cmd_ts"] > 10:
        # o dispositivo e quem sabe o estado real (ex: em modo seguro ele ignora a agenda)
        st["bomba"] = bool(d.get("ligada"))
        st["bomba_desde"] = time.time() if st["bomba"] else None
        c.publish("vilaaurora/escola-nivel-01/comando", json.dumps({"bomba_ligada": st["bomba"]}), qos=1)

    guardar(disp, tipo, p, prioridade, p.get("msg_id"))


# ---------- link com a nuvem ----------

def sessao():
    s = requests.Session()
    s.cert = (f"{PKI}/cert.pem", f"{PKI}/key.pem")
    s.verify = f"{PKI}/ca.crt"
    s.trust_env = False   # ignora proxy/CA do ambiente, so confia na CA do projeto
    return s


http = sessao()


def trocar_endpoint(destino):
    if not GW_PUB:
        return False
    ep = ENDPOINT_RESERVA if destino == "reserva" else ENDPOINT_PRINCIPAL
    r = subprocess.run(["wg", "set", "wg0", "peer", GW_PUB, "endpoint", ep], capture_output=True, text=True)
    if r.returncode != 0:
        log("falha_trocar_endpoint", destino=destino, erro=r.stderr.strip())
        return False
    st["via"] = destino
    log("link_trocado", via=destino, endpoint=ep)
    return True


def enviar():
    # no 4g a franquia e pequena, entao so manda o que e prioritario
    prio_min = 1 if st["via"] == "reserva" else 0
    with lock:
        linhas = db.execute("SELECT msg_id, dispositivo, tipo, payload, prioridade FROM buffer "
                            "WHERE enviado=0 AND prioridade>=? ORDER BY prioridade DESC, ts LIMIT 300",
                            (prio_min,)).fetchall()
    if not linhas:
        r = http.get(f"{NUVEM}/saude", timeout=4)
        r.raise_for_status()
        return 0
    itens = [{"msg_id": m, "dispositivo": d, "tipo": t, "payload": json.loads(p), "prioridade": pr}
             for m, d, t, p, pr in linhas]
    corpo = json.dumps({"borda": CN, "espaco": ESPACO, "via": st["via"], "itens": itens})
    r = http.post(f"{NUVEM}/ingest", data=corpo, headers={"Content-Type": "application/json"}, timeout=8)
    r.raise_for_status()
    st["bytes_env"] += len(corpo)
    ok = r.json().get("recebidos", [])
    with lock:
        db.executemany("UPDATE buffer SET enviado=1 WHERE msg_id=?", [(i,) for i in ok])
        db.commit()
    return len(ok)


def buscar_comandos():
    r = http.get(f"{NUVEM}/comandos", timeout=5)
    r.raise_for_status()
    for cmd in r.json():
        res = validar_e_executar(cmd)
        http.post(f"{NUVEM}/comandos/{cmd['id']}/resultado", json=res, timeout=5)


def janela_ok():
    h = datetime.now(TZ).hour
    return JANELA_PADRAO[0] <= h < JANELA_PADRAO[1]


def validar_e_executar(cmd):
    disp, acao = cmd.get("dispositivo", ""), cmd.get("acao", "")
    base = {"comando_id": cmd.get("id"), "dispositivo": disp, "acao": acao,
            "solicitado_por": cmd.get("solicitado_por"), "perfil": cmd.get("perfil")}
    if not disp.startswith(ESPACO + "-"):
        log("comando_rejeitado", motivo="dispositivo_de_outro_espaco", **base)
        return {"status": "rejeitado", "motivo": "dispositivo_de_outro_espaco"}
    if cmd.get("perfil") not in ("tecnico", "coordenacao", "soar"):
        log("comando_rejeitado", motivo="perfil_sem_permissao", **base)
        return {"status": "rejeitado", "motivo": "perfil_sem_permissao"}
    if cmd.get("alto_impacto") and not cmd.get("aprovado_por"):
        log("comando_rejeitado", motivo="alto_impacto_sem_aprovacao", **base)
        return {"status": "rejeitado", "motivo": "alto_impacto_sem_aprovacao"}
    if not janela_ok() and not cmd.get("aprovado_por") and acao != "modo_seguro":
        log("comando_rejeitado", motivo="fora_da_janela", **base)
        return {"status": "rejeitado", "motivo": "fora_da_janela"}

    if disp == "escola-bomba-01" and acao in ("ligar", "desligar"):
        set_bomba(acao == "ligar", f"comando_{cmd.get('solicitado_por')}")
    else:
        mandar_cmd(disp, acao, "nuvem", comando_id=cmd.get("id"))
    log("comando_executado", **base, aprovado_por=cmd.get("aprovado_por"))
    return {"status": "executado"}


def buscar_agendamento():
    if ESPACO != "escola":
        return
    r = http.get(f"{NUVEM}/agendamento", timeout=5)
    r.raise_for_status()
    ag = r.json()
    if not ag:
        return
    atual = cfg_get("agendamento")
    if ag == atual:
        return
    if not MODO_LEGADO:
        # valida faixa antes de aceitar. agenda desligada ou limite absurdo nao passa
        problemas = []
        if not (PISO_NIVEL <= ag.get("nivel_liga", 0) <= 80):
            problemas.append("nivel_liga_fora_da_faixa")
        if not (60 <= ag.get("nivel_desliga", 0) <= TETO_NIVEL):
            problemas.append("nivel_desliga_fora_da_faixa")
        if ag.get("nivel_liga", 0) >= ag.get("nivel_desliga", 100):
            problemas.append("limites_invertidos")
        if problemas:
            if cfg_get("ultimo_rejeitado") == ag:
                return   # ja avisou desse, nao fica repetindo o alerta
            cfg_set("ultimo_rejeitado", ag)
            log("agendamento_rejeitado", recebido=ag, problemas=problemas)
            alerta("agendamento_suspeito", "Agenda da bomba recebida da nuvem com valores fora do permitido. Mantida a agenda anterior.",
                   problemas=problemas)
            return
    cfg_set("agendamento", ag)
    log("agendamento_atualizado", agendamento=ag)
    if not ag.get("ativo", True) and not MODO_LEGADO:
        # pode desativar a agenda, mas o piso de 25% continua valendo
        log("aviso_agenda_desativada", piso_local=PISO_NIVEL)


def ciclo_link():
    pend_antes = None
    if st["link"] != "ok":
        with lock:
            pend_antes = db.execute("SELECT COUNT(*) FROM buffer WHERE enviado=0").fetchone()[0]
    try:
        n = enviar()
        buscar_comandos()
        buscar_agendamento()
        if st["link"] != "ok":
            dur = round(time.time() - st["caiu_em"], 1) if st["caiu_em"] else None
            log("link_restabelecido", via=st["via"], offline_seg=dur, pendentes_no_buffer=pend_antes)
            st["link"], st["caiu_em"] = "ok", None
        st["falhas"] = 0
        if n:
            log("lote_enviado", qtd=n, via=st["via"])
    except Exception as e:
        st["falhas"] += 1
        if st["falhas"] == 3 and st["link"] != "caiu":
            st["link"], st["caiu_em"] = "caiu", time.time()
            log("link_wan_caiu", via=st["via"], erro=type(e).__name__)
            if st["via"] == "principal" and ENDPOINT_RESERVA:
                trocar_endpoint("reserva")
                st["falhas"] = 0
        elif st["falhas"] % 20 == 0:
            log("ainda_sem_link", falhas=st["falhas"])

    # se esta no 4g, de tempos em tempos tenta voltar pra fibra
    if st["via"] == "reserva" and time.time() - st["ultimo_teste_principal"] > 120:
        st["ultimo_teste_principal"] = time.time()
        if trocar_endpoint("principal"):
            try:
                time.sleep(3)
                http.get(f"{NUVEM}/saude", timeout=5).raise_for_status()
                log("fibra_voltou")
            except Exception:
                trocar_endpoint("reserva")


def metricas():
    proc = psutil.Process()
    with lock:
        pend = db.execute("SELECT COUNT(*) FROM buffer WHERE enviado=0").fetchone()[0]
    log("metricas_borda", cpu_pct=psutil.cpu_percent(), proc_cpu_pct=proc.cpu_percent(),
        mem_mb=round(proc.memory_info().rss / 1e6, 1), mem_sis_pct=psutil.virtual_memory().percent,
        bytes_enviados=st["bytes_env"], pendentes=pend, link=st["link"], via=st["via"],
        bomba=st["bomba"], alarme_camara=st["alarme_camara"])


def main():
    global cli
    log("agente_iniciado", modo_legado=MODO_LEGADO, reserva=bool(ENDPOINT_RESERVA))
    cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=CN)
    cli.tls_set(ca_certs=f"{PKI}/ca.crt", certfile=f"{PKI}/cert.pem", keyfile=f"{PKI}/key.pem",
                tls_version=ssl.PROTOCOL_TLS_CLIENT)
    cli.on_connect = on_connect
    cli.on_message = on_message
    while True:
        try:
            # o hostname do container e o proprio CN, assim a verificacao de nome do TLS passa
            cli.connect(os.environ.get("BROKER_LOCAL", CN), 8883, 30)
            break
        except Exception as e:
            log("broker_local_indisponivel", erro=str(e))
            time.sleep(2)
    cli.loop_start()

    ult_sync = ult_met = 0
    while True:
        regra_tempo_bomba()
        if time.time() - ult_sync >= SYNC_SEG:
            ult_sync = time.time()
            ciclo_link()
        if time.time() - ult_met >= 30:
            ult_met = time.time()
            metricas()
        time.sleep(1)


if __name__ == "__main__":
    main()
