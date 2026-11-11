# resposta automatizada (SOAR caseiro)
# le os alertas do detector e executa os playbooks.
# regra de ouro: so faz sozinho o que e BAIXO RISCO. o que e alto impacto vira pedido
# na tabela respostas_pendentes e so roda depois que alguem da coordenacao aprova no painel.
#
# uso:
#   python3 soc/responder.py              -> fica ouvindo logs/alertas.log
#   python3 soc/responder.py --simular    -> so mostra o que faria, nao executa nada
#   python3 soc/responder.py --acao revogar --alvo ubs-energia-01   -> acao manual
import argparse
import json
import os
import subprocess
import time
from datetime import datetime, timezone

RAIZ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOGS = os.path.join(RAIZ, "logs")
SIMULAR = False

# classificacao de risco de cada acao (vai pro relatorio tambem)
RISCO = {
    "encerrar_sessao_vpn": "baixo",
    "bloquear_ip": "baixo",
    "isolar_dispositivo": "baixo",
    "revogar_certificado": "baixo",
    "modo_seguro_atuador": "baixo",
    "desligar_bomba": "alto",
    "tirar_painel_legado_do_ar": "alto",
    "liberar_todas_as_portas": "alto",
}


def agora():
    return datetime.now(timezone.utc)


def iso(d):
    return d.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def env():
    e = {}
    for l in open(os.path.join(RAIZ, ".env")):
        if "=" in l and not l.startswith("#"):
            k, v = l.strip().split("=", 1)
            e[k] = v
    return e


def registrar(acao, alvo, resultado, alerta=None, **extra):
    d = {"ts": iso(agora()), "servico": "responder", "evento": "resposta", "acao": acao, "risco": RISCO.get(acao),
         "alvo": alvo, "resultado": resultado, "simulado": SIMULAR, **extra}
    if alerta:
        d["regra"] = alerta.get("regra")
        d["ts_alerta"] = alerta.get("ts")
        d["ts_evento"] = alerta.get("ts_evento")
        try:
            d["mttr_seg"] = round((agora() - datetime.fromisoformat(alerta["ts"].replace("Z", "+00:00"))).total_seconds(), 3)
        except (KeyError, ValueError):
            pass
    with open(os.path.join(LOGS, "respostas.log"), "a") as f:
        f.write(json.dumps(d, ensure_ascii=False) + "\n")
    print(f"  -> {acao} ({RISCO.get(acao)}) alvo={alvo}: {resultado}")


def sh(cmd):
    if SIMULAR:
        return "simulado: " + " ".join(cmd)
    r = subprocess.run(cmd, capture_output=True, text=True)
    return "ok" if r.returncode == 0 else f"erro: {r.stderr.strip()[:200]}"


def sql(q):
    e = env()
    return sh(["docker", "exec", "db", "psql", "-U", e["POSTGRES_USER"], "-d", e["POSTGRES_DB"], "-Atc", q])


def q(s):
    return "'" + str(s).replace("'", "''") + "'"


# ---------- acoes de baixo risco ----------

def encerrar_sessao_vpn(peer, alerta=None):
    try:
        peers = json.load(open(os.path.join(RAIZ, "vpn/gerado/peers.json")))
    except OSError:
        peers = {}
    pub = next((k for k, v in peers.items() if v == peer), None)
    if not pub:
        return registrar("encerrar_sessao_vpn", peer, "peer nao encontrado", alerta)
    # remove o peer do wireguard ate alguem reemitir a chave (volta se reiniciar o gw)
    registrar("encerrar_sessao_vpn", peer, sh(["docker", "exec", "nuvem-gw", "wg", "set", "wg0", "peer", pub, "remove"]), alerta)


def bloquear_ip(ip, alerta=None):
    if not ip or ip.startswith("10.10.0."):
        return registrar("bloquear_ip", ip, "ip interno do tunel, nao bloqueado (usar encerrar sessao)", alerta)
    registrar("bloquear_ip", ip, sh(["docker", "exec", "nuvem-gw", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]), alerta)


def isolar_dispositivo(ip, alerta=None):
    # acha o container pelo ip nas redes de IoT e tira ele da rede
    if not ip:
        return registrar("isolar_dispositivo", ip, "sem ip", alerta)
    for rede in ("vila-aurora_iot_escola", "vila-aurora_iot_ubs"):
        if SIMULAR:
            return registrar("isolar_dispositivo", ip, f"simulado: docker network disconnect {rede} <container do ip>", alerta)
        r = subprocess.run(["docker", "network", "inspect", rede, "-f",
                            "{{range .Containers}}{{.Name}} {{.IPv4Address}}\n{{end}}"], capture_output=True, text=True)
        for linha in r.stdout.splitlines():
            if not linha.strip():
                continue
            nome, end = linha.split()
            if end.split("/")[0] == ip and not nome.startswith("borda"):
                return registrar("isolar_dispositivo", f"{nome} ({ip})",
                                 sh(["docker", "network", "disconnect", rede, nome]), alerta)
    registrar("isolar_dispositivo", ip, "container nao encontrado", alerta)


def revogar_certificado(cn, alerta=None):
    registrar("revogar_certificado", cn, sh([os.path.join(RAIZ, "pki/revogar.sh"), cn, "keyCompromise"]), alerta)
    sql(f"UPDATE dispositivos SET revogado=true, ativo=false WHERE cn={q(cn)}")


def modo_seguro_atuador(dispositivo, alerta=None):
    # modo seguro = a bomba so obedece a regra local da borda, ignora agenda/comando da nuvem
    espaco = dispositivo.split("-")[0]
    r = sql("INSERT INTO comandos (espaco, dispositivo, acao, solicitado_por, perfil, alto_impacto, status) "
            f"VALUES ({q(espaco)}, {q(dispositivo)}, 'modo_seguro', 'soar', 'soar', false, 'liberado')")
    registrar("modo_seguro_atuador", dispositivo, r, alerta)


# ---------- alto impacto: so pede aprovacao ----------

def pedir_aprovacao(acao, alvo, justificativa, alerta=None):
    r = sql("INSERT INTO respostas_pendentes (alerta, acao, alvo, justificativa) VALUES "
            f"({q(alerta.get('regra') if alerta else 'manual')}, {q(acao)}, {q(alvo)}, {q(justificativa)})")
    registrar(acao, alvo, "aguardando aprovacao humana: " + r, alerta)


def executar_aprovadas():
    if SIMULAR:
        return
    e = env()
    r = subprocess.run(["docker", "exec", "db", "psql", "-U", e["POSTGRES_USER"], "-d", e["POSTGRES_DB"], "-Atc",
                        "SELECT id, acao, alvo, decidido_por FROM respostas_pendentes WHERE status='aprovada'"],
                       capture_output=True, text=True)
    for linha in r.stdout.strip().splitlines():
        rid, acao, alvo, quem = linha.split("|")
        if acao == "desligar_bomba":
            res = sql("INSERT INTO comandos (espaco, dispositivo, acao, solicitado_por, perfil, alto_impacto, status, aprovado_por, aprovado_em) "
                      f"VALUES ('escola', {q(alvo)}, 'desligar', 'soar', 'soar', true, 'liberado', {q(quem)}, now())")
        elif acao == "tirar_painel_legado_do_ar":
            res = sh(["docker", "stop", "painel-legado"])
        else:
            res = "acao sem implementacao automatica, fazer manual"
        sql(f"UPDATE respostas_pendentes SET status='executada' WHERE id={int(rid)}")
        registrar(acao, alvo, res, aprovado_por=quem, resposta_id=int(rid))


# ---------- playbooks por regra ----------

def playbook(a):
    regra, alvo = a.get("regra"), a.get("alvo", {})
    print(f"[{a.get('ts')}] alerta {regra}: {a.get('detalhe')}")
    if regra == "VPN_ANOMALA":
        encerrar_sessao_vpn(alvo.get("peer"), a)
        bloquear_ip(alvo.get("ip"), a)
    elif regra == "SQLI":
        bloquear_ip(alvo.get("ip"), a)
        if alvo.get("servico") == "painel-legado":
            pedir_aprovacao("tirar_painel_legado_do_ar", "painel-legado",
                            "SQL injection confirmado no painel legado. Tirar do ar interrompe consultas dos voluntarios.", a)
    elif regra == "DISPOSITIVO_SEM_CERT":
        isolar_dispositivo(alvo.get("ip"), a)
    elif regra == "ATUADOR_FORA_PERFIL":
        disp = alvo.get("dispositivo") or "escola-bomba-01"
        if disp.startswith("escola-bomba"):
            modo_seguro_atuador(disp, a)
            pedir_aprovacao("desligar_bomba", disp,
                            "Comando/agenda suspeita na bomba. Desligar pode deixar a escola sem agua, precisa decisao humana.", a)


def seguir():
    caminho = os.path.join(LOGS, "alertas.log")
    open(caminho, "a").close()
    with open(caminho) as f:
        f.seek(0, os.SEEK_END)
        ult = 0
        while True:
            linha = f.readline()
            if linha:
                try:
                    playbook(json.loads(linha))
                except ValueError:
                    pass
                continue
            if f.tell() > os.path.getsize(caminho):
                f.seek(0)   # arquivo foi zerado
            if time.time() - ult > 5:
                ult = time.time()
                executar_aprovadas()
            time.sleep(0.5)


def main():
    global SIMULAR
    ap = argparse.ArgumentParser()
    ap.add_argument("--simular", action="store_true")
    ap.add_argument("--acao", choices=["revogar", "isolar", "bloquear_ip", "encerrar_vpn", "modo_seguro"])
    ap.add_argument("--alvo")
    a = ap.parse_args()
    SIMULAR = a.simular
    if a.acao:
        {"revogar": revogar_certificado, "isolar": isolar_dispositivo, "bloquear_ip": bloquear_ip,
         "encerrar_vpn": encerrar_sessao_vpn, "modo_seguro": modo_seguro_atuador}[a.acao](a.alvo)
        return
    print("responder ouvindo logs/alertas.log" + (" (SIMULANDO)" if SIMULAR else ""))
    seguir()


if __name__ == "__main__":
    main()
