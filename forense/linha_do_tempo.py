# monta a linha do tempo consolidada a partir dos logs coletados
# todos os horarios sao convertidos pra UTC (e mostra o horario de Brasilia do lado)
#
# uso:
#   python3 forense/linha_do_tempo.py evidencias/INC-VA-0712-LAB/<ts>/logs
#   python3 forense/linha_do_tempo.py logs --inicio 2026-11-12T05:00 --fim 2026-11-12T06:00
# saida: linha_do_tempo.csv e linha_do_tempo.md na pasta atual (ou --saida)
import argparse
import csv
import glob
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

BRT = ZoneInfo("America/Sao_Paulo")

# evento -> (tatica, tecnica ATT&CK). enterprise + ICS
ATTCK = {
    "login_ok@painel-legado": ("Initial Access", "T1078 Valid Accounts"),
    "busca_historico": ("Initial Access", "T1190 Exploit Public-Facing Application"),
    "erro_sql": ("Discovery", "T1190 (sondagem da injecao)"),
    "vpn_handshake": ("Initial Access", "T1133 External Remote Services"),
    "agendamento_rejeitado": ("Impair Process Control (ICS)", "T0836 Modify Parameter"),
    "update_agendamento": ("Impair Process Control (ICS)", "T0836 Modify Parameter"),
    "select_usuarios": ("Collection", "T1213 Data from Information Repositories"),
    "comando_rejeitado": ("Impair Process Control (ICS)", "T0855 Unauthorized Command Message"),
    "certificado_revogado": ("Resposta", "-"),
    "link_wan_caiu": ("Impacto operacional", "T0826 Loss of Availability (natural, nao ataque)"),
    "alarme_camara": ("Impacto operacional", "T0880 Loss of Safety"),
    "mqtt_sem_cert": ("Initial Access (ICS)", "T0848 Rogue Master"),
}

# eventos de rotina que so poluem a linha do tempo
RUIDO = {"metricas_borda", "lote_enviado", "lote_recebido", "http", "comandos_entregues", "monitor_vpn_iniciado",
         "broker_local_conectado", "conectado_broker", "ainda_sem_link"}


def parse_ts(s):
    if not s:
        return None
    s = str(s).strip().replace(" UTC", "+00:00").replace("Z", "+00:00")
    if "T" not in s and " " in s:
        s = s.replace(" ", "T", 1)
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def resumo_json(d):
    ev = d.get("evento", "")
    partes = []
    for k in ("usuario", "usuario_tentado", "peer", "endpoint_ip", "ip", "cliente_ip", "busca", "motivo", "problemas",
              "mensagem", "acao", "alvo", "resultado", "regra", "detalhe", "erro", "cn", "offline_seg", "via", "status",
              "uri", "dispositivo", "aprovado_por", "decidido_por"):
        if k in d and d[k] not in (None, "", []):
            v = d[k] if isinstance(d[k], str) else json.dumps(d[k], ensure_ascii=False)
            partes.append(f"{k}={v[:140]}")
    return ev, "; ".join(partes)


def classificar(ev, servico, texto):
    if ev == "login_ok" and servico == "painel-legado":
        return ATTCK["login_ok@painel-legado"]
    if ev == "busca_historico" and re.search(r"union|'|;|--", texto, re.I):
        return ATTCK["busca_historico"]
    if ev == "postgres" and re.search(r"update\s+agendamento_bomba", texto, re.I):
        return ATTCK["update_agendamento"]
    if ev == "alerta_local" and "camara" in texto:
        return ATTCK["alarme_camara"]
    return ATTCK.get(ev, ("", ""))


def ler(pasta, tudo):
    eventos = []
    arquivos = sorted(glob.glob(os.path.join(pasta, "**", "*.log"), recursive=True) +
                      glob.glob(os.path.join(pasta, "**", "*.json"), recursive=True))
    for arq in arquivos:
        fonte = os.path.relpath(arq, pasta)
        ultimo_ip = None
        try:
            f = open(arq, errors="replace")
        except (PermissionError, OSError):
            continue   # logs com dono restrito (ex.: mosquitto) sao ignorados
        with f:
            for n, linha in enumerate(f, 1):
                linha = linha.strip()
                if not linha:
                    continue
                if linha.startswith("{"):
                    try:
                        d = json.loads(linha)
                    except ValueError:
                        continue
                    if "transaction" in d:   # audit do modsecurity
                        tr = d["transaction"]
                        ts = parse_ts(tr.get("time_stamp"))
                        ev, txt = "waf_audit", f"ip={tr.get('client_ip')}; uri={tr.get('request', {}).get('uri', '')[:140]}"
                        serv = "waf"
                    elif "error_severity" in d or d.get("backend_type"):   # jsonlog do postgres
                        ts = parse_ts(d.get("timestamp"))
                        ev = "postgres"
                        serv = "db"
                        txt = f"user={d.get('user')}; host={d.get('remote_host')}; msg={str(d.get('message', ''))[:160]}"
                        # so mantem postgres relevante pra seguranca; corta telemetria/rotina
                        if not tudo and not re.search(
                                r"agendamento_bomba|legado\.|UNION\s+SELECT|information_schema|DROP |pg_sleep|OR\s+1=1",
                                str(d.get('message', '')), re.I):
                            continue
                    else:
                        ts = parse_ts(d.get("ts"))
                        ev, txt = resumo_json(d)
                        serv = d.get("servico", "")
                        if not tudo and ev in RUIDO:
                            continue
                else:
                    # mosquitto: "2026-11-09T10:39:09: mensagem"
                    ts = parse_ts(linha[:19])
                    msg = linha[21:]
                    m = re.search(r"New connection from ([\d.]+)", msg)
                    if m:
                        ultimo_ip = m.group(1)
                        if not tudo:
                            continue
                    serv = "mosquitto"
                    ev = "mqtt_sem_cert" if re.search(r"certificate", msg) else "mqtt"
                    if not tudo and ev == "mqtt" and not re.search(r"denied|error|revoked", msg, re.I):
                        continue
                    txt = msg + (f" (origem {ultimo_ip})" if ev == "mqtt_sem_cert" and ultimo_ip else "")
                if not ts:
                    continue
                tat, tec = classificar(ev, serv, txt)
                eventos.append({"utc": ts, "fonte": f"{fonte}:{n}", "servico": serv, "evento": ev,
                                "detalhe": txt, "tatica": tat, "tecnica": tec})
    eventos.sort(key=lambda e: e["utc"])
    return eventos


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pasta")
    ap.add_argument("--inicio")
    ap.add_argument("--fim")
    ap.add_argument("--tudo", action="store_true", help="inclui eventos de rotina")
    ap.add_argument("--seguranca", action="store_true", help="so os eventos com tecnica MITRE (a cadeia do ataque)")
    ap.add_argument("--saida", default=".")
    a = ap.parse_args()
    evs = ler(a.pasta, a.tudo)
    if a.inicio:
        ini = parse_ts(a.inicio)
        evs = [e for e in evs if e["utc"] >= ini]
    if a.fim:
        fim = parse_ts(a.fim)
        evs = [e for e in evs if e["utc"] <= fim]
    if a.seguranca:
        evs = [e for e in evs if e["tecnica"]]

    os.makedirs(a.saida, exist_ok=True)
    with open(os.path.join(a.saida, "linha_do_tempo.csv"), "w", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["utc", "brasilia", "servico", "evento", "detalhe", "tatica", "tecnica", "fonte"])
        for e in evs:
            w.writerow([e["utc"].isoformat(timespec="milliseconds"), e["utc"].astimezone(BRT).strftime("%d/%m %H:%M:%S"),
                        e["servico"], e["evento"], e["detalhe"], e["tatica"], e["tecnica"], e["fonte"]])
    with open(os.path.join(a.saida, "linha_do_tempo.md"), "w") as f:
        f.write("| UTC | Brasília | Serviço | Evento | Detalhe | ATT&CK |\n|---|---|---|---|---|---|\n")
        for e in evs:
            det = e["detalhe"].replace("|", "/")[:180]
            f.write(f"| {e['utc'].strftime('%H:%M:%S.%f')[:-3]} | {e['utc'].astimezone(BRT).strftime('%H:%M:%S')} | "
                    f"{e['servico']} | {e['evento']} | {det} | {e['tecnica']} |\n")
    print(f"{len(evs)} eventos -> {a.saida}/linha_do_tempo.csv e .md")


if __name__ == "__main__":
    main()
