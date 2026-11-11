# detector simples de incidentes em cima dos logs centralizados (pasta logs/)
# implementa as 4 regras do RT-13. o Wazuh tem as mesmas regras (siem/), esse aqui
# serve de plano B se o PC nao aguentar o Wazuh e tambem pra medir o MTTD
#
# uso:
#   python3 soc/detector.py               -> fica seguindo os logs (tempo real)
#   python3 soc/detector.py --tudo        -> le os logs desde o inicio (bom pra reprocessar evidencia)
#   python3 soc/detector.py --pasta evidencias/.../logs --tudo --saida /tmp/alertas.log
import argparse
import glob
import json
import os
import re
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

TZ = ZoneInfo("America/Sao_Paulo")

SQLI = re.compile(r"('|%27)\s*(or|and)\s+[\w'\"]+\s*=|union(\s|%20|\+)+(all(\s|%20|\+)+)?select|pg_sleep|;\s*(update|drop|insert|delete)\b"
                  r"|('|%27)\s*--|/\*.*\*/|information_schema|\bselect\b.+\bfrom\b", re.I)
MQTT_TLS_FALHA = re.compile(r"peer did not return a certificate|certificate verify failed|certificate revoked|"
                            r"bad certificate|unknown ca", re.I)
MQTT_NOVA_CONEXAO = re.compile(r"New connection from ([\d.]+):\d+")

MITRE = {
    "VPN_ANOMALA": "T1133 External Remote Services / T1078 Valid Accounts",
    "SQLI": "T1190 Exploit Public-Facing Application",
    "DISPOSITIVO_SEM_CERT": "T0848 Rogue Master / T0830 (ICS) - dispositivo nao autorizado",
    "ATUADOR_FORA_PERFIL": "T0836 Modify Parameter / T0855 Unauthorized Command Message (ICS)",
}


def agora():
    return datetime.now(timezone.utc)


def iso(d):
    return d.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_ts(s):
    if not s:
        return None
    s = str(s).strip().replace(" UTC", "+00:00").replace("Z", "+00:00")
    if " " in s and "T" not in s:
        s = s.replace(" ", "T", 1)
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)   # todos os containers estao em UTC
    return d.astimezone(timezone.utc)


class Detector:
    def __init__(self, pasta, saida, tudo):
        self.pasta = pasta
        self.saida = saida
        self.tudo = tudo
        self.offsets = {}
        self.ultimo_ip_mqtt = {}
        self.recentes = {}   # dedup: (regra, alvo) -> datetime
        self.total = 0

    def arquivos(self):
        fs = glob.glob(os.path.join(self.pasta, "*.log")) + glob.glob(os.path.join(self.pasta, "postgres", "*.json"))
        fs += glob.glob(os.path.join(self.pasta, "waf", "*.log"))
        nomes_fora = ("alertas.log", "respostas.log", "recursos.log", "caos.log")
        return [f for f in fs if os.path.basename(f) not in nomes_fora]

    def alertar(self, regra, ts_evento, fonte, alvo, detalhe, severidade="alta"):
        chave = (regra, json.dumps(alvo, sort_keys=True))
        ts_ev = ts_evento or agora()
        anterior = self.recentes.get(chave)
        if anterior and abs((ts_ev - anterior).total_seconds()) < 60:
            return
        self.recentes[chave] = ts_ev
        det = agora()
        a = {"ts": iso(det), "servico": "detector", "evento": "alerta", "regra": regra, "severidade": severidade,
             "ts_evento": iso(ts_ev), "mttd_seg": round((det - ts_ev).total_seconds(), 3) if not self.tudo else None,
             "fonte": os.path.basename(fonte), "alvo": alvo, "detalhe": detalhe, "mitre": MITRE.get(regra)}
        self.total += 1
        with open(self.saida, "a") as f:
            f.write(json.dumps(a, ensure_ascii=False) + "\n")
        print(f"[{regra}] {detalhe} alvo={alvo}")

    # ---------- regras ----------
    def linha_json(self, fonte, d):
        ts = parse_ts(d.get("ts") or d.get("timestamp"))
        ev = d.get("evento")

        # (a) login VPN anomalo
        if ev == "vpn_handshake":
            hora_local = ts.astimezone(TZ).hour if ts else 12
            motivos = []
            if d.get("ip_novo"):
                motivos.append("ip_nunca_visto_pra_esse_peer")
            if d.get("peer") == "desconhecido":
                motivos.append("chave_desconhecida")
            if d.get("peer", "").startswith("operador") and (hora_local < 6 or hora_local >= 23):
                motivos.append(f"operador_de_madrugada_{hora_local}h")
            if motivos:
                self.alertar("VPN_ANOMALA", ts, fonte, {"peer": d.get("peer"), "ip": d.get("endpoint_ip")},
                             ", ".join(motivos))

        # (b) padrao de SQL injection em qualquer campo de entrada que a gente loga
        for campo in ("busca", "uri", "busca_invalida"):
            v = d.get(campo)
            if isinstance(v, str) and SQLI.search(v):
                self.alertar("SQLI", ts, fonte, {"ip": d.get("ip") or d.get("cliente_ip"), "servico": d.get("servico")},
                             f"padrao de SQLi no campo {campo}: {v[:120]}")
        if ev == "erro_sql":
            self.alertar("SQLI", ts, fonte, {"ip": d.get("ip"), "servico": d.get("servico")},
                         "erro de sintaxe SQL vindo de entrada do usuario", "media")
        if ev == "busca_invalida" and SQLI.search(d.get("busca", "")):
            pass  # ja pegou acima
        # audit log do ModSecurity
        tr = d.get("transaction")
        if isinstance(tr, dict):
            ids = [m.get("details", {}).get("ruleId", "") for m in tr.get("messages", [])]
            if any(str(i).startswith("942") for i in ids):
                self.alertar("SQLI", parse_ts(tr.get("time_stamp")) or ts, fonte,
                             {"ip": tr.get("client_ip"), "servico": "waf"},
                             f"WAF bloqueou SQLi em {tr.get('request', {}).get('uri', '')[:100]}")

        # (c) dispositivo sem certificado valido no gateway (nginx)
        # (o nginx devolve 400 quando o cliente nao manda cert ou manda um revogado/invalido)
        if d.get("servico") == "nuvem-gw" and ev == "http" and d.get("status") == 400 \
                and d.get("verificacao_cert") != "SUCCESS":
            self.alertar("DISPOSITIVO_SEM_CERT", ts, fonte, {"ip": d.get("cliente_ip")},
                         f"cliente sem certificado valido no ingest ({d.get('verificacao_cert')})")

        # (d) comando de atuador fora do horario/perfil, ou agenda adulterada
        if ev in ("comando_rejeitado", "agendamento_rejeitado"):
            self.alertar("ATUADOR_FORA_PERFIL", ts, fonte,
                         {"espaco": d.get("espaco"), "dispositivo": d.get("dispositivo", "escola-bomba-01")},
                         f"{ev}: {d.get('motivo') or d.get('problemas')}")
        if ev in ("bomba_ligada", "bomba_desligada") and str(d.get("motivo", "")).startswith("comando_"):
            h = ts.astimezone(TZ).hour if ts else 12
            if h < 6 or h >= 22:
                self.alertar("ATUADOR_FORA_PERFIL", ts, fonte, {"espaco": d.get("espaco"), "dispositivo": "escola-bomba-01"},
                             f"bomba acionada por comando as {h}h")
        # log do postgres (jsonlog): alteracao direta na agenda por usuario que nao e o app
        msg = d.get("message", "")
        if "agendamento_bomba" in msg and re.search(r"\bupdate\b", msg, re.I) and d.get("user") != "painel_app":
            self.alertar("ATUADOR_FORA_PERFIL", ts, fonte, {"db_user": d.get("user"), "ip": d.get("remote_host")},
                         "agenda da bomba alterada direto no banco por usuario fora do perfil")

    def linha_mosquitto(self, fonte, linha):
        m = MQTT_NOVA_CONEXAO.search(linha)
        if m:
            self.ultimo_ip_mqtt[fonte] = m.group(1)
            return
        if MQTT_TLS_FALHA.search(linha):
            ts = parse_ts(linha[:19])
            self.alertar("DISPOSITIVO_SEM_CERT", ts, fonte,
                         {"ip": self.ultimo_ip_mqtt.get(fonte), "broker": os.path.basename(fonte)},
                         linha[21:].strip()[:150])

    def rodada(self):
        for f in self.arquivos():
            if f not in self.offsets:
                self.offsets[f] = 0 if self.tudo else os.path.getsize(f)
            try:
                tam = os.path.getsize(f)
            except OSError:
                continue
            if tam < self.offsets[f]:
                self.offsets[f] = 0   # arquivo rotacionado/sobrescrito
            try:
                fh = open(f, "r", errors="replace")
            except (PermissionError, OSError):
                # alguns logs (ex.: mosquitto) sao escritos pelo container com dono restrito; ignora
                continue
            with fh:
                fh.seek(self.offsets[f])
                for linha in fh:
                    linha = linha.strip()
                    if not linha:
                        continue
                    if linha.startswith("{"):
                        try:
                            self.linha_json(f, json.loads(linha))
                        except ValueError:
                            pass
                    elif "mosquitto" in f:
                        self.linha_mosquitto(f, linha)
                self.offsets[f] = fh.tell()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pasta", default=os.path.join(os.path.dirname(__file__), "..", "logs"))
    ap.add_argument("--saida", default=None)
    ap.add_argument("--tudo", action="store_true", help="processa os logs desde o comeco e sai")
    a = ap.parse_args()
    saida = a.saida or os.path.join(a.pasta, "alertas.log")
    d = Detector(a.pasta, saida, a.tudo)
    print(f"detector rodando em {os.path.abspath(a.pasta)} -> {saida}")
    if a.tudo:
        d.rodada()
        print(f"{d.total} alerta(s)")
        return
    while True:
        d.rodada()
        time.sleep(1)


if __name__ == "__main__":
    main()
