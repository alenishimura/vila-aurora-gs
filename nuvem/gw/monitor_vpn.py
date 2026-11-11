# fica olhando o "wg show" e gera log de handshake em json
# o wireguard nao tem log de login, entao a gente monta um
import json
import subprocess
import time
from datetime import datetime, timezone

LOG = "/logs/vpn.log"
peers = json.load(open("/vpn/peers.json"))
ultimo = {}          # pub -> (handshake, endpoint)
conhecidos = {}      # nome -> set de ips ja vistos


def agora():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def escrever(**d):
    with open(LOG, "a") as f:
        f.write(json.dumps({"ts": agora(), "servico": "nuvem-gw", **d}) + "\n")


escrever(evento="monitor_vpn_iniciado", peers=list(peers.values()))

while True:
    try:
        saida = subprocess.run(["wg", "show", "wg0", "dump"], capture_output=True, text=True).stdout
    except Exception as e:
        escrever(evento="erro_monitor", erro=str(e))
        time.sleep(5)
        continue
    for linha in saida.strip().splitlines()[1:]:
        campos = linha.split("\t")
        if len(campos) < 8:
            continue
        pub, endpoint, hs, rx, tx = campos[0], campos[2], int(campos[4]), int(campos[5]), int(campos[6])
        if hs == 0:
            continue
        nome = peers.get(pub, "desconhecido")
        ip = endpoint.rsplit(":", 1)[0] if endpoint != "(none)" else ""
        antes = ultimo.get(pub)
        if antes is None or antes[1] != endpoint or hs - antes[0] > 180:
            # handshake novo depois de um tempo parado, ou mudou de endpoint = "nova sessao"
            vistos = conhecidos.setdefault(nome, set())
            escrever(evento="vpn_handshake", peer=nome, endpoint_ip=ip, endpoint=endpoint,
                     ip_novo=bool(vistos) and ip not in vistos, primeira_vez=not vistos,
                     handshake_utc=datetime.fromtimestamp(hs, timezone.utc).isoformat(), rx=rx, tx=tx)
            vistos.add(ip)
        ultimo[pub] = (hs, endpoint)
    time.sleep(5)
