# simulador de dispositivo de campo
# cada container roda um dispositivo, com o proprio certificado (mTLS no broker da borda)
import json
import os
import random
import ssl
import time
import uuid
from datetime import datetime, timezone

import paho.mqtt.client as mqtt

NOME = os.environ["DISPOSITIVO"]          # ex: ubs-camarafria-01 (tem que ser igual ao CN do cert)
TIPO = os.environ["TIPO"]                 # camara_fria, nivel, bomba, fechadura, energia
BROKER = os.environ.get("BROKER", "localhost")
PORTA = int(os.environ.get("PORTA", "8883"))
INTERVALO = float(os.environ.get("INTERVALO", "5"))
PKI = os.environ.get("PKI_DIR", "/pki")

TOPICO_TEL = f"vilaaurora/{NOME}/telemetria"
TOPICO_CMD = f"vilaaurora/{NOME}/comando"

# estado simulado
estado = {
    "temp": 4.5,
    "nivel": 70.0,
    "bomba": False,
    "bomba_externa": False,   # o sensor de nivel fica sabendo da bomba pela borda
    "bateria": 85.0,
    "modo_seguro": False,
}
seq = 0


def agora():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log(evento, **extra):
    print(json.dumps({"ts": agora(), "servico": NOME, "evento": evento, **extra}), flush=True)


def ler():
    """gera a leitura do tipo de sensor. nada muito sofisticado, so pra ter dado plausivel"""
    if TIPO == "camara_fria":
        # arquivo de "porta aberta" serve pra simular falha (docker exec ... touch /tmp/porta_aberta)
        if os.path.exists("/tmp/porta_aberta"):
            estado["temp"] = min(estado["temp"] + random.uniform(0.2, 0.5), 18)
        else:
            alvo = 4.5
            estado["temp"] += (alvo - estado["temp"]) * 0.2 + random.gauss(0, 0.15)
        return {"temperatura_c": round(estado["temp"], 2), "umidade": round(random.uniform(55, 65), 1)}

    if TIPO == "nivel":
        # caixa d'agua da escola: consumo constante, enche quando a bomba de recalque liga
        consumo = random.uniform(0.3, 0.8)
        if os.path.exists("/tmp/consumo_alto"):
            consumo *= 4
        enche = 2.5 if estado["bomba_externa"] else 0
        estado["nivel"] = max(0.0, min(100.0, estado["nivel"] - consumo + enche))
        turbidez = round(random.uniform(0.2, 0.9), 2)
        cloro = round(random.uniform(0.6, 1.4), 2)
        return {"nivel_pct": round(estado["nivel"], 1), "turbidez_ntu": turbidez, "cloro_mg_l": cloro}

    if TIPO == "bomba":
        corrente = round(random.uniform(4.5, 5.5), 2) if estado["bomba"] else 0.0
        return {"ligada": estado["bomba"], "corrente_a": corrente, "modo_seguro": estado["modo_seguro"]}

    if TIPO == "energia":
        estado["bateria"] = max(5, min(100, estado["bateria"] + random.uniform(-0.6, 0.5)))
        return {"bateria_pct": round(estado["bateria"], 1), "geracao_w": round(random.uniform(200, 900)),
                "consumo_w": round(random.uniform(300, 700))}

    if TIPO == "fechadura":
        # de vez em quando alguem passa o cracha. id do cracha e sintetico
        if random.random() < 0.15:
            cracha = f"CR-{random.randint(1, 40):04d}"
            return {"evento": "acesso", "cracha": cracha, "liberado": random.random() > 0.1, "porta": "principal"}
        return {"evento": "heartbeat", "porta_fechada": True}

    return {}


def on_connect(cli, userdata, flags, rc, props=None):
    if rc == 0:
        log("conectado_broker", broker=BROKER)
        cli.subscribe(TOPICO_CMD, qos=1)
    else:
        log("falha_conexao_broker", rc=str(rc))


def on_message(cli, userdata, msg):
    try:
        cmd = json.loads(msg.payload)
    except ValueError:
        log("comando_invalido")
        return
    acao = cmd.get("acao")
    log("comando_recebido", acao=acao, origem=cmd.get("origem"))
    if TIPO == "bomba":
        origem = str(cmd.get("origem", ""))
        # em modo seguro so obedece as regras locais de seguranca da borda (piso/teto/tempo maximo)
        if estado["modo_seguro"] and acao in ("ligar", "desligar") and not origem.startswith("regra_local"):
            log("comando_ignorado_modo_seguro", acao=acao, origem=origem)
            return
        if acao == "ligar":
            estado["bomba"] = True
        elif acao == "desligar":
            estado["bomba"] = False
        elif acao == "modo_seguro":
            # modo seguro: obedece so a regra local da borda, ignora agenda da nuvem
            estado["modo_seguro"] = True
        elif acao == "sair_modo_seguro":
            estado["modo_seguro"] = False
    if TIPO == "nivel" and "bomba_ligada" in cmd:
        estado["bomba_externa"] = bool(cmd["bomba_ligada"])


def main():
    global seq
    cli = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=NOME)
    if os.environ.get("SEM_CERT") == "1":
        # usado so no teste do "dispositivo intruso": conecta sem certificado de cliente
        cli.tls_set(ca_certs=f"{PKI}/ca.crt", tls_version=ssl.PROTOCOL_TLS_CLIENT)
    else:
        cli.tls_set(
            ca_certs=f"{PKI}/ca.crt",
            certfile=f"{PKI}/cert.pem",
            keyfile=f"{PKI}/key.pem",
            tls_version=ssl.PROTOCOL_TLS_CLIENT,
        )
    cli.on_connect = on_connect
    cli.on_message = on_message
    cli.reconnect_delay_set(1, 30)

    while True:
        try:
            cli.connect(BROKER, PORTA, keepalive=30)
            break
        except Exception as e:
            log("broker_indisponivel", erro=str(e))
            time.sleep(3)

    cli.loop_start()
    while True:
        seq += 1
        leitura = ler()
        payload = {
            "msg_id": str(uuid.uuid4()),
            "seq": seq,
            "dispositivo": NOME,
            "tipo": TIPO,
            "ts": agora(),
            "dados": leitura,
        }
        cli.publish(TOPICO_TEL, json.dumps(payload), qos=1)
        time.sleep(INTERVALO)


if __name__ == "__main__":
    main()
