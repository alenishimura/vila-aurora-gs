# coletor da nuvem: recebe os lotes das bordas (atras do nginx com mTLS)
# o nginx passa o CN do certificado no header X-Cliente-CN
import json
import logging
import os
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from flask import Flask, abort, jsonify, request

app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.WARNING)
LOG = "/logs/coletor.log"


def agora():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def log(evento, **d):
    with open(LOG, "a") as f:
        f.write(json.dumps({"ts": agora(), "servico": "coletor", "evento": evento, **d}, ensure_ascii=False) + "\n")


def conn():
    return psycopg2.connect(host=os.environ.get("DB_HOST", "db"), dbname=os.environ["POSTGRES_DB"],
                            user="coletor_app", password=os.environ["COLETOR_DB_SENHA"])


def borda_autenticada():
    cn = request.headers.get("X-Cliente-CN", "")
    if not cn.startswith("borda-"):
        log("acesso_negado", cn=cn, ip=request.headers.get("X-Real-IP"))
        abort(403)
    return cn, cn.removeprefix("borda-")


@app.get("/saude")
def saude():
    cn, _ = borda_autenticada()
    return {"ok": True}


@app.post("/ingest")
def ingest():
    cn, espaco = borda_autenticada()
    corpo = request.get_json(silent=True) or {}
    if corpo.get("borda") != cn:
        log("borda_divergente", cn=cn, declarado=corpo.get("borda"))
        abort(403)
    itens = corpo.get("itens", [])[:500]
    recebidos, novos = [], 0
    with conn() as c, c.cursor() as cur:
        for it in itens:
            p = it.get("payload", {})
            disp = it.get("dispositivo", "")
            # borda so pode mandar dado do proprio espaco
            if disp != cn and not disp.startswith(espaco + "-"):
                log("item_rejeitado", cn=cn, dispositivo=disp)
                continue
            if it.get("tipo") == "alerta":
                cur.execute("INSERT INTO alertas (msg_id, ts, espaco, tipo, mensagem, origem, dados) "
                            "VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (msg_id) DO NOTHING",
                            (it["msg_id"], p.get("ts"), espaco, p.get("tipo_alerta"), p.get("mensagem"),
                             "regra_local", json.dumps(p)))
                recebidos.append(it["msg_id"])
                continue
            cur.execute("INSERT INTO telemetria (msg_id, ts, espaco, dispositivo, tipo, via, dados) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (msg_id) DO NOTHING",
                        (it["msg_id"], p.get("ts"), espaco, disp, it.get("tipo"), corpo.get("via"),
                         json.dumps(p.get("dados", {}))))
            novos += cur.rowcount
            d = p.get("dados", {})
            if it.get("tipo") == "fechadura" and d.get("evento") == "acesso" and cur.rowcount:
                cur.execute("INSERT INTO acessos (ts, espaco, porta, pseudonimo, liberado) VALUES (%s,%s,%s,%s,%s)",
                            (p.get("ts"), espaco, d.get("porta"), d.get("cracha"), d.get("liberado")))
            # regra de nuvem (era a UNICA que existia antes do projeto)
            if it.get("tipo") == "camara_fria" and cur.rowcount:
                t = d.get("temperatura_c")
                if t is not None and (t > 8 or t < 2):
                    cur.execute("INSERT INTO alertas (ts, espaco, tipo, mensagem, origem, dados) VALUES (%s,%s,%s,%s,%s,%s)",
                                (p.get("ts"), espaco, "camara_fria_nuvem", f"Leitura {t} C fora da faixa", "nuvem",
                                 json.dumps(d)))
            recebidos.append(it["msg_id"])
    log("lote_recebido", cn=cn, itens=len(itens), novos=novos, duplicados=len(recebidos) - novos,
        via=corpo.get("via"))
    return jsonify({"recebidos": recebidos})


@app.get("/comandos")
def comandos():
    cn, espaco = borda_autenticada()
    with conn() as c, c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("UPDATE comandos SET status='entregue' WHERE espaco=%s AND status='liberado' "
                    "RETURNING id, dispositivo, acao, solicitado_por, perfil, alto_impacto, aprovado_por", (espaco,))
        lista = cur.fetchall()
    if lista:
        log("comandos_entregues", cn=cn, ids=[x["id"] for x in lista])
    return jsonify(lista)


@app.post("/comandos/<int:cid>/resultado")
def resultado(cid):
    cn, espaco = borda_autenticada()
    r = request.get_json(silent=True) or {}
    status = "executado" if r.get("status") == "executado" else "rejeitado"
    with conn() as c, c.cursor() as cur:
        cur.execute("UPDATE comandos SET status=%s, resultado=%s, motivo=%s WHERE id=%s AND espaco=%s",
                    (status, json.dumps(r), r.get("motivo"), cid, espaco))
    log("comando_resultado", cn=cn, comando_id=cid, status=status, motivo=r.get("motivo"))
    return {"ok": True}


@app.get("/agendamento")
def agendamento():
    cn, espaco = borda_autenticada()
    with conn() as c, c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT ativo, nivel_liga, nivel_desliga FROM agendamento_bomba WHERE espaco=%s", (espaco,))
        r = cur.fetchone()
    return jsonify(r or {})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
