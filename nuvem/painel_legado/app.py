# PAINEL LEGADO - VERSAO VULNERAVEL
# reproduz o painel antigo do incidente INC-VA-0712. NAO usar fora do laboratorio.
# problemas que existem de proposito aqui:
#  1. busca do historico monta o SQL concatenando texto (SQL Injection)
#  2. conecta no banco como superusuario
#  3. mostra o erro do banco na tela
#  4. login so com senha, sem MFA, senha guardada em texto puro
import json
import os
import traceback
from datetime import datetime, timezone

import psycopg2
from flask import Flask, redirect, render_template_string, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("LEGADO_SECRET", "legado")


def log(evento, **d):
    linha = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
             "servico": "painel-legado", "evento": evento, "ip": request.remote_addr,
             "ua": request.headers.get("User-Agent", ""), **d}
    with open("/logs/painel-legado.log", "a") as f:
        f.write(json.dumps(linha, ensure_ascii=False) + "\n")


def db():
    # superusuario do postgres, igual era no sistema antigo
    c = psycopg2.connect(host=os.environ.get("DB_HOST", "db"), dbname=os.environ["POSTGRES_DB"],
                         user=os.environ["POSTGRES_USER"], password=os.environ["POSTGRES_PASSWORD"])
    c.autocommit = True
    return c


BASE = """<!doctype html><html><head><title>Painel de Supervisao v1.3</title>
<style>body{font-family:Verdana;font-size:11px;background:#ddd} .box{background:#fff;padding:10px;margin:10px;border:1px solid #999}
.erro{color:#a00;white-space:pre-wrap;font-family:monospace} table{border-collapse:collapse} td,th{border:1px solid #aaa;padding:2px 6px}</style>
</head><body><div class="box"><b>Rede Vila Aurora - Supervisao</b> {% if session.get('u') %} | logado: {{session['u']}} |
<a href="/historico">historico de acessos</a> | <a href="/agendamento">bomba escola</a> | <a href="/sair">sair</a>{% endif %}</div>
<div class="box">{{ corpo|safe }}</div></body></html>"""


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, s = request.form.get("login", ""), request.form.get("senha", "")
        with db() as c, c.cursor() as cur:
            cur.execute("SELECT nome, perfil FROM legado.usuarios WHERE login=%s AND senha=%s", (u, s))
            r = cur.fetchone()
        if r:
            session["u"] = u
            log("login_ok", usuario=u)
            return redirect("/historico")
        log("login_falha", usuario=u)
    corpo = """<form method=post>login <input name=login> senha <input type=password name=senha>
    <button>entrar</button></form>"""
    return render_template_string(BASE, corpo=corpo)


@app.get("/historico")
def historico():
    if "u" not in session:
        return redirect("/")
    busca = request.args.get("busca", "")
    log("busca_historico", usuario=session["u"], busca=busca)
    html = f"""<form>buscar por nome: <input name=busca value="{busca}"> <button>buscar</button></form><br>"""
    # VULNERAVEL: concatena a entrada do usuario direto no SQL
    sql = ("SELECT data_hora, nome_usuario, porta, espaco FROM legado.historico_acessos "
           "WHERE nome_usuario ILIKE '%" + busca + "%' ORDER BY data_hora DESC LIMIT 50")
    try:
        with db() as c, c.cursor() as cur:
            cur.execute(sql)
            linhas = cur.fetchall() if cur.description else []
        html += "<table><tr><th>data</th><th>nome</th><th>porta</th><th>espaco</th></tr>"
        for l in linhas:
            html += "<tr>" + "".join(f"<td>{x}</td>" for x in l) + "</tr>"
        html += "</table>"
    except Exception as e:
        # VULNERAVEL: vaza o erro e a query
        log("erro_sql", usuario=session["u"], erro=str(e).strip())
        html += f"<div class=erro>ERRO: {e}\nQUERY: {sql}\n{traceback.format_exc()}</div>"
    return render_template_string(BASE, corpo=html)


@app.get("/agendamento")
def agendamento():
    if "u" not in session:
        return redirect("/")
    with db() as c, c.cursor() as cur:
        cur.execute("SELECT espaco, ativo, nivel_liga, nivel_desliga, alterado_por, alterado_em FROM agendamento_bomba")
        r = cur.fetchall()
    html = "<table><tr><th>espaco</th><th>ativo</th><th>liga em</th><th>desliga em</th><th>alterado por</th><th>quando</th></tr>"
    for l in r:
        html += "<tr>" + "".join(f"<td>{x}</td>" for x in l) + "</tr>"
    return render_template_string(BASE, corpo=html + "</table>")


@app.get("/sair")
def sair():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
