# painel de supervisao novo (versao corrigida)
# - consultas sempre parametrizadas, validacao no servidor, usuario de banco com privilegio minimo
# - login com senha + TOTP (MFA) e perfis (RBAC): operador, tecnico, coordenacao, auditor
# - acoes de alto impacto so com aprovacao de outra pessoa da coordenacao
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import psycopg2
import psycopg2.extras
import pyotp
from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.environ["PAINEL_SECRET"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

PERFIS = ("operador", "tecnico", "coordenacao", "auditor")
ACOES = {
    "escola-bomba-01": {"ligar": False, "desligar": True, "modo_seguro": False, "sair_modo_seguro": False},
    "escola-fechadura-01": {"travar": False, "liberar_todas": True},
}
# o valor True quer dizer alto impacto -> precisa aprovacao


def agora():
    return datetime.now(timezone.utc)


def log(evento, **d):
    linha = {"ts": agora().isoformat(timespec="milliseconds").replace("+00:00", "Z"), "servico": "painel",
             "evento": evento, "ip": request.remote_addr, "usuario": session.get("usuario"), **d}
    with open("/logs/painel.log", "a") as f:
        f.write(json.dumps(linha, ensure_ascii=False, default=str) + "\n")


def db():
    if "db" not in g:
        g.db = psycopg2.connect(host=os.environ.get("DB_HOST", "db"), dbname=os.environ["POSTGRES_DB"],
                                user="painel_app", password=os.environ["PAINEL_DB_SENHA"],
                                cursor_factory=psycopg2.extras.RealDictCursor)
    return g.db


@app.teardown_appcontext
def fechar(e):
    c = g.pop("db", None)
    if c:
        c.close()


def consulta(sql, params=(), um=False):
    with db().cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone() if um else cur.fetchall()


def executa(sql, params=()):
    with db().cursor() as cur:
        cur.execute(sql, params)
    db().commit()


def auditar(o_que, **detalhe):
    executa("INSERT INTO auditoria (usuario, acao, detalhe) VALUES (%s,%s,%s)",
            (session.get("usuario"), o_que, json.dumps(detalhe, default=str)))
    log(o_que, **detalhe)


# ---------- seguranca basica ----------

@app.before_request
def csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    if request.method == "POST":
        if request.form.get("csrf") != session["csrf"]:
            log("csrf_invalido", rota=request.path)
            abort(400)


@app.after_request
def cabecalhos(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


def requer(*perfis):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if not session.get("mfa_ok"):
                return redirect(url_for("login"))
            if perfis and session.get("perfil") not in perfis:
                log("acesso_negado_rbac", rota=request.path, perfil=session.get("perfil"))
                abort(403)
            return f(*a, **k)
        return w
    return deco


@app.context_processor
def contexto():
    return {"perfil": session.get("perfil"), "usuario": session.get("usuario"), "csrf": session.get("csrf")}


# ---------- login + MFA ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    erro = None
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()[:40]
        senha = request.form.get("senha", "")
        op = consulta("SELECT * FROM operadores WHERE usuario=%s AND ativo", (usuario,), um=True)
        if op and op["bloqueado_ate"] and op["bloqueado_ate"] > agora():
            log("login_bloqueado", usuario_tentado=usuario)
            erro = "Conta bloqueada por alguns minutos. Procure a coordenação se precisar."
        elif op and check_password_hash(op["senha_hash"], senha):
            session.clear()
            session["pre_usuario"] = op["usuario"]
            session["csrf"] = secrets.token_urlsafe(24)
            log("senha_ok", usuario_tentado=usuario)
            return redirect(url_for("mfa"))
        else:
            if op:
                falhas = op["tentativas_falhas"] + 1
                bloq = agora() + timedelta(minutes=15) if falhas >= 5 else None
                executa("UPDATE operadores SET tentativas_falhas=%s, bloqueado_ate=%s WHERE id=%s",
                        (0 if bloq else falhas, bloq, op["id"]))
            log("login_falha", usuario_tentado=usuario)
            erro = "Usuário ou senha incorretos."
    return render_template("login.html", erro=erro)


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    usuario = session.get("pre_usuario")
    if not usuario:
        return redirect(url_for("login"))
    erro = None
    if request.method == "POST":
        codigo = re.sub(r"\D", "", request.form.get("codigo", ""))[:6]
        op = consulta("SELECT * FROM operadores WHERE usuario=%s", (usuario,), um=True)
        if op and pyotp.TOTP(op["totp_segredo"]).verify(codigo, valid_window=1):
            executa("UPDATE operadores SET tentativas_falhas=0, bloqueado_ate=NULL WHERE id=%s", (op["id"],))
            session.clear()
            session.permanent = True
            session.update(usuario=op["usuario"], perfil=op["perfil"], nome=op["nome"], mfa_ok=True,
                           csrf=secrets.token_urlsafe(24))
            auditar("login_ok", perfil=op["perfil"])
            return redirect(url_for("inicio"))
        log("mfa_falha", usuario_tentado=usuario)
        erro = "Código inválido. Confira o aplicativo autenticador."
    return render_template("mfa.html", erro=erro)


@app.get("/sair")
def sair():
    if session.get("usuario"):
        log("logout")
    session.clear()
    return redirect(url_for("login"))


# ---------- telas ----------

@app.get("/")
@requer()
def inicio():
    ultimos = consulta("""
        SELECT DISTINCT ON (dispositivo) dispositivo, espaco, tipo, ts, recebido_em, via, dados
        FROM telemetria ORDER BY dispositivo, ts DESC""")
    alertas = consulta("SELECT * FROM alertas WHERE reconhecido_em IS NULL ORDER BY ts DESC LIMIT 20")
    pend = consulta("SELECT count(*) AS n FROM comandos WHERE status='aguardando_aprovacao'", um=True)["n"]
    pend += consulta("SELECT count(*) AS n FROM respostas_pendentes WHERE status='aguardando'", um=True)["n"]
    for u in ultimos:
        u["atraso_min"] = round((agora() - u["recebido_em"]).total_seconds() / 60, 1)
    return render_template("inicio.html", ultimos=ultimos, alertas=alertas, pendentes=pend)


@app.post("/alertas/<int:aid>/reconhecer")
@requer("operador", "tecnico", "coordenacao")
def reconhecer(aid):
    executa("UPDATE alertas SET reconhecido_por=%s, reconhecido_em=now() WHERE id=%s", (session["usuario"], aid))
    auditar("alerta_reconhecido", alerta_id=aid)
    return redirect(url_for("inicio"))


# busca do historico de acessos (era aqui o SQL Injection no sistema antigo)
BUSCA_OK = re.compile(r"^[A-Za-zÀ-ÿ0-9 \-]{0,40}$")


@app.get("/acessos")
@requer("coordenacao", "auditor")
def acessos():
    busca = request.args.get("busca", "").strip()
    if not BUSCA_OK.match(busca):
        log("busca_invalida", busca=busca[:200])
        return render_template("acessos.html", linhas=[], busca="", erro="Use só letras, números, espaço ou hífen (até 40 caracteres).")
    linhas = consulta("""
        SELECT a.ts, a.espaco, a.porta, a.pseudonimo, a.liberado, v.nome
        FROM acessos a LEFT JOIN voluntarios v ON v.pseudonimo = a.pseudonimo
        WHERE v.nome ILIKE %s OR a.pseudonimo ILIKE %s
        ORDER BY a.ts DESC LIMIT 100""", (f"%{busca}%", f"%{busca}%"))
    auditar("busca_acessos", busca=busca, resultados=len(linhas))
    return render_template("acessos.html", linhas=linhas, busca=busca, erro=None)


@app.route("/comandos", methods=["GET", "POST"])
@requer("operador", "tecnico", "coordenacao", "auditor")
def comandos():
    msg = None
    if request.method == "POST":
        if session["perfil"] not in ("tecnico", "coordenacao"):
            abort(403)
        disp, acao = request.form.get("dispositivo", ""), request.form.get("acao", "")
        if disp not in ACOES or acao not in ACOES[disp]:
            abort(400)
        alto = ACOES[disp][acao]
        status = "aguardando_aprovacao" if alto else "liberado"
        executa("INSERT INTO comandos (espaco, dispositivo, acao, solicitado_por, perfil, alto_impacto, status) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (disp.split("-")[0], disp, acao, session["usuario"], session["perfil"], alto, status))
        auditar("comando_solicitado", dispositivo=disp, acao=acao, alto_impacto=alto)
        msg = ("Comando de alto impacto registrado. Outra pessoa da coordenação precisa aprovar."
               if alto else "Comando enviado para o nó de borda.")
    lista = consulta("SELECT * FROM comandos ORDER BY criado_em DESC LIMIT 50")
    return render_template("comandos.html", lista=lista, acoes=ACOES, msg=msg)


@app.post("/comandos/<int:cid>/decidir")
@requer("coordenacao")
def decidir_comando(cid):
    c = consulta("SELECT * FROM comandos WHERE id=%s", (cid,), um=True)
    if not c or c["status"] != "aguardando_aprovacao":
        abort(404)
    if c["solicitado_por"] == session["usuario"]:
        # quatro olhos: quem pediu nao aprova
        return render_template("erro.html", msg="Quem solicitou o comando não pode aprovar o próprio pedido."), 403
    aprova = request.form.get("decisao") == "aprovar"
    executa("UPDATE comandos SET status=%s, aprovado_por=%s, aprovado_em=now(), motivo=%s WHERE id=%s",
            ("liberado" if aprova else "negado", session["usuario"] if aprova else None,
             request.form.get("motivo", "")[:200], cid))
    auditar("comando_aprovado" if aprova else "comando_negado", comando_id=cid, acao=c["acao"])
    return redirect(url_for("comandos"))


@app.route("/agendamento", methods=["GET", "POST"])
@requer("operador", "tecnico", "coordenacao", "auditor")
def agendamento():
    erro = None
    if request.method == "POST":
        if session["perfil"] not in ("tecnico", "coordenacao"):
            abort(403)
        try:
            liga = int(request.form.get("nivel_liga", ""))
            desliga = int(request.form.get("nivel_desliga", ""))
        except ValueError:
            liga = desliga = -1
        ativo = request.form.get("ativo") == "sim"
        if not (25 <= liga <= 80 and 60 <= desliga <= 97 and liga < desliga):
            erro = "Valores fora do permitido: liga entre 25 e 80, desliga entre 60 e 97, e o valor de ligar precisa ser menor que o de desligar."
        elif not ativo and session["perfil"] != "coordenacao":
            erro = "Desativar a agenda da bomba só pela coordenação."
        else:
            executa("UPDATE agendamento_bomba SET ativo=%s, nivel_liga=%s, nivel_desliga=%s, alterado_por=%s, "
                    "alterado_em=now() WHERE espaco='escola'", (ativo, liga, desliga, session["usuario"]))
            auditar("agendamento_alterado", ativo=ativo, nivel_liga=liga, nivel_desliga=desliga)
    ag = consulta("SELECT * FROM agendamento_bomba WHERE espaco='escola'", um=True)
    return render_template("agendamento.html", ag=ag, erro=erro)


@app.route("/respostas", methods=["GET", "POST"])
@requer("coordenacao", "auditor")
def respostas():
    if request.method == "POST":
        if session["perfil"] != "coordenacao":
            abort(403)
        rid = int(request.form.get("id", "0"))
        aprova = request.form.get("decisao") == "aprovar"
        executa("UPDATE respostas_pendentes SET status=%s, decidido_por=%s, decidido_em=now() "
                "WHERE id=%s AND status='aguardando'", ("aprovada" if aprova else "negada", session["usuario"], rid))
        auditar("resposta_incidente_" + ("aprovada" if aprova else "negada"), resposta_id=rid)
    lista = consulta("SELECT * FROM respostas_pendentes ORDER BY criado_em DESC LIMIT 50")
    return render_template("respostas.html", lista=lista)


@app.get("/auditoria")
@requer("coordenacao", "auditor")
def auditoria():
    lista = consulta("SELECT * FROM auditoria ORDER BY ts DESC LIMIT 200")
    return render_template("auditoria.html", lista=lista)


# ---------- erros sem vazar detalhe ----------

@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def erro_http(e):
    return render_template("erro.html", msg="Não foi possível completar essa ação."), e.code


@app.errorhandler(Exception)
def erro_geral(e):
    if isinstance(e, HTTPException):
        return render_template("erro.html", msg="Não foi possível completar essa ação."), e.code
    cod = uuid.uuid4().hex[:8]
    # o detalhe fica so no log do servidor
    log("erro_interno", codigo=cod, tipo=type(e).__name__, detalhe=str(e)[:300])
    return render_template("erro.html", msg=f"Algo deu errado. Informe o código {cod} ao suporte."), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
