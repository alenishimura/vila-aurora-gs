# gera os dados sinteticos do banco e os operadores do painel
# uso: python3 nuvem/db/gerar_dados.py   (o setup.sh ja chama)
# saida:
#   nuvem/db/init/03_dados_sinteticos.sql  -> pessoas ficticias, historico legado, acessos
#   nuvem/db/init/04_operadores.sql        -> operadores com hash de senha e TOTP (fora do git)
#   segredos/operadores.txt                -> senhas e segredos TOTP pra usar no lab (fora do git)
import base64
import hashlib
import hmac
import os
import random
import secrets
from datetime import datetime, timedelta
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
random.seed(712)   # fixo pra dar sempre os mesmos dados sinteticos


def ler_env():
    env = {}
    p = RAIZ / ".env"
    if p.exists():
        for linha in p.read_text().splitlines():
            if "=" in linha and not linha.startswith("#"):
                k, v = linha.split("=", 1)
                env[k.strip()] = v.strip()
    return env


ENV = ler_env()
CHAVE = ENV.get("PSEUDO_CHAVE", "troque-isso").encode()

NOMES = ["Ana", "Bruno", "Carla", "Diego", "Elaine", "Fabio", "Gisele", "Hugo", "Ingrid", "Joao",
         "Katia", "Lucas", "Marta", "Nelson", "Olivia", "Paulo", "Rita", "Sergio", "Tania", "Vitor",
         "Wesley", "Yara", "Zeca", "Beatriz", "Caio", "Denise", "Edson", "Flavia", "Gustavo", "Helena"]
SOBRENOMES = ["Ficticio", "Silvatest", "Exemplar", "Simulado", "Modelo", "Teste", "Amostra", "Sintetico"]


def cpf_falso():
    # gera no formato de CPF mas com digito verificador ERRADO de proposito,
    # assim nunca bate com CPF de pessoa real
    n = [random.randint(0, 9) for _ in range(9)]
    s = sum(a * b for a, b in zip(n, range(10, 1, -1)))
    d1 = (s * 10 % 11) % 10
    s2 = sum(a * b for a, b in zip(n + [d1], range(11, 1, -1)))
    d2 = (s2 * 10 % 11) % 10
    d2 = (d2 + 1) % 10
    c = "".join(map(str, n + [d1, d2]))
    return f"{c[:3]}.{c[3:6]}.{c[6:9]}-{c[9:]}"


def pseudonimo(cracha):
    return "P-" + hmac.new(CHAVE, cracha.encode(), hashlib.sha256).hexdigest()[:16]


def q(s):
    return "'" + str(s).replace("'", "''") + "'"


def hash_senha(senha):
    # mesmo formato do werkzeug (pbkdf2:sha256), entao o painel confere com check_password_hash
    salt = secrets.token_hex(8)
    it = 600000
    h = hashlib.pbkdf2_hmac("sha256", senha.encode(), salt.encode(), it).hex()
    return f"pbkdf2:sha256:{it}${salt}${h}"


def main():
    linhas = ["-- dados SINTETICOS gerados por gerar_dados.py. nenhuma pessoa real.", ""]

    # pessoas ficticias do sistema legado (voluntarios e moradores)
    pessoas = []
    for i in range(1, 41):
        nome = f"{random.choice(NOMES)} {random.choice(SOBRENOMES)}"
        perfil = "voluntario" if i <= 25 else "morador"
        login = nome.split()[0].lower() + str(i)
        pessoas.append((i, nome, perfil))
        linhas.append(
            "INSERT INTO legado.usuarios (login, senha, nome, cpf, telefone, email, perfil) VALUES "
            f"({q(login)}, {q('senha' + str(1000 + i))}, {q(nome)}, {q(cpf_falso())}, "
            f"{q('(11) 9' + str(random.randint(1000, 9999)) + '-' + str(random.randint(1000, 9999)))}, "
            f"{q(login + '@exemplo.invalid')}, {q(perfil)});")
    # a coordenadora de voluntarios do incidente (conta que caiu no phishing)
    linhas.append("INSERT INTO legado.usuarios (login, senha, nome, cpf, telefone, email, perfil) VALUES "
                  "('coord.voluntarios', 'Aurora@2026', 'Coordenadora Ficticia', '000.000.001-00', "
                  "'(11) 90000-0001', 'coord@exemplo.invalid', 'admin');")
    linhas.append("")

    base = datetime(2026, 10, 1, 7, 0)
    for _ in range(300):
        p = random.choice(pessoas)
        dt = base + timedelta(minutes=random.randint(0, 60 * 24 * 30))
        linhas.append("INSERT INTO legado.historico_acessos (data_hora, nome_usuario, porta, espaco) VALUES "
                      f"({q(dt.strftime('%Y-%m-%d %H:%M:%S'))}, {q(p[1])}, 'principal', "
                      f"{q(random.choice(['escola', 'ubs', 'centro', 'horta', 'abrigo']))});")
    linhas.append("")

    (RAIZ / "nuvem/db/init/03_dados_sinteticos.sql").write_text("\n".join(linhas) + "\n")

    # ---- parte com segredo (fora do git) ----
    sec = ["-- gerado no setup. NAO versionar.", ""]
    # voluntarios no sistema novo: so nome, funcao e pseudonimo do cracha
    for i in range(1, 41):
        cracha = f"CR-{i:04d}"
        nome = pessoas[i - 1][1]
        funcao = "voluntario" if i <= 25 else "morador cadastrado"
        sec.append(f"INSERT INTO voluntarios (nome, funcao, pseudonimo) VALUES ({q(nome)}, {q(funcao)}, {q(pseudonimo(cracha))});")
    sec.append("")

    ops = [("operador1", "Operador Ficticio", "operador"),
           ("tecnico1", "Tecnico Ficticio", "tecnico"),
           ("coord1", "Coordenacao Ficticia", "coordenacao"),
           ("coord2", "Coordenacao Ficticia 2", "coordenacao"),
           ("auditor1", "Auditor Ficticio", "auditor")]
    txt = ["usuarios do painel novo (lab). senha + codigo TOTP (Google Authenticator, Aegis etc)", ""]
    for user, nome, perfil in ops:
        senha = secrets.token_urlsafe(10)
        totp = base64.b32encode(secrets.token_bytes(20)).decode()
        sec.append("INSERT INTO operadores (usuario, nome, perfil, senha_hash, totp_segredo) VALUES "
                   f"({q(user)}, {q(nome)}, {q(perfil)}, {q(hash_senha(senha))}, {q(totp)});")
        txt.append(f"{user:10} perfil={perfil:12} senha={senha}  totp={totp}")
        txt.append(f"           otpauth://totp/VilaAurora:{user}?secret={totp}&issuer=VilaAurora")
    (RAIZ / "nuvem/db/init/04_operadores.sql").write_text("\n".join(sec) + "\n")
    (RAIZ / "segredos").mkdir(exist_ok=True)
    (RAIZ / "segredos/operadores.txt").write_text("\n".join(txt) + "\n")
    print("dados gerados. senhas do painel em segredos/operadores.txt")


if __name__ == "__main__":
    main()
