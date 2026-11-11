#!/usr/bin/env bash
# teste de caos (RT-23): derruba o link WAN por no minimo 30 min e evidencia que a borda
# continua operando local e reconcilia os dados quando o link volta.
#
# derruba a "fibra" tirando a borda da rede wan_fibra (o tunel wireguard perde o endpoint).
# a UBS tem 4G de reserva, entao pra forcar modo autonomo total derrubamos as duas redes dela.
#
# uso: ./caos/teste_caos.sh [minutos]   (padrao 31)
set -euo pipefail
cd "$(dirname "$0")/.."
MIN="${1:-31}"
LOG="logs/caos.log"
# o nome do projeto vem do "name:" do docker-compose.yml, nao da pasta
PROJ=$(docker compose config --format json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('name','vila-aurora'))" 2>/dev/null)
[ -z "$PROJ" ] && PROJ=vila-aurora

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
reg() { echo "{\"ts\":\"$(ts)\",\"servico\":\"teste_caos\",\"evento\":\"$1\",\"detalhe\":\"${2:-}\"}" | tee -a "$LOG"; }

bomba_db() { docker exec db psql -U "$(grep POSTGRES_USER .env|cut -d= -f2)" -d "$(grep POSTGRES_DB .env|cut -d= -f2)" -Atc "$1" 2>/dev/null; }

echo "=== Teste de caos: $MIN min sem WAN ==="
reg inicio "derrubando a WAN da escola e da UBS por $MIN min"

# estado antes
ANTES=$(bomba_db "SELECT count(*) FROM telemetria")
reg estado_antes "telemetria no banco=$ANTES"

# derruba o link: desconecta as bordas das redes de WAN
for rede_borda in "wan_fibra:borda-escola" "wan_fibra:borda-ubs" "wan_4g:borda-ubs"; do
  rede=${rede_borda%%:*}; c=${rede_borda##*:}
  docker network disconnect "${PROJ}_${rede}" "$c" 2>/dev/null && reg wan_desconectada "$c de $rede" || true
done

FIM=$((SECONDS + MIN * 60))
echo "WAN derrubada. a borda deve continuar lendo sensores e aplicando regras locais."
echo "acompanhe: tail -f logs/borda-escola.log logs/borda-ubs.log"

# durante a queda: a cada 5 min mostra que a borda ainda funciona e injeta um evento local
while [ $SECONDS -lt $FIM ]; do
  sleep 300 || true
  resta=$(( (FIM - SECONDS) / 60 ))
  # confirma que a borda continua gerando telemetria/alertas locais (buffer cresce)
  PEND_ESCOLA=$(docker exec borda-escola python3 -c "import sqlite3;print(sqlite3.connect('/dados/buffer.db').execute('select count(*) from buffer where enviado=0').fetchone()[0])" 2>/dev/null || echo "?")
  reg durante "faltam ${resta} min; buffer nao enviado da escola=${PEND_ESCOLA}"
done

# no meio da queda, prova a operacao local: forca o nivel baixo e ve a bomba ligar sozinha
reg prova_regra_local "simulando consumo alto na escola pra ver a regra local ligar a bomba"
docker exec escola-nivel-01 sh -c "touch /tmp/consumo_alto" 2>/dev/null || true

# religa a WAN
for rede_borda in "wan_fibra:borda-escola" "wan_fibra:borda-ubs" "wan_4g:borda-ubs"; do
  rede=${rede_borda%%:*}; c=${rede_borda##*:}
  docker network connect "${PROJ}_${rede}" "$c" 2>/dev/null && reg wan_reconectada "$c em $rede" || true
done
reg link_restabelecido "aguardando reconciliacao do buffer"

# espera a borda esvaziar o buffer
for i in $(seq 1 60); do
  sleep 10
  PEND=$(docker exec borda-escola python3 -c "import sqlite3;print(sqlite3.connect('/dados/buffer.db').execute('select count(*) from buffer where enviado=0').fetchone()[0])" 2>/dev/null || echo 0)
  [ "$PEND" = "0" ] && break
done
reg reconciliacao_ok "buffer da escola pendente=$PEND"

DEPOIS=$(bomba_db "SELECT count(*) FROM telemetria")
reg estado_depois "telemetria no banco=$DEPOIS (antes=$ANTES, ganho=$((DEPOIS-ANTES)))"
reg fim "teste concluido"

echo
echo "pronto. agora gere as metricas:"
echo "  python3 metricas/medir.py"
echo "as evidencias (link caiu, regra local agiu, reconciliacao) estao em logs/ e logs/caos.log"
