#!/usr/bin/env bash
# C7 - Metricas: gera disponibilidade, MTTD, MTTR, operacao autonoma, perda e consumo a partir dos logs
# salva em entregaveis/evidencias/C7_metricas/
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=entregaveis/evidencias/C7_metricas
mkdir -p "$OUT"

echo "== metricas do RT-22 (a partir dos logs do laboratorio) =="
python3 metricas/medir.py | tee "$OUT/metricas.txt"
cp metricas/metricas.json "$OUT/" 2>/dev/null

echo
echo "obs: os numeros ficam mais completos depois de rodar o teste de caos"
echo "(./caos/teste_caos.sh 31), que derruba a WAN por 31 min e forca a operacao autonoma."
echo
echo "================================================================"
echo "evidencias de C7 em $OUT :"; ls -1 "$OUT"
echo "================================================================"
