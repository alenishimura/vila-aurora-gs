#!/usr/bin/env bash
# C6 - IA defensiva: roda o Isolation Forest/LOF sobre a telemetria e mede precisao/revocacao/FP
# ja deixei os resultados prontos na pasta; esse script regenera na sua maquina (pro video)
# salva em entregaveis/evidencias/C6_ia/
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=entregaveis/evidencias/C6_ia
mkdir -p "$OUT"

echo "rodando a IA num container temporario (instala numpy/pandas/sklearn/matplotlib, ~1-2 min)..."
docker run --rm -v "$PWD/ia:/ia" -w /ia python:3.12-slim \
  bash -c "pip install -q numpy pandas scikit-learn matplotlib && python anomalias.py"

cp ia/resultados/* "$OUT/" 2>/dev/null
echo
echo "metricas medidas:"
cat "$OUT/metricas.json"
echo
echo "================================================================"
echo "evidencias de C6 em $OUT (metricas.json + 2 graficos):"; ls -1 "$OUT"
echo "================================================================"
