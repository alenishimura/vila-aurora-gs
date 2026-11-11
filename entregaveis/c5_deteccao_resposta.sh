#!/usr/bin/env bash
# C5 - Deteccao e resposta: roda o detector das 4 regras sobre os logs e o responder em modo simulacao
# salva em entregaveis/evidencias/C5_deteccao_resposta/
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=entregaveis/evidencias/C5_deteccao_resposta
mkdir -p "$OUT"

echo "== 1. detector das 4 regras (RT-13) sobre os logs atuais =="
python3 soc/detector.py --tudo --saida "$OUT/alertas.log" 2>&1 | tee "$OUT/01_detector.txt"

echo
echo "== 2. alertas gerados (cada um com a regra e o mapeamento MITRE) =="
if [ -s "$OUT/alertas.log" ]; then
  python3 - "$OUT/alertas.log" <<'PY' | tee "$OUT/02_resumo_alertas.txt"
import json, sys
for l in open(sys.argv[1]):
    l=l.strip()
    if not l: continue
    d=json.loads(l)
    print(f"[{d.get('regra')}] sev={d.get('severidade')} mitre={d.get('mitre')}  {d.get('detalhe','')[:90]}")
PY
else
  echo "(nenhum alerta ainda. rode primeiro a demo de ataque ./entregaveis/c3_sqli.sh que gera eventos)"
fi

echo
echo "== 3. resposta automatizada (RT-15), em modo simulacao (nao executa, so mostra o que faria) =="
# PYTHONUNBUFFERED pra nao perder a saida quando o timeout encerra o processo
: > logs/alertas.log
(PYTHONUNBUFFERED=1 timeout 10 python3 -u soc/responder.py --simular > "$OUT/03_responder.txt" 2>&1 &)
sleep 2
cat "$OUT/alertas.log" >> logs/alertas.log
sleep 7
cat "$OUT/03_responder.txt"
echo
echo "repare: acoes de baixo risco (isolar, revogar, bloquear) sao automaticas;"
echo "desligar a bomba vira 'aguardando aprovacao humana' (alto impacto)."

echo
echo "================================================================"
echo "evidencias de C5 em $OUT :"; ls -1 "$OUT"
echo "================================================================"
