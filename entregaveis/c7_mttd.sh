#!/usr/bin/env bash
# C7 - mede o MTTD ao vivo. roda numa pasta temporaria do usuario (mktemp),
# so copia os logs pra la pra leitura. nao escreve em logs/ (que e do root),
# entao nao precisa de sudo.
echo "### c7_mttd v3 (mktemp, sem sudo) ###"
cd "$(dirname "$0")/.." || exit 1

T=$(mktemp -d)
echo "pasta de teste: $T"

# copia os logs atuais (leitura) pra pasta de teste
cp logs/*.log "$T"/ 2>/dev/null
[ -d logs/postgres ] && cp -r logs/postgres "$T"/ 2>/dev/null
[ -d logs/waf ] && cp -r logs/waf "$T"/ 2>/dev/null

# garante que exista o arquivo onde vamos injetar
touch "$T/painel-legado.log"

# detector seguindo a pasta de teste em tempo real (modo ao vivo => calcula mttd_seg)
python3 soc/detector.py --pasta "$T" --saida "$T/alertas.log" >/dev/null 2>&1 &
DET=$!
sleep 2

# injeta 4 tentativas de SQLi com timestamp de agora (IPs diferentes pra nao cair no dedup)
for i in 1 2 3 4; do
  python3 - "$T" "$i" <<'PY'
import sys, json
from datetime import datetime, timezone
T, i = sys.argv[1], int(sys.argv[2])
TS = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
ev = {"ts": TS, "servico": "painel-legado", "evento": "busca",
      "ip": f"203.0.113.{60+i}",
      "busca": "x' UNION SELECT login,senha FROM legado.usuarios--"}
open(T + "/painel-legado.log", "a").write(json.dumps(ev) + "\n")
PY
  sleep 1.3
done
sleep 2

kill "$DET" 2>/dev/null
wait "$DET" 2>/dev/null

echo
echo "=== alertas capturados ao vivo (repare o mttd_seg preenchido) ==="
grep '"mttd_seg"' "$T/alertas.log" | tail -n 4

echo
echo "=== metricas recalculadas, agora com MTTD ==="
python3 metricas/medir.py --pasta "$T" | grep -i -A5 '"MTTD"'
