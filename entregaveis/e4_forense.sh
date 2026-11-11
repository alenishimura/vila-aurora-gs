#!/usr/bin/env bash
# E4 - Laudo forense: reproduz o incidente, coleta evidencias com hash e cadeia de custodia,
# e gera a linha do tempo com mapeamento MITRE ATT&CK.
# salva em entregaveis/evidencias/E4_forense/
set -uo pipefail
cd "$(dirname "$0")/.."
OUT=entregaveis/evidencias/E4_forense
mkdir -p "$OUT"
CASO=INC-VA-0712-LAB
NOME="${1:-Alexandre Nishimura}"

echo "== 1. reproduzindo o incidente INC-VA-0712 (phishing -> SQLi -> dump -> sabotagem da bomba) =="
./incidente/reproduzir.sh > "$OUT/01_reproducao_incidente.txt" 2>&1
tail -25 "$OUT/01_reproducao_incidente.txt"

echo
echo "== 2. coletando evidencias com hash SHA-256 e cadeia de custodia =="
./forense/coletar.sh "$CASO" "$NOME" > "$OUT/02_coleta.txt" 2>&1
tail -8 "$OUT/02_coleta.txt"
cp evidencias/$CASO/cadeia_custodia.csv "$OUT/" 2>/dev/null

echo
echo "== 3. montando a linha do tempo consolidada (UTC + MITRE ATT&CK) =="
# pega a pasta mais recente da coleta (so diretorio, nunca o .tar.gz)
TS=$(ls -td evidencias/$CASO/*/ 2>/dev/null | head -1 | xargs -n1 basename)
LOGS="evidencias/$CASO/$TS/logs"
# linha do tempo completa (prova de log centralizado) e a versao so-ataque (o laudo)
python3 forense/linha_do_tempo.py "$LOGS" --saida "$OUT" > "$OUT/03_linha_do_tempo.txt" 2>&1
python3 forense/linha_do_tempo.py "$LOGS" --seguranca --saida "$OUT/ataque" > /dev/null 2>&1
cp "$OUT/ataque/linha_do_tempo.md" "$OUT/linha_do_tempo_ataque.md" 2>/dev/null
echo "linha do tempo do ataque (so eventos com tecnica MITRE):"
cat "$OUT/linha_do_tempo_ataque.md" 2>/dev/null

echo
echo "================================================================"
echo "evidencias de E4 em $OUT :"; ls -1 "$OUT"
echo "a cadeia de custodia completa e o pacote lacrado estao em evidencias/$CASO/"
echo "================================================================"
