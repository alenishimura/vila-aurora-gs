#!/usr/bin/env bash
# confere se nenhuma evidencia foi alterada depois da coleta
# uso: ./forense/verificar.sh evidencias/<caso>/<timestamp>
set -euo pipefail
DIR="${1:?informe a pasta da coleta}"
cd "$DIR"
if sha256sum --quiet -c hashes.sha256; then
  echo "OK: todos os $(wc -l < hashes.sha256) arquivos batem com o hash da coleta"
else
  echo "ATENCAO: tem arquivo diferente do que foi coletado"
  exit 1
fi
