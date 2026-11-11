#!/usr/bin/env bash
# rotacao de credencial: emite cert novo, revoga o antigo (superseded) e reinicia o container
# uso: ./rotacionar.sh <nome> <tipo>
set -euo pipefail
cd "$(dirname "$0")"

NOME="${1:?nome}"
TIPO="${2:?tipo}"
DIR="emitidos/$NOME"

if [ -f "$DIR/cert.pem" ]; then
  mkdir -p "$DIR/antigos"
  TS=$(date -u +%Y%m%dT%H%M%SZ)
  cp "$DIR/cert.pem" "$DIR/antigos/cert-$TS.pem"
  SEM_RESTART=1 ./revogar.sh "$NOME" superseded >/dev/null
  echo "cert antigo de $NOME revogado como superseded"
fi

./emitir.sh "$NOME" "$TIPO"

echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\",\"servico\":\"pki\",\"evento\":\"certificado_rotacionado\",\"cn\":\"$NOME\"}" >> ../logs/pki.log

if command -v docker >/dev/null 2>&1; then
  for c in "$NOME" borda-escola borda-ubs nuvem-gw; do
    docker restart "$c" >/dev/null 2>&1 && echo "reiniciado $c" || true
  done
fi
