#!/usr/bin/env bash
# revoga o certificado de um dispositivo comprometido e publica a CRL nova
# uso: ./revogar.sh <nome> [motivo]
# motivos validos do openssl: keyCompromise, superseded, cessationOfOperation...
set -euo pipefail
cd "$(dirname "$0")"

NOME="${1:?informe o nome}"
MOTIVO="${2:-keyCompromise}"
CERT="emitidos/$NOME/cert.pem"

if [ ! -f "$CERT" ]; then
  echo "nao achei $CERT"
  exit 1
fi

openssl ca -config openssl.cnf -revoke "$CERT" -crl_reason "$MOTIVO" 2>/dev/null || true
openssl ca -config openssl.cnf -gencrl -out ca/crl.pem 2>/dev/null
cp ca/crl.pem publico/crl.pem

SERIAL=$(openssl x509 -in "$CERT" -noout -serial | cut -d= -f2)
echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)\",\"servico\":\"pki\",\"evento\":\"certificado_revogado\",\"cn\":\"$NOME\",\"serial\":\"$SERIAL\",\"motivo\":\"$MOTIVO\"}" >> ../logs/pki.log

# mosquitto e nginx so leem a CRL quando sobem, entao reinicia quem usa
if command -v docker >/dev/null 2>&1 && [ "${SEM_RESTART:-0}" != "1" ]; then
  for c in borda-escola borda-ubs nuvem-gw; do
    docker restart "$c" >/dev/null 2>&1 && echo "reiniciado $c pra recarregar a CRL" || true
  done
fi

echo "revogado: $NOME (serial $SERIAL)"
openssl crl -in ca/crl.pem -noout -text | grep -A1 "Serial Number" | head -20
