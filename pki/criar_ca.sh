#!/usr/bin/env bash
# cria a CA raiz do projeto. roda uma vez so.
set -euo pipefail
cd "$(dirname "$0")"

if [ -f ca/ca.key ]; then
  echo "CA ja existe em pki/ca, nao vou sobrescrever"
  exit 0
fi

mkdir -p ca/novos emitidos
touch ca/index.txt
echo 1000 > ca/serial
echo 1000 > ca/crlnumber

# chave EC P-256, mais leve pro raspberry e atual
openssl ecparam -name prime256v1 -genkey -noout -out ca/ca.key
chmod 600 ca/ca.key

openssl req -new -x509 -config openssl.cnf -key ca/ca.key -days 1825 \
  -subj "/O=Rede Comunitaria Vila Aurora/CN=Vila Aurora CA Lab" \
  -extensions ext_ca -out ca/ca.crt

# CRL inicial (vazia). o mosquitto e o nginx precisam dela existindo
openssl ca -config openssl.cnf -gencrl -out ca/crl.pem 2>/dev/null

# pasta "publico" e o que os containers montam (sem a chave da CA)
mkdir -p publico
cp ca/ca.crt publico/ca.crt
cp ca/crl.pem publico/crl.pem

echo "CA criada:"
openssl x509 -in ca/ca.crt -noout -subject -enddate
