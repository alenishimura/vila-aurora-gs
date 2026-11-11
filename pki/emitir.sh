#!/usr/bin/env bash
# emite certificado pra um dispositivo/servico
# uso: ./emitir.sh <nome> <dispositivo|borda|servidor> [dns extra separado por virgula]
# ex:  ./emitir.sh ubs-camarafria-01 dispositivo
#      ./emitir.sh borda-ubs borda
#      ./emitir.sh painel servidor localhost,waf
set -euo pipefail
cd "$(dirname "$0")"

NOME="${1:?informe o nome (vira o CN)}"
TIPO="${2:?informe o tipo: dispositivo, borda ou servidor}"
EXTRA="${3:-}"

case "$TIPO" in
  dispositivo|borda|servidor) ;;
  *) echo "tipo invalido: $TIPO"; exit 1 ;;
esac

DIR="emitidos/$NOME"
mkdir -p "$DIR"

# cada um tem sua propria chave, nada de segredo compartilhado
openssl ecparam -name prime256v1 -genkey -noout -out "$DIR/key.pem"
chmod 644 "$DIR/key.pem"   # os containers rodam com outro uid, no lab deixo legivel

# SAN: o proprio nome + extras
SAN="DNS:$NOME"
if [ -n "$EXTRA" ]; then
  IFS=',' read -ra ITENS <<< "$EXTRA"
  for i in "${ITENS[@]}"; do
    if [[ "$i" =~ ^[0-9.]+$ ]]; then SAN="$SAN,IP:$i"; else SAN="$SAN,DNS:$i"; fi
  done
fi

openssl req -new -key "$DIR/key.pem" -subj "/O=Vila Aurora/OU=$TIPO/CN=$NOME" \
  -addext "subjectAltName=$SAN" -out "$DIR/req.csr"

# validade curta pra dispositivo (forca rotacao), 1 ano pros servidores
DIAS=180
[ "$TIPO" = "servidor" ] && DIAS=365

openssl ca -config openssl.cnf -batch -notext -days "$DIAS" \
  -extensions "ext_$TIPO" -in "$DIR/req.csr" -out "$DIR/cert.pem" 2>/dev/null

rm -f "$DIR/req.csr"
cp ca/ca.crt "$DIR/ca.crt"

SERIAL=$(openssl x509 -in "$DIR/cert.pem" -noout -serial | cut -d= -f2)
echo "emitido $NOME ($TIPO) serial=$SERIAL validade=${DIAS}d"
