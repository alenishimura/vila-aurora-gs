#!/usr/bin/env bash
# emite todos os certificados que o lab precisa
set -euo pipefail
cd "$(dirname "$0")"

./criar_ca.sh

# dispositivos de campo (um cert por dispositivo)
for d in escola-nivel-01 escola-bomba-01 escola-fechadura-01 ubs-camarafria-01 ubs-energia-01; do
  [ -f "emitidos/$d/cert.pem" ] || ./emitir.sh "$d" dispositivo
done

# nos de borda
[ -f emitidos/borda-escola/cert.pem ] || ./emitir.sh borda-escola borda
[ -f emitidos/borda-ubs/cert.pem ]    || ./emitir.sh borda-ubs borda

# servidores da nuvem
[ -f emitidos/nuvem-gw/cert.pem ] || ./emitir.sh nuvem-gw servidor 10.10.0.1,gw-fibra,gw-4g
[ -f emitidos/painel/cert.pem ]   || ./emitir.sh painel servidor localhost,waf,127.0.0.1,10.10.0.1

echo
echo "pronto. certificados em pki/emitidos/ (essa pasta NAO vai pro git)"
