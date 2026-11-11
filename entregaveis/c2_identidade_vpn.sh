#!/usr/bin/env bash
# captura das evidencias de identidade, VPN e segmentacao (C2)
# rode de dentro da pasta do projeto, com o lab no ar (docker compose up -d)
cd "$(dirname "$0")/.." || exit 1
OUT=entregaveis/evidencias/C2_identidade_vpn
mkdir -p "$OUT"

echo "== 1. um certificado por dispositivo =="
for d in pki/emitidos/*/; do
  nome=$(basename "$d")
  sub=$(openssl x509 -in "$d/cert.pem" -noout -subject 2>/dev/null | sed 's/subject=//')
  echo "$nome  $sub"
done | tee "$OUT/01_um_cert_por_dispositivo.txt"

echo; echo "== 2. certificado valido (tem que dizer OK) =="
openssl verify -CAfile pki/ca/ca.crt pki/emitidos/ubs-camarafria-01/cert.pem | tee "$OUT/02_cert_valido.txt"

echo; echo "== 3. certificado revogado (tem que dizer certificate revoked) =="
# se aparecer OK em vez de revogado, rode antes: ./pki/revogar.sh ubs-energia-01
openssl verify -crl_check -CAfile pki/ca/ca.crt -CRLfile pki/ca/crl.pem pki/emitidos/ubs-energia-01/cert.pem 2>&1 | tee "$OUT/03_revogacao.txt"

echo; echo "== 4. VPN WireGuard ativa =="
docker exec nuvem-gw wg show 2>/dev/null | tee "$OUT/04_wireguard.txt" || echo "(suba o nuvem-gw com docker compose up -d)"

echo; echo "== 5. redes segmentadas =="
docker network ls --format '{{.Name}}' | grep -i vila | tee "$OUT/05_segmentacao.txt"

echo; echo "== 6. firewall do gateway (menor privilegio) =="
docker exec nuvem-gw iptables -S 2>/dev/null | grep -E 'ACCEPT|DROP|LOG' | tee -a "$OUT/05_segmentacao.txt"

echo; echo "== 7. portas publicadas (so a UDP do WireGuard deve aparecer) =="
docker compose ps --format '{{.Name}}\t{{.Ports}}' 2>/dev/null | grep -v '^\s*$'

echo; echo "evidencias salvas em $OUT"
