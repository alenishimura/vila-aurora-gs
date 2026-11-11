#!/usr/bin/env bash
# gera as chaves wireguard e monta os .conf de cada ponta
# as chaves ficam em vpn/gerado/ (fora do git)
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p gerado
cd gerado

# usa o wg do host se tiver, senao usa a imagem da borda que ja tem o wireguard-tools
wgcmd() {
  if command -v wg >/dev/null 2>&1; then
    wg "$@"
  else
    docker run --rm -i --entrypoint wg vila/borda:lab "$@"
  fi
}

gerar() {
  local nome=$1
  if [ ! -f "$nome.key" ]; then
    wgcmd genkey > "$nome.key"
    chmod 600 "$nome.key"
  fi
  wgcmd pubkey < "$nome.key" > "$nome.pub"
}

for n in gw borda-escola borda-ubs operador-01; do gerar "$n"; done

GW_PUB=$(cat gw.pub)

cat > gw-wg0.conf <<EOF
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = $(cat gw.key)

[Peer]
# borda-escola
PublicKey = $(cat borda-escola.pub)
AllowedIPs = 10.10.0.2/32

[Peer]
# borda-ubs
PublicKey = $(cat borda-ubs.pub)
AllowedIPs = 10.10.0.3/32

[Peer]
# operador-01 (acesso administrativo remoto, ainda precisa de MFA no painel)
PublicKey = $(cat operador-01.pub)
AllowedIPs = 10.10.0.10/32
EOF

borda_conf() {
  local nome=$1 ip=$2
  cat > "$nome-wg0.conf" <<EOF
[Interface]
Address = $ip/24
PrivateKey = $(cat "$nome.key")

[Peer]
PublicKey = $GW_PUB
Endpoint = gw-fibra:51820
AllowedIPs = 10.10.0.1/32
PersistentKeepalive = 15
EOF
}
borda_conf borda-escola 10.10.0.2
borda_conf borda-ubs 10.10.0.3

# esse vai pro cliente WireGuard do PC do operador (Windows/Linux)
cat > operador-01.conf <<EOF
[Interface]
Address = 10.10.0.10/32
PrivateKey = $(cat operador-01.key)

[Peer]
PublicKey = $GW_PUB
Endpoint = 127.0.0.1:51820
AllowedIPs = 10.10.0.1/32
PersistentKeepalive = 25
EOF

# mapa chave publica -> nome, usado pelo monitor de vpn
cat > peers.json <<EOF
{"$(cat borda-escola.pub)": "borda-escola", "$(cat borda-ubs.pub)": "borda-ubs", "$(cat operador-01.pub)": "operador-01"}
EOF

chmod 644 *.conf peers.json
echo "WG_GW_PUB=$GW_PUB"
echo "configs geradas em vpn/gerado/"
