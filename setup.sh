#!/usr/bin/env bash
# prepara o laboratorio do zero: segredos, certificados, dados sinteticos, imagens e chaves da VPN
# rodar no Linux ou no WSL2 (Ubuntu) com Docker
set -euo pipefail
cd "$(dirname "$0")"

for cmd in docker openssl python3; do
  command -v $cmd >/dev/null || { echo "falta instalar: $cmd"; exit 1; }
done

# 1. .env com senhas aleatorias
if [ ! -f .env ]; then
  cp .env.example .env
  for v in POSTGRES_PASSWORD PAINEL_DB_SENHA COLETOR_DB_SENHA PAINEL_SECRET LEGADO_SECRET PSEUDO_CHAVE; do
    sed -i "s|^$v=.*|$v=$(openssl rand -hex 24)|" .env
  done
  echo "[1/6] .env criado com senhas aleatorias"
else
  echo "[1/6] .env ja existe, mantive"
fi

# 2. pastas de log (os containers rodam com usuarios diferentes, entao libera escrita)
mkdir -p logs/postgres logs/waf segredos evidencias
chmod -R 777 logs
echo "[2/6] pastas de log ok"

# 3. CA propria e certificados (um por dispositivo)
./pki/emitir_todos.sh > /dev/null
echo "[3/6] certificados emitidos"

# 4. dados sinteticos + operadores do painel
python3 nuvem/db/gerar_dados.py
echo "[4/6] dados sinteticos gerados"

# 5. imagens
docker compose build
docker compose --profile incidente build
echo "[5/6] imagens prontas"

# 6. chaves wireguard
SAIDA=$(./vpn/gerar_chaves.sh)
PUB=$(echo "$SAIDA" | grep WG_GW_PUB | cut -d= -f2-)
sed -i "s|^WG_GW_PUB=.*|WG_GW_PUB=$PUB|" .env
echo "[6/6] VPN configurada"

echo
echo "tudo pronto. agora:"
echo "  docker compose up -d"
echo "  painel: https://localhost:8443  (usuarios e TOTP em segredos/operadores.txt)"
