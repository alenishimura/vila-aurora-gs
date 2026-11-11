#!/usr/bin/env bash
# baixa o wazuh-docker oficial (single node) e pluga as configs do projeto
# precisa de uns 6-8 GB de RAM livres. se nao der, usar o soc/detector.py (plano B)
set -euo pipefail
cd "$(dirname "$0")"
RAIZ=$(cd .. && pwd)
VERSAO=v4.14.9

if [ ! -d wazuh-docker ]; then
  git clone --depth 1 -b "$VERSAO" https://github.com/wazuh/wazuh-docker.git
fi
cd wazuh-docker/single-node

mkdir -p vila
cp "$RAIZ/siem/vila_aurora_rules.xml" vila/
cp "$RAIZ/siem/wazuh_manager.conf" vila/
cp "$RAIZ/siem/docker-compose.override.yml" .
echo "VILA_LOGS=$RAIZ/logs" > .env

# linux: o indexer precisa disso (no WSL2 rodar dentro do WSL)
sudo sysctl -w vm.max_map_count=262144 || true

if [ ! -d config/wazuh_indexer_ssl_certs ]; then
  docker compose -f generate-indexer-certs.yml run --rm generator
fi

docker compose up -d
echo
echo "Wazuh subindo (demora 1-2 min). Dashboard: https://localhost:5601  usuario admin / SecretPassword"
echo "alertas do projeto: Threat Hunting -> filtrar rule.groups: vila_aurora"
