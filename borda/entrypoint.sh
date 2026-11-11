#!/usr/bin/env bash
set -e

envsubst '${ESPACO}' < /etc/mosquitto/mosquitto.conf.tpl > /etc/mosquitto/mosquitto.conf
mkdir -p /var/lib/mosquitto && chown mosquitto: /var/lib/mosquitto || true
mosquitto -c /etc/mosquitto/mosquitto.conf -d
echo "mosquitto subiu"

# tunel wireguard ate a nuvem
if [ -f /vpn/wg0.conf ]; then
  install -m 600 /vpn/wg0.conf /etc/wireguard/wg0.conf
  if wg-quick up wg0; then
    echo "wireguard ok"
  else
    echo "falha ao subir wireguard, a borda continua funcionando local"
  fi
fi

exec python -u /app/agente.py
