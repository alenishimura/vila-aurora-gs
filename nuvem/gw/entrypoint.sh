#!/usr/bin/env bash
# gateway da nuvem: termina a VPN e expoe so o necessario dentro do tunel
set -e

install -m 600 /vpn/gw-wg0.conf /etc/wireguard/wg0.conf
wg-quick up wg0

# firewall do tunel (menor privilegio entre segmentos)
# bordas -> so 443 (ingest). operador -> so 8443 (painel). o resto cai
iptables -A INPUT -i wg0 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i wg0 -s 10.10.0.2 -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i wg0 -s 10.10.0.3 -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i wg0 -s 10.10.0.10 -p tcp --dport 8443 -j ACCEPT
iptables -A INPUT -i wg0 -p icmp -j ACCEPT
iptables -A INPUT -i wg0 -j LOG --log-prefix "GW-DROP " || true
iptables -A INPUT -i wg0 -j DROP
# nada de um peer falar com outro peer pelo gateway
iptables -A FORWARD -i wg0 -j DROP

python3 /opt/gw/monitor_vpn.py &

exec nginx -g 'daemon off;'
