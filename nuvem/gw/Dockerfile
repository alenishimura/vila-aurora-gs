FROM nginx:1.27-alpine
RUN apk add --no-cache wireguard-tools iptables python3 bash
COPY nginx.conf /etc/nginx/nginx.conf
COPY entrypoint.sh monitor_vpn.py /opt/gw/
RUN chmod +x /opt/gw/entrypoint.sh
ENTRYPOINT ["/opt/gw/entrypoint.sh"]
