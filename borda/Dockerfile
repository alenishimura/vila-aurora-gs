FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      mosquitto wireguard-tools iproute2 iptables gettext-base procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mosquitto.conf.tpl /etc/mosquitto/mosquitto.conf.tpl
COPY acl /etc/mosquitto/acl
RUN chown mosquitto:mosquitto /etc/mosquitto/acl && chmod 640 /etc/mosquitto/acl
COPY agente.py entrypoint.sh ./
RUN chmod +x entrypoint.sh
# precisa de root por causa do wg-quick (NET_ADMIN). o mosquitto troca pro usuario dele sozinho
ENTRYPOINT ["/app/entrypoint.sh"]
