#!/usr/bin/env bash
# gera a chave DKIM e o arquivo de zona do dominio ficticio vilaaurora.lab
# o CoreDNS do perfil "phishing" serve essa zona em 127.0.0.1:1053
set -euo pipefail
cd "$(dirname "$0")/dns"

if [ ! -f dkim_privada.pem ]; then
  openssl genrsa -out dkim_privada.pem 2048 2>/dev/null
  chmod 600 dkim_privada.pem
fi
PUB=$(openssl rsa -in dkim_privada.pem -pubout 2>/dev/null | grep -v -- "-----" | tr -d '\n')

# TXT com mais de 255 caracteres precisa ser quebrado em pedacos
PARTES=$(echo "v=DKIM1; k=rsa; p=$PUB" | fold -w 250 | sed 's/.*/"&"/' | tr '\n' ' ')

cat > vilaaurora.lab.zone <<EOF
\$ORIGIN vilaaurora.lab.
\$TTL 3600
@       IN SOA ns1.vilaaurora.lab. ti.vilaaurora.lab. ( 2026110901 3600 600 604800 300 )
@       IN NS  ns1.vilaaurora.lab.
ns1     IN A   127.0.0.1
@       IN MX  10 mail.vilaaurora.lab.
mail    IN A   127.0.0.1

; SPF: so o servidor de e-mail da propria rede pode mandar em nome do dominio. o resto falha (-all)
@       IN TXT "v=spf1 mx ip4:127.0.0.1 -all"

; DKIM: chave publica do seletor "lab2026" (a privada fica so no servidor de e-mail)
lab2026._domainkey IN TXT ( $PARTES)

; DMARC: politica quarantine (minimo pedido no RT-10), 100% das mensagens, relatorios pra ti@
_dmarc  IN TXT "v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@vilaaurora.lab; fo=1"
EOF

echo "zona gerada em phishing/dns/vilaaurora.lab.zone"
