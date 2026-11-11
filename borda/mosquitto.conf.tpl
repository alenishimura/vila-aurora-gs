# broker MQTT local do no de borda (${ESPACO})
# so aceita cliente com certificado da CA do projeto (mTLS), sem senha compartilhada
per_listener_settings false
allow_anonymous false

listener 8883
cafile /pki/ca.crt
certfile /pki/cert.pem
keyfile /pki/key.pem
crlfile /pki-pub/crl.pem
require_certificate true
use_identity_as_username true
tls_version tlsv1.2

acl_file /etc/mosquitto/acl

persistence true
persistence_location /var/lib/mosquitto/

log_dest file /logs/mosquitto-${ESPACO}.log
log_dest stdout
log_type error
log_type warning
log_type notice
log_type information
connection_messages true
log_timestamp true
log_timestamp_format %Y-%m-%dT%H:%M:%S
