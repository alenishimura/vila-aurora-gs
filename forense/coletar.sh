#!/usr/bin/env bash
# coleta de evidencias com hash SHA-256 e cadeia de custodia
# uso: ./forense/coletar.sh <id_do_caso> "<nome de quem coletou>"
# ex:  ./forense/coletar.sh INC-VA-0712-LAB "Alexandre Nishimura"
set -euo pipefail
cd "$(dirname "$0")/.."

CASO="${1:?informe o id do caso}"
QUEM="${2:?informe quem esta coletando}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
DIR="evidencias/$CASO/$TS"
CUSTODIA="evidencias/$CASO/cadeia_custodia.csv"
mkdir -p "$DIR"/{logs,banco,sistema,borda}

[ -f "$CUSTODIA" ] || echo "item;arquivo;sha256;bytes;coletado_por;data_hora_utc;origem;metodo;observacao" > "$CUSTODIA"
ITEM=$(($(wc -l < "$CUSTODIA")))

registrar() {   # arquivo origem metodo obs
  local arq=$1 origem=$2 metodo=$3 obs=${4:-}
  local h b
  h=$(sha256sum "$arq" | cut -d' ' -f1)   # hash calculado NA HORA da coleta
  b=$(stat -c %s "$arq")
  echo "$ITEM;$arq;$h;$b;$QUEM;$(date -u +%Y-%m-%dT%H:%M:%SZ);$origem;$metodo;$obs" >> "$CUSTODIA"
  ITEM=$((ITEM + 1))
}

echo "coletando em $DIR"

# 1. logs centralizados (copia preservando data de modificacao)
cp -a logs/. "$DIR/logs/"
find "$DIR/logs" -type f | sort | while read -r f; do
  registrar "$f" "host:logs/$(basename "$f")" "cp -a (copia logica)" ""
done
ITEM=$(($(wc -l < "$CUSTODIA")))

if command -v docker >/dev/null && docker ps >/dev/null 2>&1; then
  set -a; . ./.env; set +a
  # 2. banco: dump completo + tabelas que interessam em csv
  docker exec db pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner > "$DIR/banco/dump.sql"
  registrar "$DIR/banco/dump.sql" "container db" "pg_dump" "dump completo do banco"
  for t in agendamento_bomba comandos auditoria alertas respostas_pendentes; do
    docker exec db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "\copy $t TO STDOUT WITH CSV HEADER" > "$DIR/banco/$t.csv"
    registrar "$DIR/banco/$t.csv" "container db tabela $t" "psql \\copy" ""
  done

  # 3. estado dos sistemas no momento da coleta (volatil, por isso vem cedo)
  docker ps -a --no-trunc > "$DIR/sistema/docker_ps.txt"
  registrar "$DIR/sistema/docker_ps.txt" "host docker" "docker ps -a" "containers e estado"
  docker exec nuvem-gw wg show wg0 dump > "$DIR/sistema/wg_show.txt" 2>/dev/null || true
  [ -s "$DIR/sistema/wg_show.txt" ] && registrar "$DIR/sistema/wg_show.txt" "container nuvem-gw" "wg show dump" "sessoes VPN ativas"
  docker exec nuvem-gw iptables -S > "$DIR/sistema/iptables_gw.txt" 2>/dev/null || true
  [ -s "$DIR/sistema/iptables_gw.txt" ] && registrar "$DIR/sistema/iptables_gw.txt" "container nuvem-gw" "iptables -S" "regras de firewall (bloqueios do SOAR)"
  for c in $(docker ps -a --format '{{.Names}}'); do
    docker inspect "$c" > "$DIR/sistema/inspect_$c.json"
    docker logs --timestamps "$c" > "$DIR/sistema/stdout_$c.log" 2>&1 || true
  done
  find "$DIR/sistema" -name 'inspect_*' -o -name 'stdout_*' | sort | while read -r f; do
    registrar "$f" "host docker" "docker inspect / docker logs --timestamps" ""
  done
  ITEM=$(($(wc -l < "$CUSTODIA")))

  # 4. buffer local das bordas (o que ficou guardado durante queda de link)
  for b in borda-escola borda-ubs; do
    if docker cp "$b:/dados/buffer.db" "$DIR/borda/$b-buffer.db" 2>/dev/null; then
      registrar "$DIR/borda/$b-buffer.db" "container $b:/dados/buffer.db" "docker cp" "buffer store-and-forward"
    fi
  done
fi

# 5. lista de hashes + pacote final
( cd "$DIR" && find . -type f ! -name hashes.sha256 -print0 | sort -z | xargs -0 sha256sum > hashes.sha256 )
tar -czf "$DIR.tar.gz" -C "evidencias/$CASO" "$TS"
registrar "$DIR.tar.gz" "pacote da coleta" "tar -czf" "pacote final, conferir com sha256sum"
chmod -R a-w "$DIR" "$DIR.tar.gz"

echo
echo "coleta concluida."
echo "  hashes:   $DIR/hashes.sha256"
echo "  custodia: $CUSTODIA"
echo "  pacote:   $DIR.tar.gz  sha256=$(sha256sum "$DIR.tar.gz" | cut -d' ' -f1)"
echo "pra conferir integridade depois: ./forense/verificar.sh $DIR"
