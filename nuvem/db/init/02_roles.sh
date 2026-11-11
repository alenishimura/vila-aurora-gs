#!/bin/bash
# cria os usuarios de banco com o minimo de privilegio
# as senhas vem do .env (nao ficam no repositorio)
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v painel_senha="$PAINEL_DB_SENHA" -v coletor_senha="$COLETOR_DB_SENHA" <<'EOSQL'

CREATE ROLE painel_app LOGIN PASSWORD :'painel_senha';
CREATE ROLE coletor_app LOGIN PASSWORD :'coletor_senha';

GRANT USAGE ON SCHEMA public TO painel_app, coletor_app;

-- painel: le quase tudo, escreve pouco. NAO enxerga o schema legado
GRANT SELECT ON espacos, dispositivos, telemetria, alertas, acessos, comandos,
               agendamento_bomba, respostas_pendentes, auditoria TO painel_app;
GRANT SELECT (id, usuario, nome, perfil, senha_hash, totp_segredo, ativo, tentativas_falhas, bloqueado_ate)
      ON operadores TO painel_app;
GRANT UPDATE (tentativas_falhas, bloqueado_ate) ON operadores TO painel_app;
GRANT SELECT (nome, funcao, pseudonimo) ON voluntarios TO painel_app;
GRANT INSERT ON comandos, auditoria TO painel_app;
GRANT UPDATE (status, aprovado_por, aprovado_em, motivo) ON comandos TO painel_app;
GRANT UPDATE (ativo, nivel_liga, nivel_desliga, alterado_por, alterado_em) ON agendamento_bomba TO painel_app;
GRANT UPDATE (reconhecido_por, reconhecido_em) ON alertas TO painel_app;
GRANT UPDATE (status, decidido_por, decidido_em) ON respostas_pendentes TO painel_app;
GRANT USAGE ON SEQUENCE comandos_id_seq, auditoria_id_seq TO painel_app;

-- coletor: so o que o ingest precisa
GRANT SELECT ON dispositivos, agendamento_bomba TO coletor_app;
GRANT INSERT ON telemetria, alertas, acessos TO coletor_app;
-- o ON CONFLICT (msg_id) precisa ler a coluna da chave
GRANT SELECT (msg_id) ON telemetria, alertas TO coletor_app;
GRANT SELECT, UPDATE ON comandos TO coletor_app;
GRANT USAGE ON SEQUENCE alertas_id_seq, acessos_id_seq TO coletor_app;

REVOKE ALL ON SCHEMA legado FROM PUBLIC;
EOSQL

echo "roles criados"
