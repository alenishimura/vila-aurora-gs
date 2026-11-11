-- banco da nuvem da Rede Vila Aurora
-- todos os dados aqui sao SINTETICOS (gerados pra aula)

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE TABLE espacos (
    id   TEXT PRIMARY KEY,
    nome TEXT NOT NULL
);

CREATE TABLE dispositivos (
    cn        TEXT PRIMARY KEY,
    espaco    TEXT REFERENCES espacos(id),
    tipo      TEXT NOT NULL,
    ativo     BOOLEAN DEFAULT TRUE,
    revogado  BOOLEAN DEFAULT FALSE
);

CREATE TABLE telemetria (
    msg_id      UUID PRIMARY KEY,           -- chave de idempotencia da reconciliacao
    ts          TIMESTAMPTZ NOT NULL,       -- hora da leitura no dispositivo
    recebido_em TIMESTAMPTZ DEFAULT now(),  -- hora que chegou na nuvem
    espaco      TEXT,
    dispositivo TEXT,
    tipo        TEXT,
    via         TEXT,
    dados       JSONB
);
CREATE INDEX ON telemetria (dispositivo, ts DESC);

CREATE TABLE alertas (
    id             SERIAL PRIMARY KEY,
    msg_id         UUID UNIQUE,
    ts             TIMESTAMPTZ NOT NULL,
    recebido_em    TIMESTAMPTZ DEFAULT now(),
    espaco         TEXT,
    tipo           TEXT,
    mensagem       TEXT,
    origem         TEXT,          -- regra_local (borda) ou nuvem
    dados          JSONB,
    reconhecido_por TEXT,
    reconhecido_em TIMESTAMPTZ
);

-- registro de acesso das fechaduras: so pseudonimo, nunca o id do cracha
CREATE TABLE acessos (
    id         SERIAL PRIMARY KEY,
    ts         TIMESTAMPTZ NOT NULL,
    espaco     TEXT,
    porta      TEXT,
    pseudonimo TEXT,
    liberado   BOOLEAN
);
CREATE INDEX ON acessos (ts DESC);

-- cadastro de voluntarios: o pseudonimo e o mesmo HMAC que a borda calcula
-- so coordenacao e auditor podem cruzar pseudonimo -> nome
CREATE TABLE voluntarios (
    id         SERIAL PRIMARY KEY,
    nome       TEXT NOT NULL,
    funcao     TEXT,
    pseudonimo TEXT UNIQUE
);

CREATE TABLE operadores (
    id               SERIAL PRIMARY KEY,
    usuario          TEXT UNIQUE NOT NULL,
    nome             TEXT,
    perfil           TEXT NOT NULL CHECK (perfil IN ('operador','tecnico','coordenacao','auditor')),
    senha_hash       TEXT NOT NULL,
    totp_segredo     TEXT NOT NULL,
    ativo            BOOLEAN DEFAULT TRUE,
    tentativas_falhas INT DEFAULT 0,
    bloqueado_ate    TIMESTAMPTZ
);

CREATE TABLE agendamento_bomba (
    espaco        TEXT PRIMARY KEY,
    ativo         BOOLEAN NOT NULL DEFAULT TRUE,
    nivel_liga    INT NOT NULL,
    nivel_desliga INT NOT NULL,
    alterado_por  TEXT,
    alterado_em   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE comandos (
    id             SERIAL PRIMARY KEY,
    criado_em      TIMESTAMPTZ DEFAULT now(),
    espaco         TEXT,
    dispositivo    TEXT,
    acao           TEXT,
    solicitado_por TEXT,
    perfil         TEXT,
    alto_impacto   BOOLEAN DEFAULT FALSE,
    status         TEXT DEFAULT 'liberado',  -- aguardando_aprovacao, liberado, entregue, executado, rejeitado, negado
    aprovado_por   TEXT,
    aprovado_em    TIMESTAMPTZ,
    resultado      JSONB,
    motivo         TEXT
);

-- acoes de resposta a incidente de alto impacto ficam aqui ate um humano aprovar
CREATE TABLE respostas_pendentes (
    id           SERIAL PRIMARY KEY,
    criado_em    TIMESTAMPTZ DEFAULT now(),
    alerta       TEXT,
    acao         TEXT,
    alvo         TEXT,
    justificativa TEXT,
    status       TEXT DEFAULT 'aguardando',  -- aguardando, aprovada, negada, executada
    decidido_por TEXT,
    decidido_em  TIMESTAMPTZ
);

CREATE TABLE auditoria (
    id      SERIAL PRIMARY KEY,
    ts      TIMESTAMPTZ DEFAULT now(),
    usuario TEXT,
    acao    TEXT,
    detalhe JSONB
);

INSERT INTO espacos VALUES
 ('centro', 'Centro Comunitario'),
 ('escola', 'Escola Municipal'),
 ('ubs', 'Unidade Basica de Saude'),
 ('horta', 'Horta e Cozinha Solidaria'),
 ('abrigo', 'Abrigo de Emergencia');

INSERT INTO dispositivos VALUES
 ('escola-nivel-01', 'escola', 'nivel', true, false),
 ('escola-bomba-01', 'escola', 'bomba', true, false),
 ('escola-fechadura-01', 'escola', 'fechadura', true, false),
 ('ubs-camarafria-01', 'ubs', 'camara_fria', true, false),
 ('ubs-energia-01', 'ubs', 'energia', true, false);

INSERT INTO agendamento_bomba (espaco, ativo, nivel_liga, nivel_desliga, alterado_por)
VALUES ('escola', true, 40, 90, 'implantacao');


-- ===================================================================
-- schema do SISTEMA LEGADO (antes do projeto). existe so pra reproduzir
-- o INC-VA-0712. senha em texto puro e dados pessoais em claro de proposito.
-- ===================================================================
CREATE SCHEMA legado;

CREATE TABLE legado.usuarios (
    id       SERIAL PRIMARY KEY,
    login    TEXT,
    senha    TEXT,
    nome     TEXT,
    cpf      TEXT,
    telefone TEXT,
    email    TEXT,
    perfil   TEXT
);

CREATE TABLE legado.historico_acessos (
    id            SERIAL PRIMARY KEY,
    data_hora     TIMESTAMP,
    nome_usuario  TEXT,
    porta         TEXT,
    espaco        TEXT
);
