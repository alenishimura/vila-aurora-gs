# Guia de estudo da Vila Aurora

Este guia explica o projeto do zero, na ordem em que faz sentido estudar. A ideia é que
depois de ler você consiga explicar qualquer parte na banca e no vídeo, que é exatamente o
que o enunciado cobra ("todos devem ser capazes de explicar qualquer parte do projeto").

Leia com o `docs/RELATORIO_TECNICO.md` do lado, que é o entregável formal. Aqui o tom é de
aula; lá é de relatório.

---

## 1. A história que amarra tudo

A Rede Vila Aurora tem cinco espaços (centro comunitário, escola, UBS, horta e abrigo) que
dependem de energia, água, acesso e sensores de ambiente. A internet do bairro é uma fibra
comunitária que cai no temporal, bem na hora que o abrigo e a UBS mais precisam.

Três semanas antes, aconteceu o incidente **INC-VA-0712**. A cadeia foi essa:

1. A coordenadora recebeu um e-mail "da prefeitura" (gerado por IA, sem erros) e um áudio de
   WhatsApp com a voz clonada do secretário, pedindo "atualização do acesso".
2. Ela digitou usuário e senha numa página falsa. A VPN era antiga, só senha, sem MFA.
3. De madrugada, login na VPN de um IP externo. O painel de supervisão tinha SQL Injection.
4. Pela injeção, o atacante puxou a tabela de usuários e **mudou o agendamento da bomba**. O
   reservatório da escola esvaziou.
5. A fibra caiu. O alarme da câmara fria das vacinas dependia da nuvem, então a temperatura
   subiu por horas sem ninguém saber.
6. Os logs estavam espalhados, com relógios fora de sincronia e parte sobrescrita.

**A regra de ouro do projeto**: cada um desses seis pontos tem que virar um controle na
arquitetura. Se você souber recitar essa lista e apontar onde cada falha foi resolvida, já
dá conta de metade da banca.

---

## 2. A arquitetura em camadas (RT-01)

São quatro camadas. Pense de baixo para cima:

- **Campo**: os sensores e atuadores. No lab são containers Python (`campo/sensor.py`) que
  fingem ser a câmara fria, o nível da caixa, a bomba, a fechadura e a energia. Cada um tem
  o seu certificado.
- **Borda** (`borda/agente.py`): um "mini-servidor" em cada espaço. Tem o broker MQTT local
  e roda as regras de controle. **É aqui que mora a resiliência**: mesmo sem internet, a
  borda continua lendo sensor e tomando decisão.
- **Nuvem**: consolida os dados (coletor + banco), hospeda o painel e o SIEM.
- **Supervisão**: o painel web onde o voluntário vê e intervém.

Por que separar assim? Porque se a nuvem ou a internet caem, as camadas de baixo continuam.
No sistema antigo tudo dependia da nuvem, e foi por isso que a câmara fria ficou sem alarme.

**O coração do protótipo é a borda.** Se você entender o `agente.py`, entende o projeto.

### O que a borda faz (em uma frase cada)

- Recebe a telemetria dos sensores pelo broker local, só de quem tem certificado válido.
- Aplica as regras locais: alarme da câmara fria, piso de nível da bomba, tempo máximo ligada.
- Guarda tudo num SQLite (buffer) e manda para a nuvem quando o link está de pé. Se o link
  cai, segura no buffer e reenvia depois. Isso é o **store-and-forward** (RT-02).
- Valida qualquer comando ou agenda que venha da nuvem antes de obedecer.

---

## 3. Identidade, VPN e segmentação (RT-04 a RT-07, RT-09)

### Certificado por dispositivo (mTLS)

Cada dispositivo tem um certificado X.509 emitido pela **CA do projeto** (`pki/`). "mTLS"
quer dizer que os **dois lados** provam quem são: o sensor prova que é o sensor, e o broker
prova que é o broker. Nada de senha compartilhada. Se um dispositivo é comprometido, dá para
**revogar** só o certificado dele (CRL), sem mexer nos outros.

Para explicar na prática:
- `pki/emitir.sh` cria uma chave e um certificado para um nome. A chave nunca sai do dono.
- `pki/revogar.sh` põe o certificado numa lista de revogados (CRL) e reinicia quem usa, para
  o broker e o gateway passarem a recusar aquele certificado.
- `pki/rotacionar.sh` troca um certificado por um novo e revoga o antigo. É a rotação de
  credencial que o RT-05 pede.

O broker (`borda/mosquitto.conf.tpl`) tem `require_certificate true` e lê a CRL. A ACL
(`borda/acl`) dá menor privilégio: cada dispositivo só publica no seu próprio tópico.

### VPN e segmentação

A borda fala com a nuvem por **WireGuard** (VPN moderna, `vpn/`). O acesso administrativo
remoto do operador também passa pela VPN, e ainda exige MFA no painel. **Nenhuma porta
administrativa fica exposta à internet**; a única porta aberta para fora é a do WireGuard.

Segmentação (RT-07): no `docker-compose.yml`, os dispositivos de IoT, os operadores e os
serviços ficam em redes Docker separadas, marcadas como `internal`. O firewall do gateway
(`nuvem/gw/entrypoint.sh`) só deixa a borda falar na porta do ingest e o operador na porta
do painel. Um peer não fala com o outro. Isso é o "menor privilégio entre segmentos".

### MFA e RBAC (RT-09)

O painel novo pede senha **e** um código TOTP (aquele app autenticador do celular). Depois
do login, cada pessoa tem um perfil (RBAC): operador, técnico, coordenação ou auditor. Quem
pode o quê está no `nuvem/painel/app.py`, nos decoradores `@requer(...)`. Exemplo: só
coordenação aprova comando de alto impacto; auditor só lê.

---

## 4. SQL Injection: o antes e o depois (RT-08)

Esse critério vale 1,5 ponto e é o mais fácil de demonstrar bem.

### O "antes" (painel legado, `nuvem/painel_legado/app.py`)

A busca do histórico monta o SQL **concatenando texto**:

```python
sql = "... WHERE nome_usuario ILIKE '%" + busca + "%' ..."
```

Se você digita `' UNION SELECT ...`, o seu texto vira parte da consulta. Por isso dá para:
- puxar a tabela de usuários inteira (`UNION SELECT login || ':' || senha ...`);
- alterar a agenda da bomba (`'; UPDATE agendamento_bomba ...`).

E ainda tem três erros que pioram tudo: conecta no banco como superusuário, mostra o erro do
banco na tela (ajuda o atacante) e guarda senha em texto puro. O `incidente/reproduzir.sh`
faz exatamente esse ataque, e dá para rodar o `sqlmap` em cima para mostrar automatizado.

### O "depois" (painel novo, `nuvem/painel/app.py`, função `acessos`)

Três camadas de defesa:

1. **Consulta parametrizada**: a busca vai num `%s` separado, o banco trata como dado, nunca
   como código. É a correção da causa raiz.
   ```python
   consulta("... WHERE v.nome ILIKE %s ...", (f"%{busca}%",))
   ```
2. **Validação de entrada** no servidor: a busca só aceita letras, números, espaço e hífen.
3. **Menor privilégio**: o painel conecta como `painel_app`, que nem enxerga o schema
   `legado` e só tem os GRANTs que precisa (`nuvem/db/init/02_roles.sh`). Mesmo que algo
   passasse, o estrago seria limitado. Erro vira mensagem genérica com um código, e tem o
   **WAF** (ModSecurity + OWASP CRS) na frente como camada extra.

No vídeo: mostre o `sqlmap` achando a injeção no legado, depois rode a mesma coisa no painel
novo e mostre que a entrada é rejeitada e o WAF bloqueia. É o "antes e depois" que a rubrica pede.

---

## 5. Phishing e fator humano (RT-10, RT-11, RT-18)

Tudo em `phishing/`. Três partes:

- **SPF, DKIM, DMARC** (RT-10): são registros de DNS que dificultam falsificar e-mail do
  domínio. SPF diz quais servidores podem mandar; DKIM assina a mensagem; DMARC diz o que
  fazer se falhar (aqui, `quarantine`). O `gerar_dns.sh` monta isso para o domínio fictício
  `vilaaurora.lab` e o `verificar_dns.py` confere.
- **Campanha simulada** (RT-11): Gophish, só contra contas fictícias da equipe. O passo a
  passo está no `phishing/README.md`. Você coleta abertura, clique, submissão e **reporte**.
- **Ameaças com IA** (RT-18): o phishing do incidente foi gerado por IA (sem erros) e teve
  voz clonada. A defesa é de processo: verificação fora de banda (ligar no número do cartaz),
  palavra-código combinada pessoalmente, e a regra de que decisão sobre equipamento nunca sai
  de um áudio. A dica velha de "procure erro de português" não serve mais.

Atenção ética: campanha só contra conta fictícia, nunca pessoa real. Usar pessoa real sem
consentimento zera o critério.

---

## 6. Detecção, resposta e forense (RT-12 a RT-15)

### Logs centralizados (RT-12)

Todos os serviços escrevem log em JSON na pasta `logs/`. Todos os containers estão em UTC
(sincronismo de relógio), então a linha do tempo fecha. O Wazuh (SIEM, `siem/`) lê esses
logs. Se o PC não aguentar o Wazuh, o `soc/detector.py` faz as mesmas 4 regras.

### As 4 regras de detecção (RT-13)

Estão no `soc/detector.py` e repetidas como regras do Wazuh em `siem/vila_aurora_rules.xml`:

1. **Login VPN anômalo**: handshake de um IP nunca visto, de chave desconhecida, ou operador
   de madrugada.
2. **SQL Injection**: padrão de ataque no campo de busca, erro de SQL vindo de entrada do
   usuário, ou bloqueio do WAF (regras 942xxx do CRS).
3. **Dispositivo sem certificado válido**: falha de TLS no broker, ou 400 no ingest da nuvem.
4. **Comando de atuador fora do horário/perfil**: comando rejeitado pela borda, agenda
   adulterada, ou bomba acionada de madrugada.

Cada alerta já vem com o mapeamento MITRE ATT&CK.

### Resposta automatizada (RT-15)

O `soc/responder.py` lê os alertas e age, **classificando por risco** (é o que o enunciado
mais cobra aqui):

- **Baixo risco, automático**: isolar o dispositivo, revogar certificado, encerrar a sessão
  de VPN, bloquear IP, pôr o atuador em modo seguro.
- **Alto impacto, só com aprovação humana**: desligar a bomba, liberar todas as portas. Isso
  vira um pedido na tabela `respostas_pendentes` e só roda quando a coordenação aprova no
  painel. O raciocínio: isolar um sensor é inofensivo, mas desligar a bomba do abrigo durante
  uma enchente não é.

### Forense (RT-14)

O `forense/coletar.sh`:
- calcula o **hash SHA-256 na hora da coleta** e registra na **cadeia de custódia** (quem,
  quando, de onde, como), num CSV;
- empacota tudo e deixa só leitura;
- o `verificar.sh` confere depois que nada mudou.

O `forense/linha_do_tempo.py` junta todos os logs, converte para UTC e monta a linha do
tempo com o mapeamento ATT&CK. É o que vira o laudo (E4).

---

## 7. IA & Cyber (RT-16 a RT-18)

Usamos IA de forma **defensiva**: detecção de anomalia na telemetria com **Isolation Forest**
(`ia/anomalias.py`). Por que não um LLM? Porque LLM traria o RT-17 (guardrails contra prompt
injection) junto, e para o prazo não compensa. Isolation Forest é o próprio enunciado que
sugere, e dá para medir de verdade.

O que ele pega que uma regra fixa não pega:
- sensor "travado" mandando sempre o mesmo valor (falha ou leitura falsificada);
- subida lenta de temperatura que ainda está dentro da faixa 2-8 (falha do compressor);
- queda de nível rápida demais (vazamento) ou bomba que deveria ligar e não liga (a própria
  manipulação do INC-VA-0712).

Como os dados são sintéticos e **rotulados** (sabemos onde injetamos a anomalia), medimos
precisão, revocação, F1 e taxa de falso positivo de verdade. O script compara Isolation
Forest, LOF e um híbrido, e salva gráficos. Os números estão em `ia/resultados/metricas.json`.

Lição importante para a banca: o Isolation Forest sozinho não pega o "sensor travado", porque
no treino essa característica é sempre zero. Por isso o híbrido junta o modelo com uma regra
simples. Saber explicar essa limitação vale ponto.

---

## 8. Métricas, resiliência e viabilidade (RT-19 a RT-23)

### Teste de caos (RT-23)

`caos/teste_caos.sh` derruba a WAN por 30+ minutos (desconecta a borda da rede), prova que a
borda continua operando local (a bomba liga pela regra de piso mesmo sem nuvem) e que, quando
o link volta, o buffer é reenviado sem perder dado.

### Métricas (RT-22)

`metricas/medir.py` calcula a partir dos logs:
- **Disponibilidade** (% do tempo com link).
- **MTTD** (quanto tempo entre o evento e o alerta do detector).
- **MTTR** (entre o alerta e a resposta automática).
- **Tempo de operação autônoma** (maior intervalo sem internet operando).
- **Perda na reconciliação** (enviado pela borda menos gravado no banco; deu zero, por causa
  do `msg_id` que evita duplicar e não perder).
- **Consumo** de CPU, memória e banda da borda.

### Privacidade, custo, acessibilidade (RT-19 a RT-21)

- **LGPD** (RT-19): o id do crachá nunca aparece em claro. A borda troca por um pseudônimo
  (HMAC). Só coordenação e auditor cruzam pseudônimo com nome. Dados 100% sintéticos.
- **Acessibilidade** (RT-21): o painel tem contraste AA, navegação por teclado, botão de
  texto grande e alto contraste, linguagem simples, e os avisos usam cor **e** símbolo (não
  só cor), pensando em quem não enxerga bem ou é daltônico.
- **Custo e manutenção** (RT-20): estimativa no relatório, com quem cuida de quê (firmware,
  renovação de certificado, backup).

---

## 9. Roteiro sugerido do vídeo (C9)

O vídeo precisa de demonstração real, não só slides. Sugestão de ordem (uns 8-10 min):

1. 30s: o problema (o incidente) e a ideia da solução.
2. Arquitetura em camadas (mostre o diagrama do relatório).
3. Suba o ambiente e mostre o painel novo com MFA.
4. SQL Injection: ataque no legado com sqlmap, depois a busca rejeitada no painel novo.
5. Teste de caos: derrube a WAN, mostre a borda operando sozinha e a reconciliação.
6. Detecção e resposta: dispare um alerta e mostre a resposta automática e o pedido de
   aprovação do alto impacto.
7. Forense: a coleta com hash e a linha do tempo.
8. IA: os gráficos e as métricas.
9. Fecho: as métricas e uma frase sobre custo e LGPD.

Não precisa mostrar tudo funcionando ao vivo ao mesmo tempo. Grave cada parte separada.

---

## 10. Perguntas que a banca pode fazer (e a resposta curta)

- **Por que a borda e não fazer tudo na nuvem?** Porque a internet cai justo quando mais
  precisa. A borda garante que o alarme da câmara fria e o controle da bomba continuam.
- **O que impede a nuvem comprometida de esvaziar a caixa de novo?** A regra local de piso de
  nível na borda. Ela ignora agenda da nuvem que mande a bomba desligar abaixo de 25%.
- **mTLS resolve o quê?** Garante que só dispositivo com certificado do projeto entra, e dá
  revogação individual. Acaba com a senha compartilhada.
- **Por que Isolation Forest e não um LLM?** Para o escopo, anomalia em série temporal é o
  caso certo e dá para medir. LLM traria risco de prompt injection sem ganho aqui.
- **Como o laudo forense se sustenta?** Hash calculado na coleta, cadeia de custódia, NTP em
  tudo e logs centralizados. Sem relógio sincronizado, a linha do tempo não vale.
