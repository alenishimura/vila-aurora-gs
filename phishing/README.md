# Phishing simulado e fator humano (RT-10, RT-11, RT-18)

Tudo aqui roda **só no laboratório, contra contas fictícias da própria equipe**. Nunca
mandar para pessoa real nem coletar credencial de verdade (regra de ética do enunciado,
Lei 12.737/2012). O critério C4 zera se usar pessoas reais sem consentimento.

## O que já está pronto

- **SPF, DKIM e DMARC** (RT-10): `gerar_dns.sh` cria a chave DKIM e a zona do domínio fictício
  `vilaaurora.lab`, com SPF `-all`, DKIM 2048 bits e DMARC em `p=quarantine`. O CoreDNS do
  perfil `phishing` serve a zona, e `verificar_dns.py` confere os três registros.
- **Infra do teste**: o `docker-compose.yml` sobe Gophish (painel em 127.0.0.1:3333),
  MailHog (caixa de entrada falsa em 127.0.0.1:8025) e o DNS. Ninguém sai para a internet.

## Montar a campanha (RT-11) — passo a passo no Gophish

Faça isso você mesmo no painel do Gophish, porque o conteúdo da isca precisa sair da equipe
(o professor pede que todos saibam explicar cada parte):

1. **Sending Profile**: SMTP apontando para o MailHog (`mailhog:1025`), remetente num domínio
   *parecido* com o fictício (ex.: `prefeitura-serraclara.lab`) para treinar o olhar.
2. **Users & Groups**: cadastre só as contas fictícias da equipe (ex.: `voluntario1@vilaaurora.lab`).
3. **Landing Page**: o Gophish tem "Import Site" e páginas de exemplo. Use uma página de login
   fictícia **com aviso de treinamento** e marque *Capture Submitted Data* só para contar a
   submissão (não guarde senha real — são contas de teste).
4. **Email Template**: escreva o texto da isca reproduzindo o estilo do INC-VA-0712 (urgência,
   "atualização obrigatória do acesso"). Use os placeholders `{{.FirstName}}` e `{{.URL}}` do
   próprio Gophish. Deixe pistas sutis (domínio trocado, pressa) para discutir depois.
5. **Campaign**: dispare contra o grupo fictício e acompanhe as métricas.

## Métricas a coletar (vão para o E3)

O Gophish já conta por evento. Exporte e registre a tabela:

| Métrica | Como o Gophish chama | Observação |
|---|---|---|
| Enviados | Email Sent | base do funil |
| Abertura | Email Opened | abriu o e-mail |
| Clique | Clicked Link | caiu no link |
| Submissão | Submitted Data | digitou credencial na página falsa |
| Reporte | (botão/ألias de report) | quem avisou a coordenação — **o número que queremos alto** |

Calcule taxa de clique, taxa de submissão e taxa de reporte sobre os enviados.

## Plano de conscientização adaptado a voluntários

Pensado para gente sem formação técnica (o enunciado insiste nisso):

- **Regra da verificação fora de banda**: pedido urgente que chega por e-mail ou WhatsApp só
  vale depois de ligar para o número do cartaz da coordenação. Nunca pelo contato que veio na mensagem.
- **Palavra-código** para pedidos urgentes internos, combinada presencialmente. Serve contra voz
  clonada (ver RT-18 abaixo).
- **A prefeitura/coordenação nunca pede senha** por e-mail, link ou áudio. O próprio painel já traz
  esse aviso na tela de login.
- **Como reportar**: botão de reporte ou um contato fixo. Reportar é elogiado, não punido — é o que
  mais reduz o estrago.
- Cartaz de uma página com 3 sinais de phishing (urgência, remetente estranho, link pedindo senha).

## RT-18 — ameaças potencializadas por IA no cenário

O INC-VA-0712 usou duas coisas que a IA deixou baratas e convincentes:

1. **E-mail de phishing gerado por IA**: sem erros de português e personalizado, então as dicas
   antigas ("procure erros de gramática") não servem mais.
   - Controles: SPF/DKIM/DMARC barram parte da falsificação de domínio; MFA (TOTP) no painel faz a
     senha roubada sozinha não bastar; verificação fora de banda; triagem dos e-mails.
2. **Voz clonada do secretário no WhatsApp**: reforça a urgência e confunde a vítima.
   - Controles: palavra-código combinada pessoalmente; regra de que decisão sobre equipamento
     (bomba, portas) nunca sai de um áudio; retorno de ligação para o número oficial.

A defesa aqui é de processo, não de tecnologia: nenhuma ação crítica depende de um único canal.
Isso conecta com o painel, onde comando de alto impacto exige aprovação de uma segunda pessoa.
