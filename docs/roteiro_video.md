# Roteiro do vídeo - Rede Comunitária Vila Aurora

Duração alvo: 8 a 10 minutos. Para cada parte tem o que mostrar na tela e o texto
para ler. Fala com naturalidade, não precisa decorar. Grave a tela mostrando as
coisas funcionando de verdade, que é o que o professor pede.

Dica: deixe o laboratório no ar (`docker compose up -d`) e as abas já abertas antes
de começar a gravar: o painel, o terminal, e o Gophish.

---

## 1. Abertura (30 segundos)

TELA: seu rosto ou um slide com o título "Rede Comunitária Vila Aurora".

Texto:
"Oi, eu sou o Alexandre. Esse é o meu projeto da Global Solution de Cybersecurity,
o desafio da Rede Comunitária Vila Aurora. A ideia é construir uma infraestrutura
que monitora energia, água e acesso de cinco espaços comunitários, que continua
funcionando quando a internet cai, e que resiste ao tipo de ataque que já aconteceu
com essa rede, o incidente INC-VA-0712. Vou mostrar tudo funcionando."

---

## 2. O incidente e a arquitetura (1 minuto)

TELA: o diagrama de arquitetura do relatório (as quatro camadas).

Texto:
"Primeiro, o problema. No incidente, um e-mail de phishing roubou a senha de uma
coordenadora. Com isso o atacante entrou pela VPN, explorou uma falha de SQL
Injection no painel e sabotou a bomba d'água. E quando a fibra caiu, o alarme da
câmara fria das vacinas, que dependia da nuvem, ficou mudo por horas.

Minha solução é em quatro camadas: campo, borda, nuvem e supervisão. A peça central
é a borda, um nó em cada espaço que continua operando sozinho mesmo sem internet.
Cada controle que eu vou mostrar conserta um ponto específico daquele incidente."

---

## 3. Ambiente no ar e telemetria (1 minuto)

TELA: o terminal com `docker compose ps` mostrando os containers, depois o painel
logado (a tela "Situação agora").

Texto:
"Aqui está o ambiente rodando: são quinze containers, o banco, o painel, o gateway,
as duas bordas e os sensores, cada um numa rede segmentada. No painel, repare que eu
entrei com senha e um código de verificação, o MFA, que no incidente não existia.
Essa é a tela de supervisão, com as leituras chegando em tempo real: a câmara fria a
quatro graus, a caixa d'água, a bomba. E tudo isso passou pela cadeia inteira: o
sensor leu, mandou por MQTT com certificado pra borda, a borda levou pela VPN até a
nuvem."

---

## 4. SQL Injection, antes e depois (1 minuto e meio)

TELA: rode `./entregaveis/c3_sqli.sh` ao vivo, ou mostre o print do resultado.

Texto:
"Agora o ponto mais crítico, o SQL Injection. No painel antigo, o campo de busca
juntava o texto digitado direto na consulta. Então com um UNION SELECT eu consegui
roubar a senha de todos os usuários, e com um UPDATE eu sabotei a agenda da bomba,
que foi o que esvaziou a caixa no incidente.

No painel novo, o mesmo ataque leva um HTTP 403, bloqueado pelo WAF. E a correção de
verdade está no código: em vez de juntar o texto, a consulta usa parâmetro, que trata
a entrada como dado e nunca como código, mais a validação de entrada e o banco com
privilégio mínimo. É a correção na causa raiz, não só um filtro."

---

## 5. Detecção e resposta (1 minuto)

TELA: o print do detector com as 4 regras e o print do responder (SOAR).

Texto:
"Todos os logs ficam centralizados e em UTC. Em cima deles eu tenho quatro regras de
detecção: login de VPN anômalo, SQL injection, dispositivo sem certificado e comando
de atuador fora do perfil. Aqui elas dispararam, cada alerta já mapeado no MITRE
ATT&CK.

E a resposta é automatizada, mas com cuidado: ações de baixo risco, como bloquear um
IP ou isolar um sensor, são automáticas. Já desligar a bomba, que é alto impacto e
pode deixar a escola sem água, vira um pedido que só executa depois que uma pessoa da
coordenação aprova. Essa separação entre o que a máquina faz sozinha e o que precisa
de um humano é o coração da resposta."

---

## 6. Teste de caos, a resiliência (1 minuto e meio)

TELA: o print final do teste de caos (os eventos) ou o `metricas.json`.

Texto:
"Essa é a prova mais importante. Eu derrubei a conexão das bordas com a nuvem por
trinta e dois minutos. Durante esse tempo, a borda continuou lendo os sensores e
operando sozinha, inclusive ligando a bomba pela regra local de nível. O buffer foi
guardando tudo: chegou a mais de mil mensagens acumuladas.

Quando a conexão voltou, a borda reconciliou tudo em pouco mais de um minuto, com
perda zero. Das nove mil mensagens enviadas, todas chegaram ao banco. E o consumo da
borda é baixo, uns quarenta megabytes de memória, então roda tranquilo num Raspberry
Pi. É a resposta direta à câmara fria que ficou sem alarme no incidente: agora cada
espaço funciona sozinho."

---

## 7. Forense (1 minuto)

TELA: a linha do tempo do ataque (`linha_do_tempo_ataque.md`) e a cadeia de custódia.

Texto:
"Depois de um incidente, é preciso investigar. Eu reproduzi o ataque no meu próprio
ambiente e coletei as evidências calculando o hash de cada arquivo no momento da
coleta, com cadeia de custódia: quem coletou, quando e de onde. Isso garante que a
prova não foi adulterada.

Com os relógios sincronizados, montei a linha do tempo do ataque, mapeada no MITRE:
o login com a credencial roubada, a injeção que rouba os dados, e a alteração da
bomba. É o laudo forense, que no incidente real não foi possível fazer porque os logs
estavam espalhados e com horário errado."

---

## 8. IA defensiva (1 minuto)

TELA: os gráficos da IA (`grafico_camara_fria.png`) e o `metricas.json`.

Texto:
"Pra fechar a parte técnica, a IA defensiva. Eu uso um Isolation Forest pra detectar
anomalias na telemetria. Na câmara fria, o sensor crítico, o modelo pega oitenta e
três por cento das anomalias com menos de um por cento de alarme falso.

E aqui vai uma análise honesta: o Isolation Forest sozinho não detecta um sensor
travado, porque esse padrão é invisível no treino. Por isso eu combinei ele com uma
regra simples. E pro nível da água o modelo não vai bem, então nesse caso a regra
determinística da borda é mais confiável que a IA. Medir o erro e saber onde a IA
falha vale mais do que forçar um número bonito."

---

## 9. Phishing e fator humano (1 minuto)

TELA: o resultado do `verificar_dns.py` (SPF/DKIM/DMARC) e o dashboard do Gophish.

Texto:
"O ataque começou por e-mail, então eu protegi o domínio com SPF, DKIM e DMARC, que
dificultam falsificar e-mail da rede. E rodei uma campanha de phishing simulado, só
contra contas fictícias. O resultado: de cinco pessoas, quatro clicaram e três
entregaram os dados numa página falsa. Isso mostra o tamanho do risco humano.

A defesa aqui é de processo: verificar pedidos urgentes por outro canal, uma palavra
código combinada pessoalmente, e nunca decidir sobre um equipamento a partir de um
áudio, porque hoje a IA clona voz e escreve e-mail sem erro."

---

## 10. Fechamento (30 segundos)

TELA: um slide com os números principais, ou o painel.

Texto:
"Pra fechar: a infraestrutura continua operando sem internet e sem perder dado, o
ataque do incidente foi corrigido na causa raiz, e tudo roda com software livre e
baixo custo, cerca de dois mil e quatrocentos reais por ano. Os dados pessoais são
pseudonimizados pela LGPD e o painel é acessível. Cada controle que eu mostrei
responde a uma falha do incidente INC-VA-0712. Obrigado."

---

## Sobre o uso de IA (se o professor pedir pra comentar no vídeo)

"Usei IA de duas formas. Como ferramenta defensiva do projeto, o Isolation Forest. E
como apoio pra escrever a documentação e montar o código base, que eu revisei, rodei
e testei. Respondo por todo o conteúdo, e é por isso que consigo explicar qualquer
parte."
