# Scripts de captura de evidências

Cada script roda uma demonstração inteira e salva as evidências em
`entregaveis/evidencias/<criterio>/`. Rode de dentro da pasta do projeto,
com o laboratório no ar (`docker compose up -d`).

Ordem sugerida:

| Comando | O que faz | Critério |
|---|---|---|
| `./entregaveis/c2_identidade_vpn.sh` | certificados, revogação (CRL), VPN e segmentação | C2 (1,5) |
| `./entregaveis/c3_sqli.sh` | ataque de SQL injection no painel velho e defesa no novo | C3 (1,5) |
| `./entregaveis/c5_deteccao_resposta.sh` | detector das 4 regras + resposta automatizada | C5 (parte) |
| `./entregaveis/e4_forense.sh "Seu Nome"` | reproduz o incidente, coleta com hash, linha do tempo | E4 / C5 |
| `./entregaveis/c6_ia.sh` | Isolation Forest/LOF com métricas (já vem com resultado pronto) | C6 (1,0) |
| `./caos/teste_caos.sh 31` | derruba a WAN 31 min (rode antes do c7 pra métrica cheia) | C1/C7 |
| `./entregaveis/c7_metricas.sh` | disponibilidade, MTTD, MTTR, operação autônoma | C7 (0,5) |

No fim, gera o relatório de evidências organizado (HTML, abre no navegador,
dá pra imprimir pra PDF):

```
python3 entregaveis/gerar_relatorio_evidencias.py
```

Depois é só copiar a pasta `entregaveis/evidencias/` e o `relatorio_evidencias.html`
pra onde você está montando as entregas.

Falta fazer na mão (não dá pra automatizar): a campanha de phishing no Gophish
(C4), os custos e manutenção (C8, RT-20) e o vídeo.
