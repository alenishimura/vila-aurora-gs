# Vila Aurora

Global Solution 2026.2 de Cybersecurity (FIAP). Infraestrutura em camadas para monitorar energia, água, acesso e condições ambientais dos espaços comunitários, que continua operando quando a internet cai e registra os logs para investigar incidentes (caso INC-VA-0712). É um laboratório com dados sintéticos; os ataques só rodam contra os próprios containers.

## Rodar

Linux ou WSL2 com Docker e Docker Compose.

```bash
./setup.sh              # gera segredos, certificados, dados sintéticos e chaves da VPN
docker compose up -d    # sobe campo, borda, nuvem e painel
```

Painel em https://localhost:8443 (usuários e códigos TOTP em `segredos/operadores.txt`, gerado pelo setup).

Reproduzir o incidente, testar e medir:

```bash
docker compose --profile incidente up -d          # painel legado vulnerável (SQLi)
./incidente/reproduzir.sh                          # phishing, SQLi, dump e sabotagem da bomba
./forense/coletar.sh INC-VA-0712-LAB "Seu Nome"    # evidências com hash e cadeia de custódia
python3 soc/detector.py                            # 4 regras de detecção
python3 ia_triagem/testar_prompt_injection.py      # ataca o LLM e mostra os guardrails
./caos/teste_caos.sh 31                            # teste de caos (derruba a WAN)
python3 metricas/medir.py                          # métricas
```

## Segredos

Gerados pelo `setup.sh` e no `.gitignore`. Fora do repositório: `.env`, `pki/ca/`, `pki/emitidos/`, `vpn/gerado/` e `segredos/`.
