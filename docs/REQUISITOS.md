# Mapeamento dos requisitos

Onde cada requisito do enunciado está atendido. Use como checklist antes de entregar.

| ID | Requisito | Onde | Status |
|---|---|---|---|
| RT-01 | Arquitetura em camadas, borda autônoma | `docker-compose.yml`, `borda/` | feito |
| RT-02 | Operação local + store-and-forward | `borda/agente.py` (buffer SQLite, reconciliação) | feito |
| RT-03 | Redundância proporcional (4G na UBS) | `borda/agente.py` troca endpoint, `docker-compose.yml` rede `wan_4g` | feito |
| RT-04 | Certificado X.509 por dispositivo + mTLS | `pki/`, `borda/mosquitto.conf.tpl` | feito |
| RT-05 | Revogação e rotação | `pki/revogar.sh`, `pki/rotacionar.sh` | feito |
| RT-06 | VPN moderna, admin só por VPN, nada exposto | `vpn/`, `nuvem/gw/` | feito |
| RT-07 | Segmentação com menor privilégio | redes `internal` + firewall `nuvem/gw/entrypoint.sh` | feito |
| RT-08 | SQLi corrigido, antes/depois | `nuvem/painel_legado/` vs `nuvem/painel/`, WAF | feito |
| RT-09 | MFA + RBAC (4 perfis) | `nuvem/painel/app.py` (TOTP, `@requer`) | feito |
| RT-10 | SPF, DKIM, DMARC | `phishing/gerar_dns.sh`, `verificar_dns.py` | feito |
| RT-11 | Phishing simulado + métricas + conscientização | `phishing/README.md` (montar no Gophish) | parcial, rodar você |
| RT-12 | Logs centralizados, NTP, SIEM | `logs/` em JSON, UTC, `siem/` (Wazuh) | feito |
| RT-13 | 4 regras de detecção | `soc/detector.py`, `siem/vila_aurora_rules.xml` | feito |
| RT-14 | Forense: hash, custódia, linha do tempo, ATT&CK | `forense/` | feito |
| RT-15 | Resposta de baixo risco auto + alto impacto aprovado | `soc/responder.py` | feito |
| RT-16 | IA defensiva com métricas | `ia/anomalias.py`, `ia/resultados/` | feito |
| RT-17 | Guardrails de LLM | não se aplica (sem LLM; justificado no relatório) | N/A |
| RT-18 | Ameaças por IA + controles | `phishing/README.md`, relatório | feito |
| RT-19 | Privacidade/LGPD, pseudonimização, dados sintéticos | `borda/agente.py` (HMAC), `nuvem/db/` | feito |
| RT-20 | Custos + plano de manutenção | `docs/RELATORIO_TECNICO.md` E1 | preencher |
| RT-21 | Painel acessível (WCAG AA) | `nuvem/painel/static/`, templates | feito |
| RT-22 | Métricas | `metricas/medir.py` | feito |
| RT-23 | Teste de caos ≥ 30 min | `caos/teste_caos.sh` | feito |

Diferenciais atendidos: modelagem de ameaças STRIDE (relatório), infra como código
(docker-compose versionado), PKI própria. Faltam, se quiser mais pontos: firmware assinado
(OTA), hardware real (ESP32), captura de memória com Volatility.

## O que falta você fazer

1. Rodar a campanha de phishing no Gophish e anotar as métricas (RT-11).
2. Preencher custos e plano de manutenção (RT-20) no relatório.
3. Rodar o teste de caos de verdade e colar as métricas e prints.
4. Reproduzir o incidente, coletar evidências e gerar a linha do tempo real (E4).
5. Gravar o vídeo (roteiro no guia de estudo).
6. Revisar o relatório, trocar os `[ ]` pelos seus números.
