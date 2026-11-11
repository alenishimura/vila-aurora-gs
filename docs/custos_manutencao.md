# Custos e plano de manutenção (RT-20)

Estimativa para a Rede Comunitária Vila Aurora, cinco espaços (Centro, Escola, UBS,
Horta e Abrigo). Valores em reais, de referência para 2026, pensados para orçamento de
associação de moradores. São estimativas para a equipe ajustar com cotação real.

## Implantação (custo único)

| Item | Qtd | Unitário | Total | Observação |
|---|---|---|---|---|
| Nó de borda (Raspberry Pi 4 4GB + cartão + fonte + gabinete) | 5 | R$ 750 | R$ 3.750 | um por espaço |
| Sensores de nível, turbidez e cloro (água) | 3 | R$ 300 | R$ 900 | escola, horta, abrigo |
| Sensor de temperatura da câmara fria (grau médico) | 1 | R$ 450 | R$ 450 | UBS, vacinas |
| Medição de energia (painel, bateria, consumo) | 5 | R$ 200 | R$ 1.000 | um por espaço |
| Fechadura eletrônica com leitor RFID/QR | 5 | R$ 350 | R$ 1.750 | controle de acesso |
| Microcontroladores dos sensores (ESP32) e cabos | 20 | R$ 60 | R$ 1.200 | campo |
| Modem 4G + antena (redundância da UBS) | 1 | R$ 350 | R$ 350 | só na UBS |
| Mão de obra de instalação (voluntária) | - | - | R$ 0 | feita pela equipe |
| **Total de implantação** | | | **R$ 9.400** | |

A energia (painéis solares, baterias e gerador) já existe nos espaços e não entra aqui.

## Operação por 12 meses (custo recorrente)

| Item | Mensal | Anual | Observação |
|---|---|---|---|
| Servidor em nuvem (VM pequena: coletor, painel, banco, SIEM) | R$ 120 | R$ 1.440 | 2 vCPU, 4 GB; ou doado |
| Plano de dados 4G da UBS | R$ 50 | R$ 600 | só backup, uso baixo |
| Domínio do projeto (.org.br) | - | R$ 40 | renovação anual |
| Certificados TLS (CA própria do projeto) | R$ 0 | R$ 0 | emitidos pela própria PKI |
| Backup externo (armazenamento) | R$ 15 | R$ 180 | nuvem ou HD rotativo |
| Energia dos nós de borda | R$ 10 | R$ 120 | consumo baixo, ~5 W cada |
| **Total de operação (12 meses)** | | **R$ 2.380** | |

**Custo total do primeiro ano: cerca de R$ 11.780.** A partir do segundo ano, só a
operação (~R$ 2.380/ano). O uso da CA própria e de software livre (Mosquitto, PostgreSQL,
Wazuh, WireGuard) mantém o custo recorrente baixo, sem licenças.

## Plano de manutenção

| Tarefa | Frequência | Responsável | Como |
|---|---|---|---|
| Atualizar sistema e pacotes dos nós de borda | Mensal | Voluntário de TI | `apt upgrade` e reinício programado |
| Atualizar firmware dos sensores (OTA assinado) | Trimestral ou sob demanda | Voluntário de TI | pacote assinado, só instala se a assinatura confere |
| Renovar certificados dos dispositivos | A cada 180 dias | Voluntário de TI | `pki/rotacionar.sh`, automatizável por cron |
| Renovar certificados dos servidores | Anual | Voluntário de TI | `pki/rotacionar.sh` |
| Publicar a CRL após revogar um dispositivo | Sob demanda | Voluntário de TI | `pki/revogar.sh`, reinicia broker e gateway |
| Backup do banco de dados | Diário | Automático + Coordenação confere | `pg_dump` para armazenamento externo |
| Backup das configurações e chaves | Semanal | Voluntário de TI | cópia cifrada fora do servidor |
| Revisar alertas do SIEM | Semanal | Coordenação + Voluntário de TI | painel do Wazuh |
| Testar a restauração do backup | Trimestral | Voluntário de TI | restaura num ambiente de teste |
| Teste de caos (derrubar a WAN) | Semestral | Voluntário de TI | `caos/teste_caos.sh` |
| Revisar contas e perfis do painel | Semestral | Coordenação | remover quem saiu, conferir perfis |

## Responsáveis

- **Coordenação da associação**: aprova ações de alto impacto no painel, confere backups,
  revisa acessos e conduz a conscientização dos voluntários.
- **Voluntário de TI** (uma ou duas pessoas): cuida da infraestrutura, certificados,
  atualizações e backups. É o ponto de contato técnico.
- **Operadores voluntários**: usam o painel no dia a dia, reconhecem alertas e acionam a
  coordenação quando algo foge do normal.

O desenho prioriza baixo custo de manutenção: software livre, automação dos certificados e
dos backups, e tarefas simples o suficiente para um voluntário sem formação técnica
avançada seguir um roteiro.
