# IA de triagem com guardrails (C6 / RT-16, RT-17)

Uso defensivo de IA #2 do projeto (o #1 e o Isolation Forest da telemetria).
Aqui um LLM local faz **triagem de alertas do SOC**: le um alerta e devolve uma
classificacao estruturada (categoria, severidade, acao sugerida). O LLM **nunca
executa nada** e **nunca aciona atuador fisico**; quem age sao as regras e os
humanos. Em volta dele tem uma camada de guardrails que garante seguranca mesmo
que o modelo caia numa injecao.

## Como rodar

Opcao A, com LLM real (Ollama local, recomendado):

```
# instala o ollama (uma vez)
curl -fsSL https://ollama.com/install.sh | sh
# baixa um modelo pequeno (~400 MB)
ollama pull qwen2.5:0.5b
# roda a triagem
cd ~/vila-aurora-gs
python3 ia_triagem/triagem.py
# ataca o proprio LLM com prompt injection e mede o resultado
python3 ia_triagem/testar_prompt_injection.py
```

Opcao B, sem instalar nada (modo mock, simula um modelo ingenuo que OBEDECE a
injecao, pra provar que o guardrail segura mesmo assim):

```
python3 ia_triagem/testar_prompt_injection.py --mock
```

A saida do teste e salva em `entregaveis/evidencias/C6_ia/prompt_injection.txt`.

## Os guardrails (defesa em profundidade)

1. **Entrada como dado, nunca ordem**: o alerta entra cercado por delimitadores e
   o sistema manda ignorar qualquer instrucao dentro dele. `detectar_injection`
   ainda registra a tentativa.
2. **Saida em formato fechado**: o modelo so pode responder um JSON; `validar_saida`
   descarta qualquer coisa fora do schema.
3. **Lista fechada de acoes**: a acao sugerida tem que estar em
   {monitorar, abrir_chamado, bloquear_ip, isolar_sensor, escalar_humano}. Nao
   existe acao que mexa em atuador. Se o modelo inventa, vira `escalar_humano`.
4. **Sem agencia fisica**: o LLM nao tem como desligar bomba ou liberar porta.
   Qualquer coisa de alto impacto e sempre decisao humana (RT-15, RT-17).
5. **Anti-vazamento**: um token isca (canary) fica so no contexto do sistema. Se
   ele aparecer na saida, a resposta e bloqueada.

O ponto principal: a seguranca **nao depende do modelo acertar**. O guardrail e
deterministico, entao a acao final e sempre segura, de qualquer LLM.

## Mapeamento OWASP Top 10 para LLM

| Risco OWASP LLM | Como o projeto trata |
|---|---|
| LLM01 Prompt Injection | entrada cercada e tratada como dado, deteccao de padroes, e saida num schema fechado que nao obedece comando |
| LLM02 Sensitive Information Disclosure | sem segredo no prompt util; token isca; varredura da saida contra vazamento |
| LLM05 Improper Output Handling | saida validada contra schema e lista de acoes antes de qualquer uso |
| LLM06 Excessive Agency | LLM sem acesso a atuador; acao de alto impacto sempre escala pra humano |
| LLM04 Model Denial of Service | tamanho da entrada limitado em `sanitizar_entrada` |

## Mapeamento MITRE ATLAS

| Tecnica ATLAS | Defesa |
|---|---|
| AML.T0051 LLM Prompt Injection | guardrails de entrada e saida |
| AML.T0054 LLM Jailbreak | deteccao de troca de papel + lista fechada de acoes |
| AML.T0057 LLM Data Leakage | token isca e varredura da saida |

## Resultado do teste

8 tentativas de prompt injection (diretas, indiretas e de exfiltracao): todas
neutralizadas. As perigosas (aprovar acao fisica, vazar segredo, trocar de papel)
viram `escalar_humano`; nenhuma chega a executar nada. Alertas legitimos continuam
sendo classificados normalmente, entao o guardrail protege sem quebrar o uso real.
