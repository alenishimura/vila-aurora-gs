# guardrails da triagem por LLM (RT-17)
# ideia central: nao confiar no modelo. tudo que vem de fora e dado, nunca ordem.
# o LLM so classifica alerta, ele nunca executa nada e nunca escolhe uma acao
# fora da lista fechada abaixo. acao de alto impacto sempre vai pra humano.

import re

# lista fechada de acoes que a triagem pode sugerir. repare que nao existe
# "desligar_bomba" nem nada que mexa num atuador fisico: o LLM nao tem esse poder.
ACOES_PERMITIDAS = {
    "monitorar",
    "abrir_chamado",
    "bloquear_ip",
    "isolar_sensor",
    "escalar_humano",
}

# severidades aceitas
SEVERIDADES = {"baixa", "media", "alta"}

# token isca: fica so no contexto do sistema. se aparecer na saida, teve vazamento.
CANARY = "CANARY-7a1f-NAO-REVELAR"

# padroes classicos de prompt injection (direto e indireto) e de pedido de vazamento
PADROES_INJECTION = [
    r"ignore?\s+(as\s+)?(instru|previous|anterior)",
    r"desconsidere|disregard|esque[cç]a",
    r"voc[eê]\s+agora\s+[eé]|you\s+are\s+now|aja\s+como|pretenda\s+ser",
    r"sem\s+restri[cç][oõ]es|modo\s+desenvolvedor|jailbreak|DAN",
    r"\bsystem\b\s*:|\[\s*system\s*\]|<\s*system\s*>",
    r"revele|mostre.*(senha|chave|token|segredo|prompt|instru)",
    r"api[_\s-]?key|secret|password|credenc",
    r"desligar.*bomba|acione.*atuador|liberar.*portas",
    r"responda\s+apenas\s+(sim|aprovado|ok)",
]


def detectar_injection(texto):
    # varre o texto atras dos padroes acima. devolve a lista do que casou.
    achados = []
    baixo = texto.lower()
    for p in PADROES_INJECTION:
        if re.search(p, baixo):
            achados.append(p)
    return achados


def sanitizar_entrada(texto, limite=2000):
    # corta tamanho, tira caracteres de controle e marca o conteudo como dado.
    # nao reescreve o texto do atacante (a gente quer registrar o que ele tentou),
    # so garante que ele nao escape da cerca de delimitadores no prompt.
    texto = texto.replace("\x00", "")
    texto = re.sub(r"[`]{3,}", "'''", texto)  # evita fechar bloco de codigo do prompt
    if len(texto) > limite:
        texto = texto[:limite] + " [...cortado...]"
    return texto


def validar_saida(bruto):
    # recebe o texto cru do modelo e devolve uma decisao segura, sempre.
    # se o modelo fugiu do formato, inventou acao ou tentou vazar o canary,
    # a gente descarta a resposta dele e escala pra humano.
    motivos = []

    # 1) tem que ser um JSON com os campos certos
    import json
    obj = None
    try:
        # pega o primeiro bloco {...} que aparecer, modelo pequeno gosta de enrolar
        m = re.search(r"\{.*\}", bruto, re.DOTALL)
        obj = json.loads(m.group(0)) if m else None
    except Exception:
        obj = None
    if not isinstance(obj, dict):
        return _escalar("saida nao era JSON valido")

    acao = str(obj.get("acao", "")).strip().lower()
    sev = str(obj.get("severidade", "")).strip().lower()
    cat = str(obj.get("categoria", "")).strip()
    just = str(obj.get("justificativa", "")).strip()

    # 2) acao tem que estar na lista fechada
    if acao not in ACOES_PERMITIDAS:
        motivos.append(f"acao fora da lista: '{acao}'")
        acao = "escalar_humano"

    # 3) severidade valida
    if sev not in SEVERIDADES:
        sev = "media"

    # 4) o modelo nao pode ter repetido o canary (seria vazamento)
    if CANARY.lower() in bruto.lower():
        return _escalar("tentativa de vazar o token isca")

    # 5) justificativa nao pode conter pedido de acao fisica
    if re.search(r"desligar.*bomba|liberar.*portas|acione.*atuador", just.lower()):
        motivos.append("justificativa mencionava atuador fisico")
        acao = "escalar_humano"

    return {
        "categoria": cat or "indefinida",
        "severidade": sev,
        "acao": acao,
        "justificativa": just[:300],
        "guardrail_motivos": motivos,
    }


def _escalar(motivo):
    return {
        "categoria": "suspeita",
        "severidade": "alta",
        "acao": "escalar_humano",
        "justificativa": f"bloqueado pelo guardrail: {motivo}",
        "guardrail_motivos": [motivo],
    }
