# IA defensiva (RT-16): deteccao de anomalia na telemetria da camara fria e da caixa d'agua
# com Isolation Forest. A ideia e pegar coisa que regra fixa nao pega, tipo:
#  - sensor "travado" mandando sempre o mesmo valor (pode ser falha ou alguem falsificando leitura)
#  - subida lenta de temperatura que ainda esta dentro da faixa
#  - queda de nivel rapida demais (vazamento ou bomba manipulada)
#
# uso:
#   python3 ia/anomalias.py                       -> gera dados sinteticos rotulados e avalia
#   python3 ia/anomalias.py --csv telemetria.csv  -> roda em cima de dados exportados do banco
#
# os dados sinteticos tem rotulo (sabemos onde injetamos a anomalia), entao da pra medir
# precisao, revocacao e taxa de falso positivo de verdade.
import argparse
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

AQUI = os.path.dirname(os.path.abspath(__file__))
SAIDA = os.path.join(AQUI, "resultados")
rng = np.random.default_rng(42)


def gerar_camara(dias=14):
    n = dias * 24 * 60   # uma leitura por minuto
    t = np.arange(n)
    temp = 4.5 + 0.3 * np.sin(2 * np.pi * t / (24 * 60)) + rng.normal(0, 0.12, n)
    # o compressor liga e desliga, da um serrilhado leve
    temp += 0.15 * np.sign(np.sin(2 * np.pi * t / 37))
    rot = np.zeros(n, dtype=int)
    tipo = np.array([""] * n, dtype=object)

    def marca(ini, fim, nome):
        rot[ini:fim] = 1
        tipo[ini:fim] = nome

    # 1) porta aberta: sobe rapido e volta
    for ini in rng.choice(np.arange(500, n - 200), 6, replace=False):
        dur = rng.integers(20, 50)
        temp[ini:ini + dur] += np.linspace(0, rng.uniform(3, 6), dur)
        marca(ini, ini + dur, "porta_aberta")
    # 2) sensor travado / leitura falsificada: valor constante
    for ini in rng.choice(np.arange(500, n - 200), 4, replace=False):
        dur = rng.integers(40, 90)
        temp[ini:ini + dur] = round(float(temp[ini]), 2)
        marca(ini, ini + dur, "sensor_travado")
    # 3) falha lenta do compressor: deriva dentro da faixa (regra 2-8 C nao pega no comeco)
    for ini in rng.choice(np.arange(500, n - 400), 3, replace=False):
        dur = rng.integers(150, 300)
        temp[ini:ini + dur] += np.linspace(0, 2.8, dur)
        marca(ini, ini + dur, "deriva_lenta")
    return pd.DataFrame({"t": t, "valor": temp, "anomalia": rot, "tipo": tipo, "sensor": "camara_fria"})


def gerar_nivel(dias=14):
    n = dias * 24 * 60
    nivel = np.zeros(n)
    nivel[0] = 70
    bomba = False
    rot = np.zeros(n, dtype=int)
    tipo = np.array([""] * n, dtype=object)
    consumo_extra = np.zeros(n)
    bomba_bloqueada = np.zeros(n, dtype=bool)
    # vazamento: consumo bem maior por um tempo
    for ini in rng.choice(np.arange(500, n - 300), 4, replace=False):
        dur = rng.integers(40, 120)
        consumo_extra[ini:ini + dur] = 0.6
        rot[ini:ini + dur], tipo[ini:ini + dur] = 1, "vazamento"
    # agenda adulterada (como no INC-VA-0712): a bomba nao liga
    for ini in rng.choice(np.arange(500, n - 600), 4, replace=False):
        bomba_bloqueada[ini:ini + rng.integers(300, 500)] = True
    for i in range(1, n):
        h = (i // 60) % 24
        consumo = (0.30 if 7 <= h <= 17 else 0.10) + rng.normal(0, 0.02) + consumo_extra[i]
        if nivel[i - 1] < 40 and not bomba_bloqueada[i]:
            bomba = True
        if nivel[i - 1] > 90 or bomba_bloqueada[i]:
            bomba = False
        nivel[i] = np.clip(nivel[i - 1] - consumo + (0.9 if bomba else 0), 0, 100)
        # so da pra "ver" a agenda adulterada quando a caixa passa do ponto em que a bomba deveria ligar
        if bomba_bloqueada[i] and nivel[i] < 39 and not rot[i]:
            rot[i], tipo[i] = 1, "bomba_bloqueada"
    # janela do incidente = do inicio do bloqueio ate a caixa encher de novo (o efeito ainda e do ataque)
    i = 0
    while i < n:
        if bomba_bloqueada[i] and (i == 0 or not bomba_bloqueada[i - 1]):
            fim = i
            while fim < n and bomba_bloqueada[fim]:
                fim += 1
            if rot[i:fim].any():
                while fim < n and nivel[fim] < 88:
                    fim += 1
                rot[i:fim], tipo[i:fim] = 1, "bomba_bloqueada"
            i = fim
        i += 1
    nivel += rng.normal(0, 0.05, n)
    return pd.DataFrame({"t": np.arange(n), "valor": nivel, "anomalia": rot, "tipo": tipo, "sensor": "nivel"})


def features(df):
    # janela de 10 min: media, desvio, inclinacao e quanto mudou desde a ultima leitura
    v = df["valor"]
    f = pd.DataFrame({
        "valor": v,
        "delta": v.diff().fillna(0),
        "media10": v.rolling(10, min_periods=1).mean(),
        "desvio10": v.rolling(10, min_periods=2).std().fillna(0),
        # quantas leituras iguais seguidas (sensor travado manda sempre o mesmo numero)
        "repetidas": v.diff().eq(0).astype(int).rolling(10, min_periods=1).sum(),
        "incl30": (v - v.shift(30)).fillna(0) / 30,
        "incl120": (v - v.shift(120)).fillna(0) / 120,
        "hora": (df["t"] // 60) % 24,
    })
    return f


def modelos(contaminacao):
    return {
        "isolation_forest": IsolationForest(n_estimators=200, contamination=contaminacao, random_state=7),
        # LOF precisa das features na mesma escala, por isso o StandardScaler
        "lof": make_pipeline(StandardScaler(), LocalOutlierFactor(n_neighbors=35, novelty=True,
                                                                  contamination=contaminacao)),
    }


def metricas(df, pred, teste):
    y, p = df["anomalia"].values[teste], pred[teste]
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    r = {
        "precisao": round(float(precision_score(y, p, zero_division=0)), 3),
        "revocacao": round(float(recall_score(y, p, zero_division=0)), 3),
        "f1": round(float(f1_score(y, p, zero_division=0)), 3),
        "taxa_falso_positivo": round(float(fp / (fp + tn)), 4) if (fp + tn) else 0,
        "vp": int(tp), "fp": int(fp), "fn": int(fn), "vn": int(tn),
    }
    dft = df.iloc[teste].assign(pred=p)
    r["revocacao_por_tipo"] = {t: round(float(g["pred"].mean()), 3)
                               for t, g in dft[dft["anomalia"] == 1].groupby("tipo")}
    return r


def suavizar(pred):
    # so conta anomalia se 3 de 5 leituras seguidas forem anomalas (reduz alarme falso)
    return (pd.Series(pred).rolling(5, center=True, min_periods=1).sum() >= 3).astype(int).values


def avaliar(df, nome, contaminacao):
    X = features(df)
    corte = int(len(df) * 0.4)
    # treina com os primeiros dias, tirando os trechos que a equipe ja sabe que foram problema
    # (na vida real seria um periodo que o tecnico validou como "normal").
    # as features usam janela de ate 120 min, entao tambem tiro os 150 min depois de cada problema
    sujo = df["anomalia"].rolling(150, min_periods=1).max().iloc[:corte]
    treino = X.iloc[:corte][sujo == 0]
    teste = slice(corte, None)

    res = {"sensor": nome, "leituras_teste": int(len(df) - corte),
           "anomalias_reais": int(df["anomalia"].values[teste].sum()), "modelos": {}}
    preds = {}
    for nome_m, m in modelos(contaminacao).items():
        m.fit(treino)
        preds[nome_m] = suavizar((m.predict(X) == -1).astype(int))
        res["modelos"][nome_m] = metricas(df, preds[nome_m], teste)

    # hibrido: Isolation Forest + uma regra simples de "sensor travado" (leitura identica 8 de 10 vezes).
    # o IF nao consegue pegar isso porque no treino essa feature e sempre zero (ver relatorio)
    travado = (X["repetidas"] >= 8).astype(int).values
    preds["hibrido_if_regra"] = np.maximum(preds["isolation_forest"], travado)
    res["modelos"]["hibrido_if_regra"] = metricas(df, preds["hibrido_if_regra"], teste)

    melhor = max(res["modelos"], key=lambda k: res["modelos"][k]["f1"])
    res["melhor_modelo"] = melhor
    grafico(df, preds[melhor], corte, nome, melhor)
    return res


def grafico(df, pred, corte, nome, modelo):
    fig, ax = plt.subplots(figsize=(13, 4))
    janela = df.iloc[corte:corte + 2 * 24 * 60]
    pj = pred[corte:corte + 2 * 24 * 60]
    ax.plot(janela["t"] / 60, janela["valor"], lw=0.8, color="#333", label="leitura")
    ax.fill_between(janela["t"] / 60, janela["valor"].min(), janela["valor"].max(), where=janela["anomalia"] == 1,
                    color="#f4a261", alpha=0.35, label="anomalia real (injetada)")
    ax.scatter(janela["t"][pj == 1] / 60, janela["valor"][pj == 1], s=6, color="#c1121f", label="detectado")
    ax.set_xlabel("horas")
    ax.set_ylabel("°C" if nome == "camara_fria" else "% da caixa")
    ax.set_title(f"{modelo} - {nome} (2 dias do conjunto de teste)")
    ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(SAIDA, f"grafico_{nome}.png"), dpi=120)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="csv exportado com colunas t,valor (sem rotulo so mostra as deteccoes)")
    a = ap.parse_args()
    os.makedirs(SAIDA, exist_ok=True)

    if a.csv:
        df = pd.read_csv(a.csv)
        df["anomalia"] = df.get("anomalia", 0)
        df["tipo"] = ""
        X = features(df)
        m = IsolationForest(n_estimators=200, contamination=0.02, random_state=7).fit(X)
        df["pred"] = (m.predict(X) == -1).astype(int)
        df.to_csv(os.path.join(SAIDA, "deteccoes.csv"), index=False)
        print(f"{df['pred'].sum()} leituras marcadas como anomalas de {len(df)}")
        return

    resultados = [avaliar(gerar_camara(), "camara_fria", 0.01), avaliar(gerar_nivel(), "nivel", 0.01)]
    with open(os.path.join(SAIDA, "metricas.json"), "w") as f:
        json.dump(resultados, f, indent=2, ensure_ascii=False)
    for r in resultados:
        print(f"\n== {r['sensor']} ({r['anomalias_reais']} leituras anomalas de {r['leituras_teste']}) ==")
        for nm, m in r["modelos"].items():
            print(f"  {nm:17} precisao={m['precisao']:.3f} revocacao={m['revocacao']:.3f} f1={m['f1']:.3f} "
                  f"FP={m['taxa_falso_positivo'] * 100:.2f}%  por tipo={m['revocacao_por_tipo']}")
    print(f"\ngraficos e metricas.json em {SAIDA}")


if __name__ == "__main__":
    main()
