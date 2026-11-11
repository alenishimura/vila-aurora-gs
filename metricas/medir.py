# coleta as metricas do RT-22 a partir dos logs e do estado dos containers
# disponibilidade, MTTD, MTTR, tempo de operacao autonoma, perda na reconciliacao,
# e consumo de CPU/memoria/banda do no de borda.
#
# uso: python3 metricas/medir.py            -> le logs/ e imprime + salva metricas/metricas.json
#      python3 metricas/medir.py --pasta evidencias/.../logs
import argparse
import glob
import json
import os
import statistics
import subprocess
from datetime import datetime, timezone

RAIZ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def parse_ts(s):
    if not s:
        return None
    s = str(s).replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(s)
        return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except ValueError:
        return None


def ler_json(pasta, *nomes):
    linhas = []
    for nome in nomes:
        for arq in glob.glob(os.path.join(pasta, nome)):
            try:
                fh = open(arq, errors="replace")
            except (PermissionError, OSError):
                continue
            with fh:
                for l in fh:
                    l = l.strip()
                    if l.startswith("{"):
                        try:
                            linhas.append(json.loads(l))
                        except ValueError:
                            pass
    return linhas


def disponibilidade(eventos):
    # disponibilidade do canal com a nuvem = 1 - (tempo em que a borda ficou sem link / tempo total)
    por_borda = {}
    for e in eventos:
        if e.get("evento") in ("link_wan_caiu", "link_restabelecido", "agente_iniciado"):
            por_borda.setdefault(e.get("servico"), []).append(e)
    res = {}
    for borda, evs in por_borda.items():
        evs.sort(key=lambda x: x.get("ts", ""))
        ts = [parse_ts(e["ts"]) for e in evs if parse_ts(e.get("ts"))]
        if len(ts) < 2:
            continue
        total = (ts[-1] - ts[0]).total_seconds()
        caiu_em, offline = None, 0.0
        quedas = 0
        for e in evs:
            t = parse_ts(e.get("ts"))
            if e["evento"] == "link_wan_caiu":
                caiu_em = t
                quedas += 1
            elif e["evento"] == "link_restabelecido" and caiu_em:
                offline += (t - caiu_em).total_seconds()
                caiu_em = None
        if caiu_em:
            offline += (ts[-1] - caiu_em).total_seconds()
        disp = 100 * (1 - offline / total) if total else 100
        res[borda] = {"janela_seg": round(total, 1), "offline_seg": round(offline, 1),
                      "quedas": quedas, "disponibilidade_pct": round(disp, 3)}
    return res


def mttd_mttr(alertas, respostas):
    # MTTD = tempo entre o evento acontecer e o detector alertar
    ds = [a["mttd_seg"] for a in alertas if a.get("evento") == "alerta" and a.get("mttd_seg") is not None]
    # MTTR = tempo entre o alerta e a resposta automatizada
    rs = [r["mttr_seg"] for r in respostas if r.get("evento") == "resposta" and r.get("mttr_seg") is not None]
    def resumo(xs):
        if not xs:
            return None
        return {"n": len(xs), "media_seg": round(statistics.mean(xs), 3),
                "mediana_seg": round(statistics.median(xs), 3), "max_seg": round(max(xs), 3)}
    return resumo(ds), resumo(rs)


def operacao_autonoma(eventos):
    # maior intervalo seguido que uma borda ficou sem internet e continuou operando
    maior = 0
    detalhe = None
    caiu = {}
    for e in sorted(eventos, key=lambda x: x.get("ts", "")):
        b = e.get("servico")
        if e.get("evento") == "link_wan_caiu":
            caiu[b] = parse_ts(e["ts"])
        elif e.get("evento") == "link_restabelecido" and caiu.get(b):
            dur = (parse_ts(e["ts"]) - caiu[b]).total_seconds()
            if dur > maior:
                maior, detalhe = dur, {"borda": b, "offline_seg": round(dur, 1),
                                       "pendentes_no_buffer": e.get("pendentes_no_buffer")}
            caiu[b] = None
    return maior, detalhe


def reconciliacao(coletor, eventos):
    # perda de dados = mensagens que a borda enviou mas nunca chegaram ao banco
    enviados = sum(e.get("qtd", 0) for e in eventos if e.get("evento") == "lote_enviado")
    novos = sum(c.get("novos", 0) for c in coletor if c.get("evento") == "lote_recebido")
    dup = sum(c.get("duplicados", 0) for c in coletor if c.get("evento") == "lote_recebido")
    return {"enviados_pela_borda": enviados, "gravados_no_banco": novos, "duplicados_descartados": dup,
            "perda_estimada": max(0, enviados - novos - dup)}


def recursos(eventos):
    cpu = [e["proc_cpu_pct"] for e in eventos if e.get("evento") == "metricas_borda" and "proc_cpu_pct" in e]
    mem = [e["mem_mb"] for e in eventos if e.get("evento") == "metricas_borda" and "mem_mb" in e]
    byt = [e["bytes_enviados"] for e in eventos if e.get("evento") == "metricas_borda" and "bytes_enviados" in e]
    r = {}
    if cpu:
        r["cpu_proc_pct"] = {"media": round(statistics.mean(cpu), 2), "max": round(max(cpu), 2)}
    if mem:
        r["memoria_mb"] = {"media": round(statistics.mean(mem), 1), "max": round(max(mem), 1)}
    if byt and len(byt) > 1:
        # banda media = bytes acumulados / janela de tempo
        r["banda_total_kb"] = round(max(byt) / 1024, 1)
    return r


def consumo_docker():
    try:
        out = subprocess.run(["docker", "stats", "--no-stream", "--format",
                              "{{.Name}};{{.CPUPerc}};{{.MemUsage}}"], capture_output=True, text=True, timeout=15).stdout
        linhas = [l for l in out.splitlines() if l.startswith("borda")]
        return linhas
    except Exception:
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pasta", default=os.path.join(RAIZ, "logs"))
    a = ap.parse_args()
    p = a.pasta

    borda = ler_json(p, "borda-*.log")
    coletor = ler_json(p, "coletor.log")
    alertas = ler_json(p, "alertas.log")
    respostas = ler_json(p, "respostas.log")

    mttd, mttr = mttd_mttr(alertas, respostas)
    aut, aut_det = operacao_autonoma(borda)
    r = {
        "gerado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "disponibilidade": disponibilidade(borda),
        "MTTD": mttd,
        "MTTR": mttr,
        "operacao_autonoma_sem_internet": {"maior_intervalo_seg": round(aut, 1), **(aut_det or {})},
        "reconciliacao": reconciliacao(coletor, borda),
        "recursos_borda": recursos(borda),
        "consumo_docker_agora": consumo_docker(),
    }
    os.makedirs(os.path.join(RAIZ, "metricas"), exist_ok=True)
    with open(os.path.join(RAIZ, "metricas", "metricas.json"), "w") as f:
        json.dump(r, f, indent=2, ensure_ascii=False)
    print(json.dumps(r, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
