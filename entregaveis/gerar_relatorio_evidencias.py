# gera um relatorio de evidencias unico e organizado (HTML) a partir de tudo que foi capturado
# em entregaveis/evidencias/. abre no navegador, da pra imprimir pra PDF ou printar limpo.
# uso: python3 entregaveis/gerar_relatorio_evidencias.py
import base64
import glob
import html
import os
from datetime import datetime

RAIZ = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVID = os.path.join(RAIZ, "entregaveis", "evidencias")
SAIDA = os.path.join(RAIZ, "entregaveis", "relatorio_evidencias.html")

# titulo, criterio e pontos de cada pasta
SECOES = {
    "C2_identidade_vpn": ("Identidade, VPN e segmentacao", "C2", "1,5"),
    "C3_sql_injection": ("SQL Injection: antes e depois", "C3", "1,5"),
    "C5_deteccao_resposta": ("Deteccao e resposta automatizada", "C5", "1,5"),
    "E4_forense": ("Laudo forense do INC-VA-0712", "E4 / C5", "-"),
    "C6_ia": ("IA defensiva: deteccao de anomalias", "C6", "1,0"),
    "C7_metricas": ("Metricas e continuidade", "C7", "0,5"),
}
ORDEM = ["C2_identidade_vpn", "C3_sql_injection", "C5_deteccao_resposta", "E4_forense", "C6_ia", "C7_metricas"]


def img64(caminho):
    with open(caminho, "rb") as f:
        return "data:image/png;base64," + base64.b64encode(f.read()).decode()


def bloco_arquivo(caminho):
    nome = os.path.basename(caminho)
    if nome.endswith(".png"):
        return f'<figure><img src="{img64(caminho)}" alt="{html.escape(nome)}"><figcaption>{html.escape(nome)}</figcaption></figure>'
    if nome.endswith((".txt", ".md", ".csv")):
        try:
            txt = open(caminho, errors="replace").read()[:20000]
        except OSError:
            return ""
        return f'<h4>{html.escape(nome)}</h4><pre>{html.escape(txt)}</pre>'
    return ""


def main():
    partes = [f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<title>Relatorio de Evidencias - Rede Vila Aurora</title>
<style>
 body{{font-family:Arial,Helvetica,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;line-height:1.5}}
 h1{{border-bottom:3px solid #0b4f8a;padding-bottom:.3rem}}
 h2{{background:#0b4f8a;color:#fff;padding:.5rem .8rem;margin-top:2.5rem;border-radius:4px}}
 h4{{margin:1.2rem 0 .3rem;color:#0b4f8a}}
 pre{{background:#f4f4f0;border:1px solid #ccc;padding:.8rem;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}}
 .tag{{font-size:.8rem;background:#e6f1fb;color:#0c447c;padding:.1rem .5rem;border-radius:10px;margin-left:.5rem}}
 figure{{margin:1rem 0}} img{{max-width:100%;border:1px solid #ccc}} figcaption{{font-size:12px;color:#555}}
 .cap{{color:#555;font-size:.9rem}}
</style></head><body>
<h1>Relatorio de Evidencias &middot; Rede Comunitaria Vila Aurora</h1>
<p class="cap">Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M')} a partir das capturas em entregaveis/evidencias/.
Ambiente de laboratorio, dados sinteticos. Cada secao corresponde a um criterio da rubrica.</p>"""]

    pastas = ORDEM + [os.path.basename(p) for p in sorted(glob.glob(os.path.join(EVID, "*")))
                      if os.path.basename(p) not in ORDEM]
    vistos = set()
    for pasta in pastas:
        if pasta in vistos:
            continue
        vistos.add(pasta)
        caminho = os.path.join(EVID, pasta)
        if not os.path.isdir(caminho):
            continue
        titulo, criterio, pontos = SECOES.get(pasta, (pasta, "-", "-"))
        partes.append(f'<h2>{html.escape(titulo)} <span class="tag">{criterio} &middot; {pontos} pt</span></h2>')
        arquivos = sorted(glob.glob(os.path.join(caminho, "*")))
        # mostra .md e .txt primeiro, depois imagens, ignora subpastas
        arquivos = [a for a in arquivos if os.path.isfile(a)]
        for a in arquivos:
            b = bloco_arquivo(a)
            if b:
                partes.append(b)

    partes.append("</body></html>")
    with open(SAIDA, "w") as f:
        f.write("\n".join(partes))
    print(f"relatorio gerado: {SAIDA}")
    print("abra no navegador. pra virar PDF: Ctrl+P -> Salvar como PDF.")


if __name__ == "__main__":
    main()
