# consulta o DNS do lab e confere se SPF, DKIM e DMARC estao certos (RT-10)
# uso: python3 phishing/verificar_dns.py [servidor] [porta]
# padrao: 127.0.0.1 1053 (CoreDNS do perfil phishing)
import sys

import dns.resolver

SERV = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORTA = int(sys.argv[2]) if len(sys.argv) > 2 else 1053
DOM = "vilaaurora.lab"

r = dns.resolver.Resolver(configure=False)
r.nameservers = [SERV]
r.port = PORTA


def txt(nome):
    try:
        return ["".join(p.decode() for p in x.strings) for x in r.resolve(nome, "TXT")]
    except Exception as e:
        return [f"ERRO: {e}"]


ok = True
spf = [t for t in txt(DOM) if t.startswith("v=spf1")]
print("SPF  :", spf)
if not spf or not spf[0].endswith("-all"):
    print("  !! SPF ausente ou sem -all")
    ok = False

dkim = txt(f"lab2026._domainkey.{DOM}")
print("DKIM :", [d[:60] + "..." for d in dkim])
if not dkim or "p=" not in dkim[0]:
    print("  !! DKIM sem chave publica")
    ok = False

dmarc = txt(f"_dmarc.{DOM}")
print("DMARC:", dmarc)
if not dmarc or not any(p in dmarc[0] for p in ("p=quarantine", "p=reject")):
    print("  !! DMARC precisa ser no minimo quarantine")
    ok = False

print("\nresultado:", "OK, os tres registros estao corretos" if ok else "tem problema")
