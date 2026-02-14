import streamlit as st
import requests
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import tldextract

# ------------------------------------------------
# CONFIG / UI
# ------------------------------------------------
st.set_page_config(page_title="Security Quick Check", page_icon="🛡️", layout="wide")

st.title("Security Quick Check")
st.write("Analisi basata esclusivamente su informazioni pubbliche (HTTP / DNS / SSL). Nessun test intrusivo.")
st.caption("Nota: verifica preliminare. Non sostituisce un assessment professionale completo.")

UA = {"User-Agent": "SecurityQuickCheck/1.0"}

# ------------------------------------------------
# HELPERS (PUBLIC / SAFE)
# ------------------------------------------------
def normalize_input(v: str) -> str:
    v = (v or "").strip().lower()
    v = v.replace("https://", "").replace("http://", "")
    return v.split("/")[0].strip()

def target_is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False

def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address((value or "").strip())
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False

def apex_domain(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname

def http_get(url: str, timeout=10):
    try:
        return requests.get(url, timeout=timeout, allow_redirects=True, headers=UA)
    except Exception:
        return None

def fetch_headers_https(host: str):
    r = requests.get(
        f"https://{host}",
        timeout=10,
        allow_redirects=True,
        headers=UA,
    )
    return r.url, r.status_code, r.headers

def check_redirect_http_to_https(host: str):
    """
    Best-effort: prova HTTP e vede se finisce su HTTPS.
    """
    try:
        r = requests.get(f"http://{host}", timeout=10, allow_redirects=True, headers=UA)
        final = r.url or ""
        return True, final.lower().startswith("https://"), final, r.status_code
    except Exception:
        return False, False, None, None

def check_www_variant(domain_root: str):
    """
    Best-effort: confronta www.<root> e <root>, vede se redirigono ad un canonical uguale.
    """
    try:
        r1 = requests.get(f"https://{domain_root}", timeout=10, allow_redirects=True, headers=UA)
        r2 = requests.get(f"https://www.{domain_root}", timeout=10, allow_redirects=True, headers=UA)
        return {
            "ok": True,
            "apex_final": r1.url,
            "www_final": r2.url,
            "apex_status": r1.status_code,
            "www_status": r2.status_code,
            "same_final": (r1.url == r2.url),
        }
    except Exception:
        return {"ok": False}

def tls_details(host: str, port: int = 443):
    """
    Connessione TLS best-effort: versione TLS, cipher, cert subject/SAN/issuer, scadenza.
    """
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            tls_version = ssock.version()
            cipher = ssock.cipher()

    not_after = cert.get("notAfter")
    expires = None
    days_left = None
    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days

    # Subject + Issuer
    subject = cert.get("subject", [])
    subject_str = ", ".join("=".join(x) for item in subject for x in item) if subject else "N/D"
    issuer = cert.get("issuer", [])
    issuer_str = ", ".join("=".join(x) for item in issuer for x in item) if issuer else "N/D"

    # SAN
    san = cert.get("subjectAltName", [])
    san_dns = [v for (k, v) in san if k.lower() == "dns"] if san else []

    return {
        "tls_version": tls_version,
        "cipher": cipher,  # tuple (name, protocol, bits)
        "subject": subject_str,
        "issuer": issuer_str,
        "san_dns": san_dns,
        "expires": expires,
        "days_left": days_left,
    }

def dns_query(name: str, rtype: str):
    try:
        ans = dns.resolver.resolve(name, rtype)
        return [str(r) for r in ans]
    except Exception:
        return []

def dns_txt(name: str):
    try:
        answers = dns.resolver.resolve(name, "TXT")
        out = []
        for r in answers:
            out.append("".join([p.decode("utf-8") if isinstance(p, bytes) else str(p) for p in r.strings]))
        return out
    except Exception:
        return []

def get_caa(domain: str):
    return dns_query(domain, "CAA")

def dnssec_enabled(domain: str):
    # Best-effort: se c'è DS sul dominio, la zona è probabilmente firmata.
    return len(dns_query(domain, "DS")) > 0

def fetch_text(url: str, max_chars=5000):
    r = http_get(url)
    if not r or r.status_code >= 400:
        return None
    return (r.text or "")[:max_chars]

def check_security_txt(host: str):
    urls = [f"https://{host}/.well-known/security.txt", f"https://{host}/security.txt"]
    for u in urls:
        txt = fetch_text(u, max_chars=5000)
        if txt:
            return u, txt
    return None, None

def check_robots_sitemap(host: str):
    robots_url = f"https://{host}/robots.txt"
    robots = fetch_text(robots_url, max_chars=5000)
    sitemaps = []
    if robots:
        for line in robots.splitlines():
            if line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
    return robots_url, robots, sitemaps

def hsts_preload_readiness(hsts_value: str):
    """
    Best-effort: controlla includeSubDomains + preload + max-age>=31536000
    """
    if not hsts_value:
        return False, ["Header HSTS mancante"]

    v = hsts_value.lower()
    issues = []

    # max-age
    max_age = None
    try:
        parts = [p.strip() for p in v.split(";")]
        for p in parts:
            if p.startswith("max-age"):
                max_age = int(p.split("=", 1)[1].strip())
                break
    except Exception:
        max_age = None

    if max_age is None:
        issues.append("max-age non trovato")
    elif max_age < 31536000:
        issues.append("max-age < 31536000 (1 anno)")

    if "includesubdomains" not in v:
        issues.append("includeSubDomains mancante")
    if "preload" not in v:
        issues.append("preload mancante")

    return len(issues) == 0, issues

def ct_subdomains(domain_root: str, limit: int = 200):
    """
    OSINT pubblico via Certificate Transparency (crt.sh).
    Restituisce subdomini presenti nei certificati (best-effort).
    """
    try:
        url = f"https://crt.sh/?q=%25.{domain_root}&output=json"
        r = requests.get(url, timeout=12, headers=UA)
        if r.status_code != 200:
            return []

        data = r.json()
        names = set()
        for row in data:
            nv = row.get("name_value", "")
            for n in str(nv).splitlines():
                n = n.strip().lower()
                if n.startswith("*."):
                    n = n[2:]
                if n and n.endswith(domain_root):
                    names.add(n)
                if len(names) >= limit:
                    break
            if len(names) >= limit:
                break

        return sorted(names)
    except Exception:
        return []

def tcp_connect(host: str, port: int, timeout=1.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

# ------------------------------------------------
# SESSION STATE (per non perdere i risultati al rerun)
# ------------------------------------------------
if "analyzed" not in st.session_state:
    st.session_state.analyzed = False
if "target_value" not in st.session_state:
    st.session_state.target_value = ""
if "advanced" not in st.session_state:
    st.session_state.advanced = False

# ------------------------------------------------
# INPUT
# ------------------------------------------------
target = st.text_input("Dominio o IP pubblico (es: azienda.it oppure 8.8.8.8)", value=st.session_state.target_value)
go = st.button("Analizza")

if go and target:
    st.session_state.analyzed = True
    st.session_state.target_value = target

if not st.session_state.analyzed or not st.session_state.target_value:
    st.info("Inserisci un dominio (o IP pubblico) e premi *Analizza*.")
    st.stop()

# ------------------------------------------------
# ANALISI
# ------------------------------------------------
host = normalize_input(st.session_state.target_value)
is_ip = target_is_ip(host)

if is_ip and not is_public_ip(host):
    st.error("IP non consentito: inserisci solo IP PUBBLICI (no privati/loopback/riservati).")
    st.stop()

root = apex_domain(host)

st.markdown("---")
st.subheader("Riepilogo")
st.write(f"Target: {host}")
st.write(f"Tipo: {'IP pubblico' if is_ip else 'Dominio'}")
if not is_ip:
    st.write(f"Dominio principale (apex): {root}")

# Safe defaults
final_url = None
status = 0
headers = {}
tls = {}
spf = None
dmarc = None
dnssec = False
caa = []
ns = []
mx = []
soa = []
header_score = 0

# ------------------------------------------------
# 1) SECURITY HEADERS
# ------------------------------------------------
st.markdown("## 1) Security Headers")

header_list = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
]

try:
    if is_ip:
        r = http_get(f"http://{host}")
        if r:
            final_url, status, headers = r.url, r.status_code, r.headers
            st.write(f"URL finale (HTTP): {final_url}")
            st.write(f"HTTP status: {status}")
        else:
            st.error("Impossibile raggiungere HTTP sull’IP (best-effort).")
    else:
        final_url, status, headers = fetch_headers_https(host)
        st.write(f"URL finale: {final_url}")
        st.write(f"HTTP status: {status}")
except Exception:
    st.error("Impossibile leggere gli header (host non raggiungibile / errore SSL / redirect).")

for h in header_list:
    if h in headers:
        st.success(f"✔ {h} presente")
        header_score += 1
    else:
        st.warning(f"⚠ {h} mancante")

st.caption(f"Punteggio headers: {header_score}/{len(header_list)}")

# ------------------------------------------------
# 2) TLS / SSL (RICH)
# ------------------------------------------------
st.markdown("## 2) TLS / SSL (dettagli)")

if is_ip:
    if tcp_connect(host, 443, timeout=2.0):
        st.warning("Porta 443 raggiungibile. Nota: su IP non validiamo hostname del certificato (best-effort).")
    else:
        st.warning("Porta 443 non raggiungibile (o filtrata).")
else:
    try:
        tls = tls_details(host, 443)
        st.success("Connessione TLS riuscita (best-effort).")
        st.write(f"TLS Version: **{tls.get('tls_version','N/D')}**")
        c = tls.get("cipher")
        if c:
            st.write(f"Cipher: **{c[0]}** — {c[1]} — {c[2]} bits")

        st.write(f"Issuer: {tls.get('issuer','N/D')}")
        st.write(f"Subject: {tls.get('subject','N/D')}")

        san_dns = tls.get("san_dns", [])
        if san_dns:
            st.write("SAN (DNS) principali:")
            st.code("\n".join(san_dns[:50]))

        if tls.get("days_left") is None:
            st.warning("Non riesco a determinare la scadenza del certificato.")
        else:
            dl = tls["days_left"]
            if dl < 0:
                st.error(f"Certificato SCADUTO ({dl} giorni).")
            elif dl < 30:
                st.warning(f"Certificato in scadenza: {dl} giorni.")
            else:
                st.success(f"Certificato valido: scade tra {dl} giorni.")

        if tls.get("expires"):
            st.write(f"Scadenza: {tls['expires'].strftime('%Y-%m-%d %H:%M UTC')}")
    except Exception:
        st.error("Impossibile verificare TLS/SSL (porta 443 non disponibile o handshake fallito).")

# ------------------------------------------------
# 3) EMAIL SECURITY (SPF / DMARC)
# ------------------------------------------------
st.markdown("## 3) Email Security (SPF / DMARC)")

if is_ip:
    st.info("Per IP non esistono SPF/DMARC (sono record DNS del dominio).")
else:
    spf = next((x for x in dns_txt(root) if x.lower().startswith("v=spf1")), None)
    dmarc = next((x for x in dns_txt(f"_dmarc.{root}") if x.lower().startswith("v=dmarc1")), None)

    if spf:
        st.success("✔ SPF presente")
        st.code(spf)
    else:
        st.warning("⚠ SPF assente (record TXT v=spf1 mancante)")

    if dmarc:
        st.success("✔ DMARC presente")
        st.code(dmarc)
    else:
        st.warning("⚠ DMARC assente (record TXT su _dmarc.<dominio> mancante)")

# ------------------------------------------------
# 4) DNS HYGIENE / HARDENING (DNSSEC / CAA / NS / MX / SOA)
# ------------------------------------------------
st.markdown("## 4) DNS Hygiene / Hardening (DNSSEC / CAA / NS / MX / SOA)")

if is_ip:
    st.info("Per IP non si applicano DNSSEC/CAA/NS/MX/SOA (valgono per il dominio).")
else:
    dnssec = dnssec_enabled(root)
    caa = get_caa(root)
    ns = dns_query(root, "NS")
    mx = dns_query(root, "MX")
    soa = dns_query(root, "SOA")

    if dnssec:
        st.success("✔ DNSSEC: record DS trovato (best-effort: zona probabilmente firmata)")
        st.code("\n".join(dns_query(root, "DS")))
    else:
        st.warning("⚠ DNSSEC: record DS non trovato (probabilmente non firmato)")

    if caa:
        st.success("✔ CAA presente (limita chi può emettere certificati)")
        st.code("\n".join(caa))
    else:
        st.warning("⚠ CAA assente")

    if ns:
        st.success("✔ NS (nameserver) rilevati")
        st.code("\n".join(ns))
    else:
        st.warning("⚠ NS non rilevati (anomalo)")

    if mx:
        st.success("✔ MX (mail exchanger) rilevati")
        st.code("\n".join(mx))
    else:
        st.warning("⚠ MX assenti (può essere normale se non gestisci posta sul dominio)")

    if soa:
        st.success("✔ SOA rilevato")
        st.code("\n".join(soa))
    else:
        st.warning("⚠ SOA non rilevato (anomalo)")

# ------------------------------------------------
# 5) REPUTATION / LIMITI (SAFE)
# ------------------------------------------------
st.markdown("## 5) Limiti & Legal Safe Mode")
st.info(
    "Questo strumento usa solo dati pubblici e richieste standard (HTTP/DNS/SSL). "
    "Non esegue exploit, brute-force, autenticazioni, né scanning esteso. "
    "Le verifiche tecniche aggiuntive (porte) sono best-effort e vanno usate solo con autorizzazione del proprietario."
)

# ------------------------------------------------
# 6) MODALITÀ TECNICA (solo con autorizzazione)
# ------------------------------------------------
st.markdown("## 6) Modalità tecnica")
st.caption(
    "Abilita controlli best-effort aggiuntivi (semplice TCP connect su poche porte comuni). "
    "Da usare solo con autorizzazione del proprietario."
)

st.session_state.advanced = st.checkbox(
    "Modalità tecnica avanzata (richiede autorizzazione del proprietario)",
    value=st.session_state.advanced,
    key="advanced_checkbox",
)
advanced = st.session_state.advanced

# ------------------------------------------------
# 7) Exposure — Porte comuni (best-effort)
# ------------------------------------------------
st.markdown("## 7) Exposure — Porte comuni (best-effort)")

if not advanced:
    st.info("Attiva la modalità tecnica avanzata (punto 6) per visualizzare i controlli sulle porte.")
else:
    st.info(
        "Controllo leggero: verifica solo se la porta risponde (TCP connect). "
        "Nessuna scansione aggressiva, nessun brute-force, nessun tentativo di accesso."
    )

    common_ports = [
        (21, "FTP"),
        (22, "SSH"),
        (25, "SMTP"),
        (80, "HTTP"),
        (443, "HTTPS"),
        (110, "POP3"),
        (143, "IMAP"),
        (3306, "MySQL"),
        (3389, "RDP"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
        (8080, "HTTP-alt"),
        (8443, "HTTPS-alt"),
        (9200, "Elasticsearch"),
    ]

    open_ports = 0
    for p, name in common_ports:
        if tcp_connect(host, p):
            st.warning(f"⚠ Porta {p} ({name}) aperta (best-effort)")
            open_ports += 1
        else:
            st.success(f"✔ Porta {p} ({name}) chiusa")

    if open_ports == 0:
        st.success("✔ Nessuna porta comune risulta esposta (best-effort).")
    else:
        st.warning("⚠ Alcune porte comuni risultano esposte: verifica che siano volute e protette (firewall/VPN/ACL).")

# ------------------------------------------------
# 8) OSINT PACK (GRATIS) — redirect / security.txt / robots / sitemap / HSTS / CT
# ------------------------------------------------
st.markdown("## 8) OSINT Pack — Asset & Best Practice Pubbliche (gratis)")

# 8.1 Redirect HTTP -> HTTPS
st.markdown("### 8.1 Redirect HTTP → HTTPS")
ok_http, is_https, final, code = check_redirect_http_to_https(host)
if not ok_http:
    st.warning("Impossibile verificare il redirect (HTTP non raggiungibile o filtrato).")
else:
    st.write(f"Final URL: {final} (status {code})")
    if is_https:
        st.success("✔ Redirect a HTTPS presente (best-effort).")
    else:
        st.warning("⚠ Non risulta redirect a HTTPS (best-effort). Consigliato redirect 80→443.")

# 8.2 WWW vs apex canonical
st.markdown("### 8.2 WWW ↔ non-WWW (canonical)")
if is_ip:
    st.info("Canonical WWW: non applicabile a IP.")
else:
    vv = check_www_variant(root)
    if not vv.get("ok"):
        st.warning("Impossibile verificare WWW/non-WWW (best-effort).")
    else:
        st.write(f"Apex finale: {vv['apex_final']} (status {vv['apex_status']})")
        st.write(f"WWW finale: {vv['www_final']} (status {vv['www_status']})")
        if vv["same_final"]:
            st.success("✔ www e non-www convergono allo stesso URL finale (best-effort).")
        else:
            st.warning("⚠ www e non-www NON convergono: consigliato scegliere un canonical e redirigere l’altro.")

# 8.3 security.txt
st.markdown("### 8.3 security.txt (best practice)")
sec_url, sec_txt = check_security_txt(host)
if sec_txt:
    st.success("✔ security.txt trovato")
    st.write(f"URL: {sec_url}")
    st.code(sec_txt)
else:
    st.warning("⚠ security.txt non trovato (best practice per contatto vulnerabilità).")

# 8.4 robots / sitemap
st.markdown("### 8.4 robots.txt & sitemap")
robots_url, robots_txt, sitemaps = check_robots_sitemap(host)
if robots_txt:
    st.success("✔ robots.txt trovato")
    st.write(f"URL: {robots_url}")
    st.code(robots_txt[:2000])
    if sitemaps:
        st.success("✔ Sitemap dichiarate in robots.txt")
        for sm in sitemaps[:20]:
            st.write(f"- {sm}")
    else:
        st.info("Nessuna sitemap dichiarata in robots.txt (best-effort).")
else:
    st.warning("⚠ robots.txt non trovato (best-effort).")

# 8.5 HSTS preload readiness
st.markdown("### 8.5 HSTS Preload Readiness (best-effort)")
hsts_val = headers.get("Strict-Transport-Security") if isinstance(headers, dict) else None
if not hsts_val:
    st.warning("⚠ HSTS non presente. (Per siti web pubblici è raccomandato abilitare HSTS.)")
else:
    st.code(hsts_val)
    ready, issues = hsts_preload_readiness(hsts_val)
    if ready:
        st.success("✔ Configurazione HSTS compatibile con requisiti preload (best-effort).")
    else:
        st.warning("⚠ HSTS non 'preload-ready' (best-effort). Dettagli:")
        for i in issues:
            st.write(f"- {i}")

# 8.6 Certificate Transparency (solo dominio)
st.markdown("### 8.6 Certificate Transparency (subdomini dai registri pubblici)")
if is_ip:
    st.info("CT: non applicabile a IP. Inserisci un dominio per ottenere subdomini da registri pubblici.")
else:
    with st.spinner("Ricerca CT in corso (crt.sh)..."):
        subs = ct_subdomains(root, limit=200)

    if not subs:
        st.warning("Nessun risultato CT trovato (o sorgente momentaneamente non disponibile).")
    else:
        st.success(f"Trovati {len(subs)} possibili subdomini nei registri CT (best-effort).")
        st.code("\n".join(subs[:200]))
        st.caption("Nota: presenza in CT ≠ vulnerabilità. È un indicatore di superficie esposta (asset discovery).")

# ------------------------------------------------
# 9) Checklist sintetica
# ------------------------------------------------
st.markdown("## 9) Checklist sintetica")

checks_ok = 0
checks_total = 0

checks_total += 1
if status in (200, 301, 302, 307, 308):
    st.success("✔ Raggiungibilità web OK (best-effort)")
    checks_ok += 1
else:
    st.warning("⚠ Raggiungibilità non verificata / status non atteso")

checks_total += 1
if (not is_ip) and isinstance(tls.get("days_left"), int) and tls["days_left"] > 0:
    st.success("✔ Certificato SSL valido")
    checks_ok += 1
elif is_ip:
    st.info("SSL su IP: validazione hostname non applicabile (best-effort).")
else:
    st.warning("⚠ SSL non valido o non verificabile")

if not is_ip:
    checks_total += 1
    if spf:
        st.success("✔ SPF presente")
        checks_ok += 1
    else:
        st.warning("⚠ SPF assente")

    checks_total += 1
    if dmarc:
        st.success("✔ DMARC presente")
        checks_ok += 1
    else:
        st.warning("⚠ DMARC assente")

    checks_total += 1
    if dnssec:
        st.success("✔ DNSSEC presente")
        checks_ok += 1
    else:
        st.warning("⚠ DNSSEC assente")

    checks_total += 1
    if caa:
        st.success("✔ CAA presente")
        checks_ok += 1
    else:
        st.warning("⚠ CAA assente")
else:
    st.info("SPF/DMARC/DNSSEC/CAA: N/A su IP (valgono sul dominio).")

st.caption(f"Checklist: {checks_ok}/{checks_total}")

# ------------------------------------------------
# 10) CYBER EXPOSURE INDEX (Score)
# ------------------------------------------------
st.markdown("## 10) Cyber Exposure Index")

# WEIGHTS: Web(40) Email(35) DNS(25)
web = 0
email_score = 0
dns_score = 0

# WEB
if status in (200, 301, 302, 307, 308):
    web += 10
if (not is_ip) and isinstance(tls.get("days_left"), int) and tls["days_left"] > 0:
    web += 10
web += min(20, header_score * 5)

# EMAIL
if not is_ip:
    if spf:
        email_score += 10
    if dmarc:
        email_score += 15
        dl = dmarc.lower()
        if "p=quarantine" in dl:
            email_score += 5
        if "p=reject" in dl:
            email_score += 10

# DNS
if not is_ip:
    if dnssec:
        dns_score += 10
    if caa:
        dns_score += 10
    # bonus “igiene DNS”
    if mx:
        dns_score += 3
    if ns:
        dns_score += 2

total = min(web + email_score + dns_score, 100)

c1, c2, c3 = st.columns(3)
with c1:
    st.metric("Web", f"{web}/40")
with c2:
    st.metric("Email", f"{email_score}/35")
with c3:
    st.metric("DNS", f"{dns_score}/25")

st.markdown(f"### Punteggio Totale: {total}/100")

if total < 40:
    st.error("Livello di esposizione: ALTO")
elif total < 70:
    st.warning("Livello di esposizione: MEDIO")
else:
    st.success("Livello di esposizione: BASSO")

st.markdown("---")
st.caption("Suggerimento: se vuoi, aggiungi contatti e CTA (report PDF + remediation plan) in sidebar per trasformare il tool in lead generator.")

