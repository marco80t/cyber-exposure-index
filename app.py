import streamlit as st
import requests
import ssl
import socket
import ipaddress
from datetime import datetime, timezone

import dns.resolver
import tldextract

# ------------------------------------------------
# CONFIG / UI
# ------------------------------------------------
st.set_page_config(page_title="Security Quick Check", page_icon="🛡️", layout="wide")

st.title("Security Quick Check")
st.write("Analisi basata esclusivamente su informazioni pubbliche (HTTP / DNS / SSL). Nessun test intrusivo.")
st.caption("Nota: questo strumento fornisce una verifica preliminare e non sostituisce un assessment professionale completo.")

UA = {"User-Agent": "SecurityQuickCheck/1.0"}

# ------------------------------------------------
# HELPERS (PUBLIC / SAFE)
# ------------------------------------------------
def normalize_domain(d: str) -> str:
    d = (d or "").strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    return d.split("/")[0]

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

def fetch_headers(host: str):
    r = requests.get(
        f"https://{host}",
        timeout=8,
        allow_redirects=True,
        headers=UA,
    )
    return r.url, r.status_code, r.headers

def ssl_info(host: str):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()

    not_after = cert.get("notAfter")
    expires = None
    days_left = None

    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days

    return {"expires": expires, "days_left": days_left}

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
    try:
        answers = dns.resolver.resolve(domain, "CAA")
        return [str(r) for r in answers]
    except Exception:
        return []

def dnssec_enabled(domain: str):
    # Best-effort: se c'è DS sul dominio, la zona è probabilmente firmata.
    try:
        dns.resolver.resolve(domain, "DS")
        return True
    except Exception:
        return False

def tcp_connect(host: str, port: int, timeout=1.2) -> bool:
    # Best-effort: semplice connect TCP (NO scan aggressivo, NO brute force, NO exploitation).
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def http_get(url: str, timeout=8):
    try:
        return requests.get(url, timeout=timeout, allow_redirects=True, headers=UA)
    except Exception:
        return None

def fetch_text(url: str, max_chars=5000):
    r = http_get(url)
    if not r or r.status_code >= 400:
        return None
    return (r.text or "")[:max_chars]

def check_security_txt(host: str):
    # Public file: security.txt
    urls = [f"https://{host}/.well-known/security.txt", f"https://{host}/security.txt"]
    for u in urls:
        txt = fetch_text(u, max_chars=5000)
        if txt:
            return u, txt
    return None, None

def check_redirect_http_to_https(host: str):
    """
    Best-effort: prova HTTP e vede se finisce su HTTPS.
    """
    try:
        r = requests.get(f"http://{host}", timeout=8, allow_redirects=True, headers=UA)
        final = r.url or ""
        return True, final.lower().startswith("https://"), final, r.status_code
    except Exception:
        return False, False, None, None

def hsts_preload_readiness(hsts_value: str):
    """
    Controllo "preload readiness" best-effort:
    - includeSubDomains
    - preload
    - max-age >= 31536000
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
    Restituisce subdomini trovati nei certificati.
    """
    try:
        url = f"https://crt.sh/?q=%25.{domain_root}&output=json"
        r = requests.get(url, timeout=10, headers=UA)
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

# ------------------------------------------------
# SESSION STATE (per non perdere i risultati al rerun)
# ------------------------------------------------
if "analyzed" not in st.session_state:
    st.session_state.analyzed = False
if "domain_value" not in st.session_state:
    st.session_state.domain_value = ""
if "advanced" not in st.session_state:
    st.session_state.advanced = False

# ------------------------------------------------
# INPUT
# ------------------------------------------------
domain = st.text_input("Dominio o IP pubblico (es: azienda.it oppure 8.8.8.8)", value=st.session_state.domain_value)
go = st.button("Analizza")

# Se premi Analizza, memorizzo dominio e “blocco” l’analisi come attiva
if go and domain:
    st.session_state.analyzed = True
    st.session_state.domain_value = domain

# Se non ho ancora analizzato, fine qui (così non appaiono sezioni a caso in home)
if not st.session_state.analyzed or not st.session_state.domain_value:
    st.info("Inserisci un dominio (o IP pubblico) e premi *Analizza*.")
    st.stop()

# ------------------------------------------------
# BLOCCO ANALISI (resta attivo anche dopo rerun)
# ------------------------------------------------
host = normalize_domain(st.session_state.domain_value)
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

# Variabili “safe default” per evitare errori a cascata
final_url = None
status = 0
headers = {}
info = {"days_left": None, "expires": None}
spf = None
dmarc = None
dnssec = False
caa = []
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
        # Su IP l’HTTPS può fallire per mismatch certificato: facciamo HTTP best-effort
        r = requests.get(
            f"http://{host}",
            timeout=8,
            allow_redirects=True,
            headers=UA,
        )
        final_url, status, headers = r.url, r.status_code, r.headers
        st.write(f"URL finale (HTTP): {final_url}")
        st.write(f"HTTP status: {status}")
        st.info("Nota: su IP la lettura header via HTTPS può fallire (certificato non associato all’IP).")
    else:
        final_url, status, headers = fetch_headers(host)
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
# 2) SSL
# ------------------------------------------------
st.markdown("## 2) SSL Certificate")

try:
    if is_ip:
        # Su IP: best-effort reachability 443 (no validazione hostname/cert)
        if tcp_connect(host, 443, timeout=2.0):
            st.warning("Porta 443 raggiungibile. Nota: su IP non validiamo certificato/hostname (best-effort).")
        else:
            st.warning("Porta 443 non raggiungibile (o filtrata).")
    else:
        info = ssl_info(host)
        if info["days_left"] is None:
            st.warning("Non riesco a determinare la scadenza del certificato.")
        elif info["days_left"] < 0:
            st.error(f"Certificato SCADUTO ({info['days_left']} giorni).")
        elif info["days_left"] < 30:
            st.warning(f"Certificato in scadenza: {info['days_left']} giorni.")
        else:
            st.success(f"Certificato valido: scade tra {info['days_left']} giorni.")

        if info.get("expires"):
            st.write(f"Scadenza: {info['expires'].strftime('%Y-%m-%d %H:%M UTC')}")
except Exception:
    st.error("Impossibile verificare SSL (porta 443 non disponibile o handshake fallito).")

# ------------------------------------------------
# 3) EMAIL SECURITY (SPF / DMARC)
# ------------------------------------------------
st.markdown("## 3) Email Security (SPF / DMARC)")

if is_ip:
    st.info("Per IP non esistono SPF/DMARC (sono record DNS del dominio).")
    spf, dmarc = None, None
else:
    try:
        spf = next((x for x in dns_txt(root) if x.lower().startswith("v=spf1")), None)
        dmarc = next((x for x in dns_txt(f"_dmarc.{root}") if x.lower().startswith("v=dmarc1")), None)
    except Exception:
        spf, dmarc = None, None

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
# 4) DNS HARDENING (DNSSEC / CAA)
# ------------------------------------------------
st.markdown("## 4) DNS Hardening (DNSSEC / CAA)")

if is_ip:
    st.info("Per IP non si applicano DNSSEC/CAA (valgono per il dominio/zone DNS).")
    dnssec, caa = False, []
else:
    dnssec = dnssec_enabled(root)
    caa = get_caa(root)

    if dnssec:
        st.success("✔ DNSSEC: record DS trovato (best-effort: zona probabilmente firmata)")
    else:
        st.warning("⚠ DNSSEC: record DS non trovato (probabilmente non firmato)")

    if caa:
        st.success("✔ CAA presente (limita chi può emettere certificati)")
        st.code("\n".join(caa))
    else:
        st.warning("⚠ CAA assente")

# ------------------------------------------------
# 5) REPUTATION (SAFE)
# ------------------------------------------------
st.markdown("## 5) Reputation (SAFE)")
st.info(
    "Analisi esclusivamente su configurazione tecnica pubblica. "
    "Nessun accesso a sistemi terzi, nessun test intrusivo, nessuna interrogazione dark web."
)

# ------------------------------------------------
# 6) MODALITÀ TECNICA (solo con autorizzazione)
# ------------------------------------------------
st.markdown("## 6) Modalità tecnica")
st.caption(
    "Questa modalità abilita controlli best-effort aggiuntivi (semplice TCP connect su poche porte comuni). "
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
        (3306, "MySQL"),
        (3389, "RDP"),
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
# 8) OSINT PACK (GRATIS) — CT + security.txt + redirect + HSTS preload
# ------------------------------------------------
st.markdown("## 8) OSINT Pack (GRATIS) — Asset & Best Practice Pubbliche")

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

# 8.2 security.txt
st.markdown("### 8.2 security.txt (RFC best practice)")
sec_url, sec_txt = check_security_txt(host)
if sec_txt:
    st.success("✔ security.txt trovato")
    st.write(f"URL: {sec_url}")
    st.code(sec_txt)
else:
    st.warning("⚠ security.txt non trovato (best practice per contatto vulnerabilità).")

# 8.3 HSTS preload readiness (solo se header presente)
st.markdown("### 8.3 HSTS Preload Readiness (best-effort)")
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

# 8.4 Certificate Transparency (solo dominio)
st.markdown("### 8.4 Certificate Transparency (subdomini dai registri pubblici)")
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
# 9) Risultati sintetici (Checklist)
# ------------------------------------------------
st.markdown("## 9) Checklist sintetica")

checks_ok = 0
checks_total = 0

# Reachability
checks_total += 1
if (not is_ip) and status in (200, 301, 302, 307, 308):
    st.success("✔ HTTPS raggiungibile")
    checks_ok += 1
elif is_ip and status in (200, 301, 302, 307, 308):
    st.success("✔ HTTP raggiungibile (IP)")
    checks_ok += 1
else:
    st.warning("⚠ Raggiungibilità non verificata / status non atteso")

# SSL valid (solo dominio)
checks_total += 1
if (not is_ip) and isinstance(info.get("days_left"), int) and info["days_left"] > 0:
    st.success("✔ Certificato SSL valido")
    checks_ok += 1
elif is_ip:
    st.info("SSL su IP: non validato (best-effort).")
else:
    st.warning("⚠ SSL non valido o non verificabile")

# SPF / DMARC (solo dominio)
checks_total += 1
if not is_ip and spf:
    st.success("✔ SPF presente")
    checks_ok += 1
elif is_ip:
    st.info("SPF: N/A su IP")
else:
    st.warning("⚠ SPF assente")

checks_total += 1
if not is_ip and dmarc:
    st.success("✔ DMARC presente")
    checks_ok += 1
elif is_ip:
    st.info("DMARC: N/A su IP")
else:
    st.warning("⚠ DMARC assente")

# DNSSEC / CAA (solo dominio)
checks_total += 1
if not is_ip and dnssec:
    st.success("✔ DNSSEC presente")
    checks_ok += 1
elif is_ip:
    st.info("DNSSEC: N/A su IP")
else:
    st.warning("⚠ DNSSEC assente")

checks_total += 1
if not is_ip and caa:
    st.success("✔ CAA presente")
    checks_ok += 1
elif is_ip:
    st.info("CAA: N/A su IP")
else:
    st.warning("⚠ CAA assente")

st.caption(f"Checklist: {checks_ok}/{checks_total}")

# ------------------------------------------------
# 10) CYBER EXPOSURE INDEX (Score)
# ------------------------------------------------
st.markdown("## 10) Cyber Exposure Index")

web = 0
email_score = 0
dns_score = 0

# WEB
if status in (200, 301, 302, 307, 308):
    web += 10

# SSL (solo dominio)
if (not is_ip) and isinstance(info.get("days_left"), int) and info["days_left"] > 0:
    web += 10

# Headers score
web += min(20, header_score * 5)

# EMAIL (solo dominio)
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

# DNS (solo dominio)
if not is_ip:
    if dnssec:
        dns_score += 10
    if caa:
        dns_score += 10

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
