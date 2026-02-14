import streamlit as st
import requests
import ssl
import socket
from datetime import datetime, timezone
import dns.resolver
import tldextract

# ------------------------------------------------
# CONFIG
# ------------------------------------------------
st.set_page_config(page_title="Security Quick Check", page_icon="🛡️", layout="wide")

st.title("Security Quick Check")
st.write("Analisi basata esclusivamente su informazioni pubbliche (HTTP / DNS / SSL). Nessun test intrusivo.")

# ------------------------------------------------
# HELPERS
# ------------------------------------------------
def normalize_domain(d):
    d = (d or "").strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    return d.split("/")[0]

def apex_domain(hostname):
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname

def fetch_headers(host):
    r = requests.get(f"https://{host}", timeout=8, allow_redirects=True)
    return r.status_code, r.headers

def ssl_info(host):
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

    return {
        "expires": expires,
        "days_left": days_left
    }

def dns_txt(name):
    try:
        answers = dns.resolver.resolve(name, "TXT")
        return ["".join([p.decode() for p in r.strings]) for r in answers]
    except:
        return []

def dns_exists(name, rtype):
    try:
        dns.resolver.resolve(name, rtype)
        return True
    except:
        return False

def get_caa(domain):
    try:
        answers = dns.resolver.resolve(domain, "CAA")
        return [str(r) for r in answers]
    except:
        return []

def dnssec_enabled(domain):
    try:
        dns.resolver.resolve(domain, "DS")
        return True
    except:
        return False

def tcp_connect(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

# ------------------------------------------------
# INPUT
# ------------------------------------------------
domain = st.text_input("Dominio (es: azienda.it)")
go = st.button("Analizza")

if go and domain:

    host = normalize_domain(domain)
    root = apex_domain(host)

    st.markdown("---")
    st.subheader("Riepilogo")
    st.write(f"Host: {host}")
    st.write(f"Dominio principale: {root}")

    # ------------------------------------------------
    # 1) SECURITY HEADERS
    # ------------------------------------------------
    st.markdown("## 1) Security Headers")

    headers = {}
    status = 0

    try:
        status, headers = fetch_headers(host)
        st.write(f"HTTP Status: {status}")
    except:
        st.error("HTTPS non raggiungibile")

    header_list = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Referrer-Policy"
    ]

    header_score = 0
    for h in header_list:
        if h in headers:
            st.success(f"{h} presente")
            header_score += 1
        else:
            st.warning(f"{h} mancante")

    # ------------------------------------------------
    # 2) SSL
    # ------------------------------------------------
    st.markdown("## 2) SSL Certificate")

    info = {"days_left": None}
    try:
        info = ssl_info(host)
        if info["days_left"] and info["days_left"] > 0:
            st.success(f"Certificato valido ({info['days_left']} giorni)")
        else:
            st.warning("Certificato in scadenza o non verificabile")
    except:
        st.error("Impossibile verificare SSL")

    # ------------------------------------------------
    # 3) EMAIL SECURITY
    # ------------------------------------------------
    st.markdown("## 3) Email Security")

    spf = next((x for x in dns_txt(root) if x.lower().startswith("v=spf1")), None)
    dmarc = next((x for x in dns_txt(f"_dmarc.{root}") if x.lower().startswith("v=dmarc1")), None)

    if spf:
        st.success("SPF presente")
    else:
        st.warning("SPF assente")

    if dmarc:
        st.success("DMARC presente")
    else:
        st.warning("DMARC assente")

    # ------------------------------------------------
    # 4) DNS HARDENING
    # ------------------------------------------------
    st.markdown("## 4) DNS Hardening")

    dnssec = dnssec_enabled(root)
    caa = get_caa(root)

    if dnssec:
        st.success("DNSSEC attivo")
    else:
        st.warning("DNSSEC non rilevato")

    if caa:
        st.success("CAA presente")
    else:
        st.warning("CAA assente")

    # ------------------------------------------------
    # 5) REPUTATION (SAFE)
    # ------------------------------------------------
    st.markdown("## 5) Reputation (SAFE)")
    st.info("Analisi esclusivamente su configurazione tecnica pubblica. Nessuna interrogazione dark web.")

    # -----------------------------
# 6) Modalità tecnica (solo con autorizzazione)
# -----------------------------
st.markdown("## 6) Modalità tecnica")

advanced = st.checkbox("Modalità tecnica avanzata (richiede autorizzazione del proprietario)")

if advanced:
    st.markdown("### Exposure — Porte comuni (best-effort)")
    st.info("Verifica leggera TCP connect. Nessuno scan aggressivo.")

    common_ports = [21, 22, 25, 80, 443, 3306, 3389]

    for p in common_ports:
        if tcp_connect(host, p):
            st.warning(f"Porta {p} aperta")
        else:
            st.success(f"Porta {p} chiusa")
    # ------------------------------------------------
    # 7) CYBER EXPOSURE INDEX
    # ------------------------------------------------
    st.markdown("## 7) Cyber Exposure Index")

    web = 0
    email_score = 0
    dns_score = 0

    if status in (200, 301, 302):
        web += 10

    if info["days_left"] and info["days_left"] > 0:
        web += 10

    web += header_score * 5

    if spf:
        email_score += 10

    if dmarc:
        email_score += 15
        if "p=reject" in dmarc.lower():
            email_score += 10

    if dnssec:
        dns_score += 10

    if caa:
        dns_score += 10

    total = min(web + email_score + dns_score, 100)

    st.write(f"### Punteggio Totale: {total}/100")

    if total < 40:
        st.error("Livello di esposizione: ALTO")
    elif total < 70:
        st.warning("Livello di esposizione: MEDIO")
    else:
        st.success("Livello di esposizione: BASSO")

