import streamlit as st
import requests
import ssl
import socket
from datetime import datetime, timezone

import dns.resolver
import tldextract


# -----------------------------
# UI / BRANDING
# -----------------------------
st.set_page_config(
    page_title="Security Quick Check",
    page_icon="🛡️",
    layout="wide"
)

def load_css():
    st.markdown(
        """
        <style>
        .block-container { padding-top: 2rem; }
        .metric-box {
            padding: 14px 16px;
            border-radius: 12px;
            border: 1px solid rgba(49,51,63,0.2);
            background: rgba(255,255,255,0.02);
        }
        .small { opacity: 0.8; font-size: 0.92rem; }
        </style>
        """,
        unsafe_allow_html=True
    )

load_css()

# Sidebar brand
with st.sidebar:
    st.markdown("## 🛡️ Security Quick Check")
    try:
        st.image("assets/logo.png", use_container_width=True)
    except:
        pass
    st.markdown("Strumento di verifica preliminare *(no-scan invasivi)*.")
    st.markdown("---")
    st.markdown("### Contatti")
    st.markdown("📩 *info@TUODOMINIO.it*")
    st.markdown("📞 *+39 ...*")
    st.markdown("---")
    st.markdown("<div class='small'>Nota: risultati basati su dati pubblici (HTTP/DNS/SSL). Non sostituisce un assessment completo.</div>", unsafe_allow_html=True)


st.title("Security Quick Check")
st.write("Inserisci un dominio e ottieni una verifica preliminare di *Security Headers, **SSL* e *SPF/DMARC*.")

# -----------------------------
# Helpers
# -----------------------------
def normalize_domain(d: str) -> str:
    d = (d or "").strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    d = d.split("/")[0]
    return d

def apex_domain(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname

def fetch_headers(url: str):
    # Segue redirect, prende header finali
    r = requests.get(url, timeout=8, allow_redirects=True)
    return r.url, r.status_code, r.headers

def ssl_info(hostname: str, port: int = 443):
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
    # Parse scadenza
    not_after = cert.get("notAfter")
    expires = None
    days_left = None
    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days

    issuer = cert.get("issuer", [])
    issuer_str = ", ".join("=".join(x) for item in issuer for x in item) if issuer else "N/D"

    subject = cert.get("subject", [])
    subject_str = ", ".join("=".join(x) for item in subject for x in item) if subject else "N/D"

    return {
        "issuer": issuer_str,
        "subject": subject_str,
        "expires": expires,
        "days_left": days_left,
    }

def dns_txt_records(name: str):
    try:
        answers = dns.resolver.resolve(name, "TXT")
        out = []
        for rdata in answers:
            # join fragments
            txt = "".join([part.decode("utf-8") if isinstance(part, bytes) else str(part) for part in rdata.strings])
            out.append(txt)
        return out
    except:
        return []

def find_spf(domain_root: str):
    txts = dns_txt_records(domain_root)
    for t in txts:
        if t.lower().startswith("v=spf1"):
            return t
    return None

def find_dmarc(domain_root: str):
    txts = dns_txt_records(f"_dmarc.{domain_root}")
    for t in txts:
        if t.lower().startswith("v=dmarc1"):
            return t
    return None


# -----------------------------
# Input
# -----------------------------
col1, col2 = st.columns([3,1])
with col1:
    domain_in = st.text_input("Dominio (es: azienda.it o www.azienda.it)")
with col2:
    st.write("")
    st.write("")
    go = st.button("Analizza", use_container_width=True)

if go and domain_in:
    host = normalize_domain(domain_in)
    root = apex_domain(host)

    st.markdown("---")
    st.subheader("Riepilogo")
    st.write(f"*Host inserito:* {host}  |  *Dominio principale:* {root}")

    headers = {}

    # -----------------------------
    # 1) Security Headers (HTTP)
    # -----------------------------
    st.markdown("## 1) Security Headers")
    checks = {
        "HSTS": "Strict-Transport-Security",
        "X-Frame-Options": "X-Frame-Options",
        "Content-Security-Policy": "Content-Security-Policy",
        "Referrer-Policy": "Referrer-Policy"
    }

    try:
        final_url, status, headers = fetch_headers(f"https://{host}")
        st.write(f"URL finale: *{final_url}*  |  HTTP status: *{status}*")

        score = 0
        for name, header in checks.items():
            if header in headers:
                st.success(f"✔ {name} presente")
                score += 1
            else:
                st.error(f"✘ {name} mancante")

        st.markdown(f"<div class='metric-box'><b>Punteggio Headers:</b> {score}/{len(checks)}</div>", unsafe_allow_html=True)

    except Exception:
        st.error("Impossibile leggere gli header via HTTPS (dominio non raggiungibile o errore SSL/redirect).")

    # -----------------------------
    # 2) SSL Certificate
    # -----------------------------
    st.markdown("## 2) SSL Certificato")
    try:
        info = ssl_info(host)
        if info["days_left"] is None:
            st.warning("Non riesco a determinare la scadenza del certificato.")
        else:
            if info["days_left"] < 0:
                st.error(f"Certificato *SCADUTO* ({info['days_left']} giorni).")
            elif info["days_left"] < 30:
                st.warning(f"Certificato in scadenza: *{info['days_left']} giorni*.")
            else:
                st.success(f"Certificato OK: scade tra *{info['days_left']} giorni*.")

        st.write(f"*Issuer:* {info['issuer']}")
        if info["expires"]:
            st.write(f"*Scadenza:* {info['expires'].strftime('%Y-%m-%d %H:%M UTC')}")

    except Exception:
        st.error("Impossibile leggere il certificato SSL (host non supporta 443 o handshake fallito).")

    # -----------------------------
    # 3) SPF / DMARC
    # -----------------------------
    st.markdown("## 3) Email Security (SPF / DMARC)")
    spf = find_spf(root)
    dmarc = find_dmarc(root)

    if spf:
        st.success("✔ SPF trovato")
        st.code(spf)
    else:
        st.error("✘ SPF non trovato (record TXT v=spf1 mancante)")

    if dmarc:
        st.success("✔ DMARC trovato")
        st.code(dmarc)
    else:
        st.error("✘ DMARC non trovato (record TXT su _dmarc.<dominio> mancante)")

    st.markdown("---")
    st.markdown("### Vuoi il report completo (PDF) + piano di intervento?")
    st.markdown("Scrivimi: *info@TUODOMINIO.it*  — oggetto: Security Quick Check")
    # -----------------------------
    # 4) CYBER EXPOSURE INDEX
    # -----------------------------
    st.markdown("## 4) Cyber Exposure Index")

    total_score = 0

    # WEB SECURITY (max 40)
    web_score = 0

    # HTTPS reachable
    try:
        requests.get(f"https://{host}", timeout=5)
        web_score += 10
    except:
        pass

    # SSL valid
    try:
        if info.get("days_left") is not None and info["days_left"] > 0:
            web_score += 10
    except:
        pass

    # TLS modern (per ora: se ssl_info ha funzionato)
    try:
        _ = info.get("issuer")
        web_score += 10
    except:
        pass

    # Headers (4 header = 10 punti totali)
    headers_score = 0
    header_list = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Referrer-Policy"
    ]
    for header in header_list:
        if header in headers:
            headers_score += 2.5

    web_score += headers_score
    total_score += web_score

    # EMAIL SECURITY (max 35)
    email_score = 0
    if spf:
        email_score += 10

    if dmarc:
        email_score += 15
        if "p=reject" in dmarc.lower() or "p=quarantine" in dmarc.lower():
            email_score += 10

    total_score += email_score

    # DNS GOVERNANCE (max 25)
    dns_score = 0

    # CAA (10)
    try:
        caa = dns.resolver.resolve(root, "CAA")
        if len(list(caa)) > 0:
            dns_score += 10
    except:
        pass

    # DNSSEC (10) - controllo semplice: presenza record DS
    try:
        ds = dns.resolver.resolve(root, "DS")
        if len(list(ds)) > 0:
            dns_score += 10
    except:
        pass

    # MX ridondanza (5)
    try:
        mx = dns.resolver.resolve(root, "MX")
        if len(list(mx)) >= 2:
            dns_score += 5
    except:
        pass

    total_score += dns_score

    # DISPLAY
    st.markdown(f"### Punteggio Totale: *{int(total_score)}/100*")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"<div class='metric-box'><b>Web</b><br>{int(web_score)}/40</div>", unsafe_allow_html=True)
    with c2:
        st.markdown(f"<div class='metric-box'><b>Email</b><br>{int(email_score)}/35</div>", unsafe_allow_html=True)
    with c3:
        st.markdown(f"<div class='metric-box'><b>DNS</b><br>{int(dns_score)}/25</div>", unsafe_allow_html=True)

    if total_score < 40:
        st.error("Livello di esposizione: *ALTO*")
    elif total_score < 70:
        st.warning("Livello di esposizione: *MEDIO*")
    else:
        st.success("Livello di esposizione: *BASSO*")