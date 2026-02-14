import streamlit as st
import requests
import ssl
import socket
from datetime import datetime, timezone

import dns.resolver
import tldextract

# ------------------------------------------------
# CONFIG / UI
# ------------------------------------------------
st.set_page_config(page_title="Security Quick Check", page_icon="🛡️", layout="wide")

st.title("Security Quick Check")
st.write("Analisi basata esclusivamente su informazioni pubbliche (HTTP / DNS / SSL). Nessun test intrusivo.")
st.caption(
    "Nota: questo strumento fornisce una verifica preliminare e non sostituisce un assessment professionale completo."
)

# ------------------------------------------------
# HELPERS (PUBLIC / SAFE)
# ------------------------------------------------
def normalize_domain(d: str) -> str:
    d = (d or "").strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    return d.split("/")[0]

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
        headers={"User-Agent": "SecurityQuickCheck/1.0"},
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

# ------------------------------------------------
# INPUT
# ------------------------------------------------
domain = st.text_input("Dominio (es: azienda.it)")
go = st.button("Analizza")

# ==============================================================
# TUTTO CIÒ CHE VIENE DOPO È DENTRO IL BLOCCO DI ANALISI
# ==============================================================

if go and domain:
    host = normalize_domain(domain)
    root = apex_domain(host)

    st.markdown("---")
    st.subheader("Riepilogo")
    st.write(f"*Host:* {host}")
    st.write(f"*Dominio principale (apex):* {root}")

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
        final_url, status, headers = fetch_headers(host)
        st.write(f"*URL finale:* {final_url}")
        st.write(f"*HTTP status:* {status}")
    except Exception:
        st.error("Impossibile leggere gli header via HTTPS (host non raggiungibile / errore SSL / redirect).")

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
        info = ssl_info(host)
        if info["days_left"] is None:
            st.warning("Non riesco a determinare la scadenza del certificato.")
        elif info["days_left"] < 0:
            st.error(f"Certificato *SCADUTO* ({info['days_left']} giorni).")
        elif info["days_left"] < 30:
            st.warning(f"Certificato in scadenza: *{info['days_left']} giorni*.")
        else:
            st.success(f"Certificato valido: scade tra *{info['days_left']} giorni*.")

        if info.get("expires"):
            st.write(f"*Scadenza:* {info['expires'].strftime('%Y-%m-%d %H:%M UTC')}")
    except Exception:
        st.error("Impossibile verificare SSL (porta 443 non disponibile o handshake fallito).")

    # ------------------------------------------------
    # 3) EMAIL SECURITY (SPF / DMARC)
    # ------------------------------------------------
    st.markdown("## 3) Email Security (SPF / DMARC)")

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
        "Da usare *solo* con autorizzazione del proprietario del dominio."
    )

    advanced = st.checkbox("Modalità tecnica avanzata (richiede autorizzazione del proprietario)")

    # ------------------------------------------------
    # 7) Exposure — Porte comuni (best-effort)
    # ------------------------------------------------
    if advanced:
        st.markdown("## 7) Exposure — Porte comuni (best-effort)")
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
                st.warning(f"⚠ Porta {p} ({name}) *aperta* (best-effort)")
                open_ports += 1
            else:
                st.success(f"✔ Porta {p} ({name}) chiusa")

        if open_ports == 0:
            st.success("✔ Nessuna porta comune risulta esposta (best-effort).")
        else:
            st.warning("⚠ Alcune porte comuni risultano esposte: verifica che siano volute e protette (firewall/VPN/ACL).")

    # ------------------------------------------------
    # 8) Data Breach / Darkweb (GRATIS) — Nota realistica
    # ------------------------------------------------
    st.markdown("## 8) Data Breach / Darkweb (GRATIS) — Nota realistica")
    st.info(
        "Un controllo 'dark web' affidabile richiede tipicamente database proprietari o servizi a pagamento "
        "(es. provider intelligence / breach monitoring). "
        "Questa app non esegue interrogazioni dark web e non effettua raccolta di credenziali. "
        "Qui si mostrano solo segnali tecnici pubblici (HTTP/DNS/SSL)."
    )

    # ------------------------------------------------
    # 9) Risultati sintetici (Checklist)
    # ------------------------------------------------
    st.markdown("## 9) Checklist sintetica")

    checks_ok = 0
    checks_total = 0

    # HTTPS reachable (status “buono”)
    checks_total += 1
    if status in (200, 301, 302, 307, 308):
        st.success("✔ HTTPS raggiungibile")
        checks_ok += 1
    else:
        st.warning("⚠ HTTPS non verificato / status non atteso")

    # SSL valid
    checks_total += 1
    if isinstance(info.get("days_left"), int) and info["days_left"] > 0:
        st.success("✔ Certificato SSL valido")
        checks_ok += 1
    else:
        st.warning("⚠ SSL non valido o non verificabile")

    # SPF
    checks_total += 1
    if spf:
        st.success("✔ SPF presente")
        checks_ok += 1
    else:
        st.warning("⚠ SPF assente")

    # DMARC
    checks_total += 1
    if dmarc:
        st.success("✔ DMARC presente")
        checks_ok += 1
    else:
        st.warning("⚠ DMARC assente")

    # DNSSEC
    checks_total += 1
    if dnssec:
        st.success("✔ DNSSEC presente")
        checks_ok += 1
    else:
        st.warning("⚠ DNSSEC assente")

    # CAA
    checks_total += 1
    if caa:
        st.success("✔ CAA presente")
        checks_ok += 1
    else:
        st.warning("⚠ CAA assente")

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
    if isinstance(info.get("days_left"), int) and info["days_left"] > 0:
        web += 10
    # 4 headers => 20 punti (5 ciascuno)
    web += min(20, header_score * 5)

    # EMAIL
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
    if dnssec:
        dns_score += 10
    if caa:
        dns_score += 10

    total = web + email_score + dns_score
    total = min(total, 100)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Web", f"{web}/40")
    with c2:
        st.metric("Email", f"{email_score}/35")
    with c3:
        st.metric("DNS", f"{dns_score}/25")

    st.markdown(f"### Punteggio Totale: *{total}/100*")

    if total < 40:
        st.error("Livello di esposizione: *ALTO*")
    elif total < 70:
        st.warning("Livello di esposizione: *MEDIO*")
    else:
        st.success("Livello di esposizione: *BASSO*")
