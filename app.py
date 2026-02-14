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

with st.expander("Disclaimer legale / uso consentito", expanded=False):
    st.markdown(
        """
- Lo strumento effettua **solo controlli passivi / best-effort** su informazioni pubbliche (HTTP/DNS/SSL) e un **semplice TCP connect** su poche porte comuni (se attivi la modalità tecnica).
- **Nessuna scansione aggressiva**, nessun brute-force, nessun tentativo di accesso, nessun exploit.
- Usa la modalità tecnica **solo con autorizzazione del proprietario** del sistema/asset.
- I risultati possono essere **incompleti** (timeout, filtri, CDN, WAF, configurazioni particolari).
        """
    )

# ------------------------------------------------
# HELPERS
# ------------------------------------------------
def is_ip_target(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

def normalize_target(d: str) -> str:
    d = (d or "").strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    d = d.split("/")[0]
    return d

def apex_domain(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname

def fetch_https(host: str):
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

    issuer = cert.get("issuer", [])
    issuer_str = ", ".join("=".join(x) for item in issuer for x in item) if issuer else "N/D"

    subject = cert.get("subject", [])
    subject_str = ", ".join("=".join(x) for item in subject for x in item) if subject else "N/D"

    return {"expires": expires, "days_left": days_left, "issuer": issuer_str, "subject": subject_str}

def dns_query(name: str, rtype: str):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        ans = resolver.resolve(name, rtype)
        return [str(r) for r in ans]
    except Exception:
        return []

def dns_txt(name: str):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        ans = resolver.resolve(name, "TXT")
        out = []
        for r in ans:
            # join fragments
            out.append("".join([p.decode("utf-8") if isinstance(p, bytes) else str(p) for p in r.strings]))
        return out
    except Exception:
        return []

def dnssec_enabled(domain: str):
    # Best-effort: DS presente => zona probabilmente firmata
    return bool(dns_query(domain, "DS"))

def get_caa(domain: str):
    return dns_query(domain, "CAA")

def find_spf(domain_root: str):
    for t in dns_txt(domain_root):
        if t.lower().startswith("v=spf1"):
            return t
    return None

def find_dmarc(domain_root: str):
    for t in dns_txt(f"_dmarc.{domain_root}"):
        if t.lower().startswith("v=dmarc1"):
            return t
    return None

def dkim_best_effort(domain_root: str):
    # DKIM: best-effort su selector comuni
    selectors = ["default", "selector1", "selector2", "google", "smtp", "mail", "dkim", "s1", "s2"]
    found = []
    for s in selectors:
        name = f"{s}._domainkey.{domain_root}"
        for t in dns_txt(name):
            if "v=dkim1" in t.lower():
                found.append((s, t))
                break
    return found

def mta_sts(domain_root: str):
    rec = None
    for t in dns_txt(f"_mta-sts.{domain_root}"):
        if t.lower().startswith("v=stsv1"):
            rec = t
            break
    return rec

def tls_rpt(domain_root: str):
    for t in dns_txt(f"_smtp._tls.{domain_root}"):
        if t.lower().startswith("v=tlsrptv1"):
            return t
    return None

def tcp_connect(host: str, port: int, timeout=1.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

# ------------------------------------------------
# SESSION STATE
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
target = st.text_input("Dominio o IP (es: tmconsulenza.it oppure 8.8.8.8)", value=st.session_state.target_value)
go = st.button("Analizza")

if go and target:
    st.session_state.analyzed = True
    st.session_state.target_value = target.strip()

if not st.session_state.analyzed or not st.session_state.target_value:
    st.info("Inserisci un dominio o IP e premi *Analizza*.")
    st.stop()

# ------------------------------------------------
# BLOCCO ANALISI
# ------------------------------------------------
raw = normalize_target(st.session_state.target_value)
is_ip = is_ip_target(raw)

host = raw
root = None

if not is_ip:
    root = apex_domain(host)

st.markdown("---")
st.subheader("Riepilogo")
st.write(f"Target: **{raw}**")
st.write(f"Tipo: **{'IP' if is_ip else 'Dominio'}**")
if root:
    st.write(f"Dominio principale (apex): **{root}**")

# Defaults
final_url = None
status = 0
headers = {}
tls = {"days_left": None, "expires": None, "issuer": "N/D", "subject": "N/D"}

spf = None
dmarc = None
mx = []
dkim_found = []
mta_sts_rec = None
tls_rpt_rec = None

dnssec = False
caa = []
ns = []
soa = []

header_score = 0

# Applicabilità
web_applicable = False
email_applicable = False   # REGOLA: SOLO SE MX PRESENTE
dns_applicable = False

possible_web = 0
possible_email = 0
possible_dns = 0

# ------------------------------------------------
# 1) SECURITY HEADERS (solo dominio, best-effort)
# ------------------------------------------------
st.markdown("## 1) Security Headers")

header_list = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
]

if is_ip:
    st.info("N/A: su IP la verifica headers HTTPS è spesso non attendibile senza hostname (SNI/virtual host).")
else:
    try:
        final_url, status, headers = fetch_https(host)
        st.write(f"URL finale: {final_url}")
        st.write(f"HTTP status: {status}")
        web_applicable = status in (200, 301, 302, 307, 308) or (final_url is not None)
    except Exception:
        st.warning("N/A: impossibile leggere headers via HTTPS (host non raggiungibile / errore SSL / redirect).")
        web_applicable = False

    if web_applicable:
        for h in header_list:
            if h in headers:
                st.success(f"✔ {h} presente")
                header_score += 1
            else:
                st.warning(f"⚠ {h} mancante")
        st.caption(f"Punteggio headers: {header_score}/{len(header_list)}")
    else:
        st.info("N/A: se il sito non risponde, non possiamo valutare headers.")

# ------------------------------------------------
# 2) SSL (solo dominio, best-effort)
# ------------------------------------------------
st.markdown("## 2) SSL Certificate")

if is_ip:
    st.info("N/A: su IP la validazione certificato è spesso non attendibile senza hostname (SNI).")
else:
    try:
        tls = ssl_info(host)
        if tls["days_left"] is None:
            st.warning("Non riesco a determinare la scadenza del certificato.")
        elif tls["days_left"] < 0:
            st.error(f"Certificato SCADUTO ({tls['days_left']} giorni).")
        elif tls["days_left"] < 30:
            st.warning(f"Certificato in scadenza: {tls['days_left']} giorni.")
        else:
            st.success(f"Certificato valido: scade tra {tls['days_left']} giorni.")

        st.write(f"Issuer: {tls.get('issuer','N/D')}")
        if tls.get("expires"):
            st.write(f"Scadenza: {tls['expires'].strftime('%Y-%m-%d %H:%M UTC')}")
    except Exception:
        st.warning("N/A: impossibile verificare SSL (porta 443 non disponibile o handshake fallito).")

# ------------------------------------------------
# 3) EMAIL SECURITY (SOLO se MX presente)
# ------------------------------------------------
st.markdown("## 3) Email Security (SPF / DMARC / DKIM)")

if is_ip:
    st.info("N/A: controlli Email richiedono un dominio.")
else:
    mx = dns_query(root, "MX")
    email_applicable = bool(mx)  # REGOLA CONFERMATA

    if not email_applicable:
        st.info("N/A: nessun record MX rilevato → il dominio probabilmente non gestisce posta (non penalizzato).")
    else:
        st.write("MX rilevati:")
        for m in mx:
            st.write(f"- {m}")

        spf = find_spf(root)
        dmarc = find_dmarc(root)
        dkim_found = dkim_best_effort(root)

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

        if dkim_found:
            st.success(f"✔ DKIM trovato (best-effort) — {len(dkim_found)} selector")
            for sel, rec in dkim_found:
                st.write(f"Selector: **{sel}**")
                st.code(rec)
        else:
            st.warning("⚠ DKIM non trovato nei selector comuni (potrebbe essere presente con selector custom).")

# ------------------------------------------------
# 4) DNS HARDENING (DNSSEC / CAA + NS/SOA)
# ------------------------------------------------
st.markdown("## 4) DNS Hardening (DNSSEC / CAA)")

if is_ip:
    st.info("N/A: controlli DNS hardening richiedono un dominio.")
else:
    ns = dns_query(root, "NS")
    soa = dns_query(root, "SOA")

    dnssec = dnssec_enabled(root)
    caa = get_caa(root)

    # DNS applicabile se risponde qualcosa di “base”
    dns_applicable = bool(ns) or bool(soa) or bool(caa) or dnssec

    if not dns_applicable:
        st.warning("N/A/Inconclusivo: DNS non risponde alle query principali (timeout / policy / errore).")
    else:
        if ns:
            st.write("NS:")
            for n in ns:
                st.write(f"- {n}")
        if soa:
            st.write("SOA:")
            for s in soa[:1]:
                st.write(f"- {s}")

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
# 5) EMAIL HARDENING (MTA-STS / TLS-RPT) SOLO SE EMAIL APPLICABILE
# ------------------------------------------------
st.markdown("## 5) Email Hardening (MTA-STS / TLS-RPT)")

if is_ip:
    st.info("N/A: richiede un dominio.")
elif not email_applicable:
    st.info("N/A: nessun MX → non applichiamo hardening email.")
else:
    mta_sts_rec = mta_sts(root)
    tls_rpt_rec = tls_rpt(root)

    if mta_sts_rec:
        st.success("✔ MTA-STS record trovato")
        st.code(mta_sts_rec)
    else:
        st.warning("⚠ MTA-STS non trovato")

    if tls_rpt_rec:
        st.success("✔ TLS-RPT record trovato")
        st.code(tls_rpt_rec)
    else:
        st.warning("⚠ TLS-RPT non trovato")

# ------------------------------------------------
# 6) REPUTATION (SAFE)
# ------------------------------------------------
st.markdown("## 6) Reputation (SAFE)")
st.info(
    "Analisi esclusivamente su configurazione tecnica pubblica. "
    "Nessun accesso a sistemi terzi, nessun test intrusivo, nessuna interrogazione dark web."
)

# ------------------------------------------------
# 7) MODALITÀ TECNICA (solo con autorizzazione)
# ------------------------------------------------
st.markdown("## 7) Modalità tecnica")
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
# 8) Exposure — Porte comuni (best-effort) [SOLO SE ADVANCED]
# ------------------------------------------------
st.markdown("## 8) Exposure — Porte comuni (best-effort)")

if not advanced:
    st.info("Attiva la modalità tecnica avanzata (punto 7) per visualizzare i controlli sulle porte.")
    open_ports = None
else:
    st.info(
        "Controllo leggero: verifica solo se la porta risponde (TCP connect). "
        "Nessuna scansione aggressiva, nessun brute-force, nessun tentativo di accesso."
    )

    common_ports = [
        (21, "FTP"),
        (22, "SSH"),
        (25, "SMTP"),
        (53, "DNS"),
        (80, "HTTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (443, "HTTPS"),
        (465, "SMTPS"),
        (587, "SMTP Submission"),
        (993, "IMAPS"),
        (995, "POP3S"),
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
# 9) Checklist sintetica (con N/A)
# ------------------------------------------------
st.markdown("## 9) Checklist sintetica")

checks_ok = 0
checks_total = 0

# WEB (solo se applicabile)
if not is_ip and web_applicable:
    checks_total += 1
    if status in (200, 301, 302, 307, 308):
        st.success("✔ HTTPS raggiungibile")
        checks_ok += 1
    else:
        st.warning("⚠ HTTPS non verificato / status non atteso")

    checks_total += 1
    if isinstance(tls.get("days_left"), int) and tls["days_left"] > 0:
        st.success("✔ Certificato SSL valido")
        checks_ok += 1
    else:
        st.warning("⚠ SSL non valido o non verificabile")
else:
    st.info("N/A: Checklist Web non applicabile (IP o sito non raggiungibile).")

# EMAIL (solo se MX)
if not is_ip and email_applicable:
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
    if dkim_found:
        st.success("✔ DKIM rilevato (best-effort)")
        checks_ok += 1
    else:
        st.warning("⚠ DKIM non rilevato (selector comuni)")
else:
    st.info("N/A: Checklist Email non applicabile (IP o nessun MX).")

# DNS (solo se applicabile)
if not is_ip and dns_applicable:
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
    st.info("N/A: Checklist DNS non applicabile (IP o DNS non conclusivo).")

if checks_total > 0:
    st.caption(f"Checklist: {checks_ok}/{checks_total}")
else:
    st.caption("Checklist: N/A")

# ------------------------------------------------
# 10) CYBER EXPOSURE INDEX (NORMALIZZATO)
# ------------------------------------------------
st.markdown("## 10) Cyber Exposure Index (normalizzato)")

web = 0
email_score = 0
dns_score = 0

possible_web = 0
possible_email = 0
possible_dns = 0

# WEB (40) solo se applicabile e non IP
if (not is_ip) and web_applicable:
    possible_web = 40
    if status in (200, 301, 302, 307, 308):
        web += 10
    if isinstance(tls.get("days_left"), int) and tls["days_left"] > 0:
        web += 10
    web += min(20, header_score * 5)

# EMAIL (35) solo se MX
if (not is_ip) and email_applicable:
    possible_email = 35
    if spf:
        email_score += 10
    if dmarc:
        email_score += 15
        dl = dmarc.lower()
        if "p=quarantine" in dl:
            email_score += 5
        if "p=reject" in dl:
            email_score += 10
    if dkim_found:
        email_score += 5  # piccolo bonus

# DNS (25) solo se applicabile
if (not is_ip) and dns_applicable:
    possible_dns = 25
    if dnssec:
        dns_score += 10
    if caa:
        dns_score += 10
    if email_applicable and mta_sts_rec:
        dns_score += 3
    if email_applicable and tls_rpt_rec:
        dns_score += 2

earned = web + email_score + dns_score
possible = possible_web + possible_email + possible_dns

if possible == 0:
    total = 0
    st.warning("Dati insufficienti: non è stato possibile eseguire controlli affidabili sul target.")
else:
    total = round((earned / possible) * 100)

c1, c2, c3 = st.columns(3)
with c1:
    st.metric("Web", f"{web}/{possible_web}" if possible_web else "N/A")
with c2:
    st.metric("Email", f"{email_score}/{possible_email}" if possible_email else "N/A")
with c3:
    st.metric("DNS", f"{dns_score}/{possible_dns}" if possible_dns else "N/A")

st.markdown(f"### Punteggio Totale: **{total}/100**")

# Rischio: solo se abbastanza coverage
if possible < 40:
    st.info("Valutazione non conclusiva: pochi controlli applicabili (servizi non esposti o non raggiungibili).")
else:
    if total < 40:
        st.error("Livello di esposizione: **ALTO**")
    elif total < 70:
        st.warning("Livello di esposizione: **MEDIO**")
    else:
        st.success("Livello di esposizione: **BASSO**")
