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
def tcp_connect(host: str, port: int, timeout=1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def try_banner(host: str, port: int, timeout=2.0) -> str:
    # banner best-effort: per HTTP/HTTPS mostriamo status line; per altri servizi tentiamo read
    try:
        if port in (80, 8080, 8000, 8888):
            r = http_get(f"http://{host}:{port}", timeout=timeout)
            if r:
                return f"HTTP {r.status_code}"
            return "open"
        if port in (443, 8443):
            r = http_get(f"https://{host}:{port}", timeout=timeout)
            if r:
                return f"HTTPS {r.status_code}"
            return "open"

        # altri: tentativo banner grezzo
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(120)
                if data:
                    return data.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
        return "open"
    except Exception:
        return "closed"
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
from urllib.parse import urlparse

def http_get(url: str, timeout=8):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "SecurityQuickCheck"})
        return r
    except Exception:
        return None

def head_get(url: str, timeout=8):
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "SecurityQuickCheck"})
        return r
    except Exception:
        return None

def fetch_text(url: str, max_chars=4000):
    r = http_get(url)
    if not r or r.status_code >= 400:
        return None
    txt = r.text
    return txt[:max_chars]

def check_security_txt(host: str):
    urls = [f"https://{host}/.well-known/security.txt", f"https://{host}/security.txt"]
    for u in urls:
        txt = fetch_text(u)
        if txt:
            return u, txt
    return None, None

def check_robots_sitemap(host: str):
    robots_url = f"https://{host}/robots.txt"
    robots = fetch_text(robots_url, max_chars=3000)
    sitemaps = []
    if robots:
        for line in robots.splitlines():
            if line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
    return robots_url, robots, sitemaps

def cookie_flags_from_response(resp):
    # Cerca Set-Cookie e valuta Secure/HttpOnly/SameSite
    out = []
    if not resp:
        return out
    raw = resp.headers.get("Set-Cookie")
    if not raw:
        return out

    # requests a volte concatena: gestiamo split " , " con cautela => split su "\n" non c'è
    # teniamolo semplice: lista di cookie separati da ", " se c'è "expires=" può rompere; facciamo best-effort.
    candidates = [raw]
    for c in candidates:
        c_l = c.lower()
        out.append({
            "raw": c,
            "secure": "secure" in c_l,
            "httponly": "httponly" in c_l,
            "samesite": ("samesite=" in c_l)
        })
    return out

def dns_record_exists(name: str, rtype: str):
    try:
        dns.resolver.resolve(name, rtype)
        return True
    except Exception:
        return False

def get_caa(domain_root: str):
    try:
        answers = dns.resolver.resolve(domain_root, "CAA")
        return [str(r) for r in answers]
    except Exception:
        return []

def dnssec_status(domain_root: str):
    # DNSSEC "best effort": verifica presenza record DS su zona (sul dominio stesso)
    # Se non c'è DS, probabilmente non è firmato. Non è una prova assoluta per sottodomini.
    try:
        answers = dns.resolver.resolve(domain_root, "DS")
        return True, [str(r) for r in answers]
    except Exception:
        return False, []

def mta_sts(domain_root: str):
    # MTA-STS: TXT _mta-sts.<domain> + file https://mta-sts.<domain>/.well-known/mta-sts.txt
    txts = dns_txt_records(f"_mta-sts.{domain_root}")
    rec = None
    for t in txts:
        if t.lower().startswith("v=stsv1"):
            rec = t
            break
    policy_url = f"https://mta-sts.{domain_root}/.well-known/mta-sts.txt"
    policy = fetch_text(policy_url, max_chars=3000)
    return rec, policy_url, policy

def tls_rpt(domain_root: str):
    # TLS-RPT: TXT _smtp._tls.<domain>
    txts = dns_txt_records(f"_smtp._tls.{domain_root}")
    for t in txts:
        if t.lower().startswith("v=tlsrptv1"):
            return t
    return None

def dkim_best_effort(domain_root: str):
    # DKIM selectors comuni (non invasivo): se troviamo un TXT, segnaliamo.
    selectors = ["default", "selector1", "selector2", "google", "smtp", "mail", "dkim", "s1", "s2"]
    found = []
    for s in selectors:
        name = f"{s}._domainkey.{domain_root}"
        txts = dns_txt_records(name)
        for t in txts:
            if "v=dkim1" in t.lower():
                found.append((s, t))
                break
    return found

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
status = 0
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
    info = {}
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
    # 4) DNS Hardening (DNSSEC / CAA)
    # -----------------------------
    st.markdown("## 4) DNS Hardening (DNSSEC / CAA)")

    # DNSSEC
    is_dnssec, ds_records = dnssec_status(root)
    if is_dnssec:
        st.success("✔ DNSSEC: trovato record DS (zona probabilmente firmata)")
        st.code("\n".join(ds_records))
    else:
        st.warning("⚠ DNSSEC: record DS non trovato (probabilmente NON firmato)")

    # CAA
    caa = get_caa(root)
    if caa:
        st.success("✔ CAA presente (limita chi può emettere certificati)")
        st.code("\n".join(caa))
    else:
        st.warning("⚠ CAA assente (chiunque può emettere certificati se compromessi DNS/CA)")

    # -----------------------------
    # 5) Email Hardening (DKIM / MTA-STS / TLS-RPT)
    # -----------------------------
    st.markdown("## 5) Email Hardening (DKIM / MTA-STS / TLS-RPT)")

    # DKIM best-effort
    dkim = dkim_best_effort(root)
    if dkim:
        st.success(f"✔ DKIM: trovato (best-effort) {len(dkim)} record")
        for sel, rec in dkim:
            st.write(f"Selector: *{sel}*")
            st.code(rec)
    else:
        st.warning("⚠ DKIM: non trovato nei selector comuni (potrebbe esserci con selector custom)")

    # MTA-STS
    sts_rec, sts_url, sts_policy = mta_sts(root)
    if sts_rec:
        st.success("✔ MTA-STS: record DNS trovato")
        st.code(sts_rec)
    else:
        st.warning("⚠ MTA-STS: record DNS non trovato")

    if sts_policy:
        st.success("✔ MTA-STS policy trovata")
        st.write(f"URL: {sts_url}")
        st.code(sts_policy)
    else:
        st.info("MTA-STS policy non trovata (non sempre presente o host non esiste)")

    # TLS-RPT
    rpt = tls_rpt(root)
    if rpt:
        st.success("✔ TLS-RPT: record trovato")
        st.code(rpt)
    else:
        st.warning("⚠ TLS-RPT: record non trovato")

    # -----------------------------
    # 6) Web Public Files (security.txt / robots / sitemap)
    # -----------------------------
    st.markdown("## 6) Web Public Files (security.txt / robots / sitemap)")

    # security.txt
    sec_url, sec_txt = check_security_txt(host)
    if sec_txt:
        st.success("✔ security.txt trovato")
        st.write(f"URL: {sec_url}")
        st.code(sec_txt)
    else:
        st.warning("⚠ security.txt non trovato (best practice per contatto vulnerabilità)")

    # robots + sitemap
    robots_url, robots_txt, sitemaps = check_robots_sitemap(host)
    if robots_txt:
        st.success("✔ robots.txt trovato")
        st.write(f"URL: {robots_url}")
        st.code(robots_txt)
        if sitemaps:
            st.success("✔ Sitemap dichiarate in robots.txt")
            for sm in sitemaps:
                st.write(f"- {sm}")
        else:
            st.info("Nessuna sitemap dichiarata in robots.txt")
    else:
        st.warning("⚠ robots.txt non trovato")

    # -----------------------------
    # 7) Cookie Flags (best effort)
    # -----------------------------
    st.markdown("## 7) Cookie Flags (Secure / HttpOnly / SameSite)")

    resp = http_get(f"https://{host}")
    cookies = cookie_flags_from_response(resp)

    if not resp:
        st.warning("Non riesco a leggere i cookie (host non raggiungibile).")
    elif not cookies:
        st.info("Nessun Set-Cookie visibile sulla home (può essere normale).")
    else:
        for c in cookies:
            ok = c["secure"] and c["httponly"] and c["samesite"]
            if ok:
                st.success("✔ Cookie con flag corretti (Secure + HttpOnly + SameSite)")
            else:
                st.warning("⚠ Cookie con flag migliorabili")
            st.code(c["raw"])

    # -----------------------------
    # 8) FREE Breach / Darkweb (GRATIS) - Cosa possiamo fare davvero
    # -----------------------------
    st.markdown("## 8) Data Breach / Darkweb (GRATIS) — Nota realistica")

    st.info(
        "Un vero controllo 'darkweb' serio richiede database commerciali o API a pagamento (HIBP, Intelligence vendor). "
        "Gratuitamente possiamo fare solo OSINT indiretta: hardening email (DMARC/DKIM/MTA-STS), reputazione DNS, e segnali tecnici."
    )
    # -----------------------------
    # 9) Exposure - Common Ports (best-effort)
    # -----------------------------
    st.markdown("## 9) Exposure — Porte comuni (best-effort)")

    common_ports = [
        (80, "HTTP"),
        (443, "HTTPS"),
        (21, "FTP"),
        (22, "SSH"),
        (25, "SMTP"),
        (110, "POP3"),
        (143, "IMAP"),
        (3306, "MySQL"),
        (3389, "RDP"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
        (9200, "Elasticsearch"),
        (8080, "HTTP-alt"),
        (8443, "HTTPS-alt"),
    ]

    st.info("Controllo leggero: verifica solo se la porta risponde (TCP connect). Niente scan aggressivi.")

    results = []
    for p, name in common_ports:
        is_open = tcp_connect(host, p, timeout=1.2)
        if is_open:
            banner = try_banner(host, p, timeout=2.0)
            results.append((p, name, "OPEN", banner))
        else:
            results.append((p, name, "closed", ""))

    open_any = any(r[2] == "OPEN" for r in results)
    if not open_any:
        st.success("✔ Nessuna porta comune risulta esposta (best-effort).")
    else:
        st.warning("⚠ Alcune porte comuni risultano esposte. Verifica che siano volute e protette.")

    for p, name, state, banner in results:
        if state == "OPEN":
            st.write(f"✅ *{p}* ({name}) — *OPEN*  {banner}")
        else:
            st.write(f"➖ *{p}* ({name}) — {state}")
            # -----------------------------
    # 10) Cyber Exposure Index (Score)
    # -----------------------------
    st.markdown("## 10) Cyber Exposure Index")

    # SAFE DEFAULTS
    safe_headers = headers if isinstance(headers, dict) else {}
    days_left = info.get("days_left", -1) if isinstance(info, dict) else -1

    # WEIGHTS
    web = 0       # max 40
    email = 0     # max 35
    dns = 0       # max 25

    # ---- WEB (40) ----
    # HTTPS reachable / status ok (best effort)
    if status in (200, 301, 302, 307, 308):
        web += 10

    # SSL valid (days_left > 0)
    if isinstance(days_left, int) and days_left > 0:
        web += 10

    # Headers presence (4 header -> 20 punti: 5 ciascuno)
    header_list = [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "Content-Security-Policy",
        "Referrer-Policy"
    ]
    web += min(20, sum(5 for h in header_list if h in safe_headers))

    # ---- EMAIL (35) ----
    if spf:
        email += 10

    if dmarc:
        email += 15
        dl = dmarc.lower()
        if "p=quarantine" in dl:
            email += 5
        if "p=reject" in dl:
            email += 10

    # ---- DNS (25) ----
    if is_dnssec:
        dns += 10
    if caa:
        dns += 10
    # bonus per MTA-STS + TLS-RPT (igiene email avanzata)
    if sts_rec:
        dns += 3
    if rpt:
        dns += 2

    total = web + email + dns
    if total > 100:
        total = 100

    st.markdown(f"<div class='metric-box'><b>Punteggio Totale:</b> {total}/100</div>", unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f"<div class='metric-box'><b>Web</b><br>{web}/40</div>", unsafe_allow_html=True)
    with c2:
        st.markdown(f"<div class='metric-box'><b>Email</b><br>{email}/35</div>", unsafe_allow_html=True)
    with c3:
        st.markdown(f"<div class='metric-box'><b>DNS</b><br>{dns}/25</div>", unsafe_allow_html=True)

    if total < 40:
        st.error("Livello di esposizione: *ALTO*")
    elif total < 70:
        st.warning("Livello di esposizione: *MEDIO*")
    else:
        st.success("Livello di esposizione: *BASSO*")
