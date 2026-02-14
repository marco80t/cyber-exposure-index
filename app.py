import streamlit as st
import requests
import ssl
import socket
import ipaddress
from datetime import datetime, timezone

import dns.resolver
import tldextract

# PDF
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


# ------------------------------------------------
# CONFIG / UI
# ------------------------------------------------
st.set_page_config(page_title="Security Quick Check", page_icon="🛡️", layout="wide")
UA = {"User-Agent": "SecurityQuickCheck/1.0"}

# ------------------------------------------------
# SIDEBAR
# ------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ Security Quick Check")
    st.caption("Verifica preliminare su dati pubblici (HTTP/DNS/SSL).")

    try:
        st.image("assets/logo.png", use_container_width=True)
    except Exception:
        pass

    st.markdown("---")
    st.markdown("### Contatti")
    st.write("📩 **security@tmconsulenza.it**")
    st.write("🌐 **tmconsulenza.it**")

    st.markdown("---")
    st.markdown("### Disclaimer")
    st.caption(
        "Tool basato su informazioni pubbliche e richieste standard. "
        "Non esegue exploit, brute-force, autenticazioni o scanning esteso. "
        "La modalità tecnica fa solo TCP connect su poche porte comuni e va usata solo con autorizzazione."
    )

# ------------------------------------------------
# MAIN
# ------------------------------------------------
st.title("Security Quick Check")
st.write("Analisi basata esclusivamente su informazioni pubbliche (HTTP / DNS / SSL). Nessun test intrusivo.")
st.caption("Nota: verifica preliminare. Non sostituisce un assessment professionale completo.")


# ------------------------------------------------
# HELPERS
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

def tls_details(host: str, port: int = 443):
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

    subject = cert.get("subject", [])
    subject_str = ", ".join("=".join(x) for item in subject for x in item) if subject else "N/D"
    issuer = cert.get("issuer", [])
    issuer_str = ", ".join("=".join(x) for item in issuer for x in item) if issuer else "N/D"

    san = cert.get("subjectAltName", [])
    san_dns = [v for (k, v) in san if k.lower() == "dns"] if san else []

    return {
        "tls_version": tls_version,
        "cipher": cipher,
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

def dnssec_enabled(domain: str):
    return len(dns_query(domain, "DS")) > 0

def get_caa(domain: str):
    return dns_query(domain, "CAA")

def tcp_connect(host: str, port: int, timeout=1.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

# -------- DKIM --------
def dkim_lookup(domain_root: str, selector: str):
    name = f"{selector}._domainkey.{domain_root}"
    txts = dns_txt(name)
    for t in txts:
        if "v=dkim1" in t.lower():
            return name, t
    return name, None

def detect_mail_provider_from_mx(mx_records: list[str]) -> str:
    """Best-effort: identifica provider guardando MX."""
    mx_l = " ".join(mx_records).lower()
    if "protection.outlook.com" in mx_l or "mail.protection.outlook.com" in mx_l or "outlook.com" in mx_l:
        return "m365"
    if "google.com" in mx_l or "googlemail.com" in mx_l:
        return "google"
    return "unknown"

def dkim_selectors_to_try(domain_root: str, mx_records: list[str]) -> list[str]:
    # base
    common = [
        "default", "selector1", "selector2", "google", "smtp", "mail", "dkim",
        "s1", "s2", "m1", "m2", "k1", "k2", "mail1", "mail2"
    ]

    provider = detect_mail_provider_from_mx(mx_records)

    if provider == "m365":
        # Microsoft 365 tipicamente usa selector1/selector2
        boosted = ["selector1", "selector2"]
    elif provider == "google":
        # Google a volte usa google._domainkey + (a volte selector personalizzati)
        boosted = ["google", "selector1", "selector2"]
    else:
        boosted = ["selector1", "selector2", "default", "google"]

    # unisci mantenendo ordine e unicità
    out = []
    for s in boosted + common:
        if s not in out:
            out.append(s)
    return out

def dkim_best_effort(domain_root: str, mx_records: list[str]):
    sels = dkim_selectors_to_try(domain_root, mx_records)
    attempts = []
    found = []
    for sel in sels:
        qname, rec = dkim_lookup(domain_root, sel)
        attempts.append(qname)
        if rec:
            found.append((sel, qname, rec))
    return found, attempts


# ------------------------------------------------
# PDF
# ------------------------------------------------
def build_pdf_report(report: dict) -> bytes:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    def line(y, text, size=10):
        c.setFont("Helvetica", size)
        c.drawString(40, y, text)

    y = h - 50
    line(y, "Security Quick Check - Report (preliminare)", 14)
    y -= 20
    line(y, f"Target: {report.get('target','')}", 11)
    y -= 14
    line(y, f"Data: {report.get('date','')}", 10)
    y -= 20

    line(y, "Disclaimer:", 11)
    y -= 12
    for chunk in report.get("disclaimer", "").split("\n"):
        line(y, chunk, 9)
        y -= 11
        if y < 80:
            c.showPage()
            y = h - 50

    y -= 10
    line(y, "Risultati principali:", 11)
    y -= 14

    for section, items in report.get("sections", {}).items():
        line(y, f"- {section}", 11)
        y -= 12
        for it in items:
            line(y, f"  • {it}", 9)
            y -= 11
            if y < 80:
                c.showPage()
                y = h - 50
        y -= 6

    c.showPage()
    c.save()
    return buf.getvalue()


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
target = st.text_input("Dominio o IP pubblico (es: tmconsulenza.it oppure 8.8.8.8)", value=st.session_state.target_value)
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

# defaults
final_url = None
status = 0
headers = {}
tls = {}
header_score = 0

spf = None
dmarc = None
mx = []
ns = []
soa = []
dnssec = False
caa = []

dkim_found = []
dkim_attempts = []
dkim_manual_record = None


# ------------------------------------------------
# 1) Security Headers
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

for hname in header_list:
    if hname in headers:
        st.success(f"✔ {hname} presente")
        header_score += 1
    else:
        st.warning(f"⚠ {hname} mancante")

st.caption(f"Punteggio headers: {header_score}/{len(header_list)}")


# ------------------------------------------------
# 2) TLS / SSL (dettagli)
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
        ciph = tls.get("cipher")
        if ciph:
            st.write(f"Cipher: **{ciph[0]}** — {ciph[1]} — {ciph[2]} bits")

        st.write(f"Issuer: {tls.get('issuer','N/D')}")
        st.write(f"Subject: {tls.get('subject','N/D')}")

        san_dns = tls.get("san_dns", [])
        if san_dns:
            st.write("SAN (DNS) principali:")
            st.code("\n".join(san_dns[:50]))

        dl = tls.get("days_left")
        if dl is None:
            st.warning("Non riesco a determinare la scadenza del certificato.")
        else:
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
# 3) Email Security (SPF / DMARC / DKIM)
# ------------------------------------------------
st.markdown("## 3) Email Security (SPF / DMARC / DKIM)")

if is_ip:
    st.info("Per IP non esistono SPF/DMARC/DKIM (sono record DNS del dominio).")
else:
    # SPF / DMARC
    spf = next((x for x in dns_txt(root) if x.lower().startswith("v=spf1")), None)
    dmarc = next((x for x in dns_txt(f"_dmarc.{root}") if x.lower().startswith("v=dmarc1")), None)

    c1, c2 = st.columns(2)
    with c1:
        if spf:
            st.success("✔ SPF presente")
            st.code(spf)
        else:
            st.warning("⚠ SPF assente (record TXT v=spf1 mancante)")
    with c2:
        if dmarc:
            st.success("✔ DMARC presente")
            st.code(dmarc)
        else:
            st.warning("⚠ DMARC assente (record TXT su _dmarc.<dominio> mancante)")

    st.markdown("---")
    st.markdown("### DKIM (auto + manuale)")
    st.caption("DKIM dipende dal selector. Qui proviamo selector comuni + dedotti dai MX, e puoi inserirne uno manuale.")

    # MX (serve per autodetect)
    mx = dns_query(root, "MX")
    if mx:
        st.write("MX rilevati (best-effort):")
        st.code("\n".join(mx[:30]))
    else:
        st.info("MX non rilevati (può essere normale se non usi posta sul dominio).")

    # DKIM auto
    dkim_found, dkim_attempts = dkim_best_effort(root, mx)

    if dkim_found:
        st.success(f"✔ DKIM trovato su {len(dkim_found)} selector (best-effort)")
        for sel, qname, rec in dkim_found[:10]:
            st.write(f"Selector: **{sel}** — `{qname}`")
            st.code(rec[:1200])
    else:
        st.warning("⚠ DKIM non trovato nei tentativi automatici (best-effort).")

    with st.expander("Mostra query DKIM tentate (debug)"):
        st.code("\n".join(dkim_attempts[:60]) if dkim_attempts else "Nessun tentativo effettuato.")

    # Manual selector
    selector = st.text_input("Selector DKIM manuale (opzionale) — esempio: selector1 / selector2 / google", value="")
    if selector.strip():
        qname, rec = dkim_lookup(root, selector.strip())
        if rec:
            st.success("✔ DKIM trovato per selector manuale")
            st.write(f"Query: `{qname}`")
            st.code(rec[:1500])
            dkim_manual_record = rec
        else:
            st.warning("⚠ Nessun record DKIM trovato per questo selector (best-effort).")
            st.write(f"Query fatta: `{qname}`")


# ------------------------------------------------
# 4) DNS Hygiene / Hardening
# ------------------------------------------------
st.markdown("## 4) DNS Hygiene / Hardening (DNSSEC / CAA / NS / SOA)")

if is_ip:
    st.info("Per IP non si applicano DNSSEC/CAA/NS/SOA (valgono per il dominio).")
else:
    dnssec = dnssec_enabled(root)
    caa = get_caa(root)
    ns = dns_query(root, "NS")
    soa = dns_query(root, "SOA")

    if dnssec:
        st.success("✔ DNSSEC: record DS trovato (best-effort)")
        st.code("\n".join(dns_query(root, "DS")))
    else:
        st.warning("⚠ DNSSEC: record DS non trovato")

    if caa:
        st.success("✔ CAA presente")
        st.code("\n".join(caa))
    else:
        st.warning("⚠ CAA assente")

    if ns:
        st.success("✔ NS rilevati")
        st.code("\n".join(ns))
    else:
        st.warning("⚠ NS non rilevati (anomalo)")

    if soa:
        st.success("✔ SOA rilevato")
        st.code("\n".join(soa))
    else:
        st.warning("⚠ SOA non rilevato (anomalo)")


# ------------------------------------------------
# 5) Limiti & Legal Safe Mode
# ------------------------------------------------
st.markdown("## 5) Limiti & Legal Safe Mode")
st.info(
    "Questo strumento usa solo dati pubblici e richieste standard (HTTP/DNS/SSL). "
    "Non esegue exploit, brute-force, autenticazioni, né scanning esteso. "
    "La modalità tecnica fa solo TCP connect su poche porte comuni ed è da usare solo con autorizzazione."
)


# ------------------------------------------------
# 6) Modalità tecnica
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
# 7) Exposure — Porte comuni
# ------------------------------------------------
st.markdown("## 7) Exposure — Porte comuni (best-effort)")

if not advanced:
    st.info("Attiva la modalità tecnica avanzata (punto 6) per visualizzare i controlli sulle porte.")
    port_results = []
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

    port_results = []
    open_ports = 0
    for p, name in common_ports:
        is_open = tcp_connect(host, p)
        port_results.append((p, name, is_open))
        if is_open:
            st.warning(f"⚠ Porta {p} ({name}) aperta (best-effort)")
            open_ports += 1
        else:
            st.success(f"✔ Porta {p} ({name}) chiusa")

    if open_ports == 0:
        st.success("✔ Nessuna porta comune risulta esposta (best-effort).")
    else:
        st.warning("⚠ Alcune porte comuni risultano esposte: verifica che siano volute e protette (firewall/VPN/ACL).")


# ------------------------------------------------
# 8) OSINT Pack (gratis, pubblico)
# ------------------------------------------------
st.markdown("## 8) OSINT Pack (pubblico / gratis)")
st.info("Sezione OSINT basata solo su risorse pubbliche. Nessun accesso non autorizzato.")


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
        st.success("✔ SPF presente"); checks_ok += 1
    else:
        st.warning("⚠ SPF assente")

    checks_total += 1
    if dmarc:
        st.success("✔ DMARC presente"); checks_ok += 1
    else:
        st.warning("⚠ DMARC assente")

    checks_total += 1
    dkim_ok = bool(dkim_found) or bool(dkim_manual_record)
    if dkim_ok:
        st.success("✔ DKIM presente (best-effort)"); checks_ok += 1
    else:
        st.warning("⚠ DKIM non rilevato (potrebbe essere su selector non testato)")

    checks_total += 1
    if dnssec:
        st.success("✔ DNSSEC presente"); checks_ok += 1
    else:
        st.warning("⚠ DNSSEC assente")

    checks_total += 1
    if caa:
        st.success("✔ CAA presente"); checks_ok += 1
    else:
        st.warning("⚠ CAA assente")

st.caption(f"Checklist: {checks_ok}/{checks_total}")


# ------------------------------------------------
# 10) Cyber Exposure Index (Score)
# ------------------------------------------------
st.markdown("## 10) Cyber Exposure Index")

web = 0
email_score = 0
dns_score = 0

if status in (200, 301, 302, 307, 308):
    web += 10
if (not is_ip) and isinstance(tls.get("days_left"), int) and tls["days_left"] > 0:
    web += 10
web += min(20, header_score * 5)

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
    if bool(dkim_found) or bool(dkim_manual_record):
        email_score += 5

    if dnssec:
        dns_score += 10
    if caa:
        dns_score += 10
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


# ------------------------------------------------
# PDF EXPORT
# ------------------------------------------------
st.markdown("---")
st.markdown("## 📄 Report PDF")

disclaimer_pdf = (
    "Report automatico basato su informazioni pubbliche (HTTP/DNS/SSL) e richieste standard. "
    "Non include test intrusivi e non sostituisce un assessment professionale completo.\n"
    "La sezione 'porte' è best-effort (TCP connect su poche porte) e va usata solo con autorizzazione."
)

dkim_summary = "N/A su IP"
if not is_ip:
    dkim_ok = bool(dkim_found) or bool(dkim_manual_record)
    dkim_summary = "PRESENTE (best-effort)" if dkim_ok else "NON RILEVATO (best-effort)"

sections = {
    "Riepilogo": [
        f"Target: {host}",
        f"Tipo: {'IP pubblico' if is_ip else 'Dominio'}",
        (f"Apex: {root}" if not is_ip else "Apex: N/A"),
    ],
    "Web / Headers": [
        f"HTTP status: {status}",
        f"Headers score: {header_score}/4",
    ],
    "TLS/SSL": [
        f"TLS version: {tls.get('tls_version','N/A') if not is_ip else 'N/A su IP'}",
        f"SSL days left: {tls.get('days_left','N/A') if not is_ip else 'N/A su IP'}",
    ],
    "Email": [
        f"SPF: {'PRESENTE' if spf else 'ASSENTE' if not is_ip else 'N/A su IP'}",
        f"DMARC: {'PRESENTE' if dmarc else 'ASSENTE' if not is_ip else 'N/A su IP'}",
        f"DKIM: {dkim_summary}",
    ],
    "DNS": [
        f"DNSSEC: {'PRESENTE' if dnssec else 'ASSENTE' if not is_ip else 'N/A su IP'}",
        f"CAA: {'PRESENTE' if (caa and not is_ip) else 'ASSENTE' if not is_ip else 'N/A su IP'}",
        f"NS: {len(ns) if not is_ip else 'N/A'}",
        f"MX: {len(mx) if not is_ip else 'N/A'}",
    ],
    "Porte (solo modalità tecnica)": [
        ("N/A (modalità tecnica non attiva)" if not advanced else f"Verificate: {len(port_results)}"),
        ("N/A" if not advanced else f"Aperte: {sum(1 for _,_,op in port_results if op)}"),
    ],
    "Score": [
        f"Cyber Exposure Index: {total}/100"
    ]
}

report_obj = {
    "target": host,
    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    "disclaimer": disclaimer_pdf,
    "sections": sections,
}

pdf_bytes = build_pdf_report(report_obj)

st.download_button(
    label="⬇️ Scarica Report PDF",
    data=pdf_bytes,
    file_name=f"security_quick_check_{host.replace(':','_')}.pdf",
    mime="application/pdf",
)

st.markdown("### Vuoi un piano di intervento completo (hardening + remediation)?")
st.write("Scrivi a **security@tmconsulenza.it** — oggetto: **Security Quick Check**")
