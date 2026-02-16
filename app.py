import streamlit as st
import requests
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
import dns.resolver
import tldextract
import re

# ============================================================
# CONFIG
# ============================================================
st.set_page_config(page_title="Security Quick Check Pro", page_icon="🛡️", layout="wide")

CONTACT_SITE = "tmconsulenza.it"
CONTACT_MAIL = "info@tmconsulenza.it"

# ============================================================
# MATRIX UI / CSS (SIDEBAR LEGGIBILE + CONTRASTO)
# ============================================================
def apply_matrix_style():
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(circle at 20% 10%, rgba(0,255,136,0.12) 0%, transparent 40%),
                radial-gradient(circle at 80% 20%, rgba(0,255,136,0.08) 0%, transparent 40%),
                linear-gradient(rgba(0,0,0,0.88), rgba(0,0,0,0.92)),
                url("assets/bg.png");
            background-size: cover;
            background-position: center;
            background-attachment: fixed;
        }
        .stApp:before {
            content: "";
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image:
                linear-gradient(to right, rgba(0,255,136,0.06) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(0,255,136,0.05) 1px, transparent 1px);
            background-size: 60px 60px;
            opacity: 0.18;
            z-index: 0;
        }
        section.main > div { position: relative; z-index: 1; }

        /* SIDEBAR */
        [data-testid="stSidebar"] {
            background: rgba(8, 14, 11, 0.96) !important;
            border-right: 1px solid rgba(0,255,136,0.22);
        }
        [data-testid="stSidebar"] * { color: rgba(235,255,245,0.92) !important; }
        [data-testid="stSidebar"] a { color: #00ff88 !important; }
        [data-testid="stSidebar"] .stMarkdown h1,
        [data-testid="stSidebar"] .stMarkdown h2,
        [data-testid="stSidebar"] .stMarkdown h3 {
            color: #00ff88 !important;
            text-shadow: 0 0 10px rgba(0,255,136,0.45);
        }
        [data-testid="stSidebar"] hr { border-color: rgba(0,255,136,0.18) !important; }

        /* GLOBAL TEXT */
        html, body, [class*="st-"], .stMarkdown, .stText, .stCaption, .stWrite {
            color: rgba(235,255,245,0.92) !important;
        }
        h1, h2, h3, h4 {
            color: #00ff88 !important;
            text-shadow: 0 0 12px rgba(0,255,136,0.55);
        }
        .small { opacity: 0.85; font-size: 0.92rem; }

        /* GLASS */
        .glass {
            padding: 16px 18px;
            border-radius: 14px;
            border: 1px solid rgba(0,255,136,0.28);
            background: rgba(10, 18, 14, 0.58);
            box-shadow: 0 0 30px rgba(0,255,136,0.10);
            backdrop-filter: blur(10px);
        }
        .glass * { color: rgba(235,255,245,0.94) !important; }

        /* METRICS */
        [data-testid="stMetric"] {
            background: rgba(10, 18, 14, 0.58) !important;
            border: 1px solid rgba(0,255,136,0.28) !important;
            border-radius: 14px !important;
            padding: 12px !important;
        }

        /* INPUTS */
        .stTextInput label { color: rgba(235,255,245,0.85) !important; }
        .stTextInput input {
            color: rgba(235,255,245,0.95) !important;
            border-radius: 10px !important;
            border: 1px solid rgba(0,255,136,0.28) !important;
            background: rgba(10, 18, 14, 0.58) !important;
        }

        /* TABS */
        button[data-baseweb="tab"] {
            border-radius: 999px !important;
            margin-right: 8px;
            border: 1px solid rgba(0,255,136,0.22) !important;
            background: rgba(10, 18, 14, 0.35) !important;
            color: rgba(235,255,245,0.92) !important;
        }
        button[data-baseweb="tab"][aria-selected="true"] {
            background: rgba(0,255,136,0.14) !important;
            box-shadow: 0 0 18px rgba(0,255,136,0.20) !important;
        }

        /* BUTTONS */
        .stButton>button {
            background: linear-gradient(135deg, #00ff88, #00cc6a);
            color: #06120b !important;
            border-radius: 10px;
            font-weight: 900;
            border: 0;
            box-shadow: 0 0 18px rgba(0,255,136,0.22);
        }
        .stButton>button:hover {
            filter: brightness(1.05);
            box-shadow: 0 0 26px rgba(0,255,136,0.32);
        }

        /* RADAR */
        .radar {
            width: 180px; height: 180px;
            border-radius: 999px;
            border: 1px solid rgba(0,255,136,0.35);
            background:
              radial-gradient(circle, rgba(0,255,136,0.12) 0%, rgba(0,255,136,0.03) 35%, transparent 70%),
              conic-gradient(#00ff88 var(--p), rgba(255,255,255,0.07) 0);
            box-shadow: 0 0 35px rgba(0,255,136,0.10);
            position: relative;
            display:flex; align-items:center; justify-content:center;
        }
        .radar:after{
            content:"";
            position:absolute; inset:14px;
            border-radius:999px;
            border:1px dashed rgba(0,255,136,0.20);
        }
        .radar span{
            font-size: 2rem;
            font-weight: 900;
            color:#00ff88 !important;
            text-shadow: 0 0 10px rgba(0,255,136,0.45);
        }

        /* REMEDIATION CARDS */
        .fix-card {
            padding: 14px 16px;
            border-radius: 14px;
            border: 1px solid rgba(0,255,136,0.22);
            background: rgba(10, 18, 14, 0.52);
            margin-bottom: 12px;
        }
        .fix-title { font-weight: 900; color: #00ff88; }
        .fix-meta { opacity: 0.85; font-size: 0.90rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )

apply_matrix_style()

# ============================================================
# HELPERS
# ============================================================
def is_ip_target(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

def normalize_target(v: str) -> str:
    v = (v or "").strip().lower()
    v = v.replace("https://", "").replace("http://", "")
    return v.split("/")[0]

def apex_domain(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname

def dns_query(name: str, rtype: str):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        return [str(r) for r in resolver.resolve(name, rtype)]
    except Exception:
        return []

def dns_txt(name: str):
    try:
        ans = dns.resolver.resolve(name, "TXT")
        out = []
        for r in ans:
            out.append("".join([p.decode("utf-8") if isinstance(p, bytes) else str(p) for p in r.strings]))
        return out
    except Exception:
        return []

def fetch_https(host: str):
    r = requests.get(
        f"https://{host}",
        timeout=10,
        allow_redirects=True,
        headers={"User-Agent": "SecurityQuickCheckPro/1.0"},
    )
    return r.url, r.status_code, r.headers, r

def ssl_info(host: str):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            tls_ver = ssock.version()
    not_after = cert.get("notAfter")
    expires = None
    days_left = None
    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
    issuer = ", ".join("=".join(x) for item in cert.get("issuer", []) for x in item) if cert.get("issuer") else "N/D"
    san = [v for t, v in cert.get("subjectAltName", []) if t.lower() == "dns"]
    return {"expires": expires, "days_left": days_left, "issuer": issuer, "tls": tls_ver, "san": san}

def tcp_connect(host: str, port: int, timeout=1.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def best_effort_dkim(root: str, selector: str = ""):
    selectors = [selector.strip()] if selector.strip() else ["default", "selector1", "selector2", "google", "k1", "mail", "s1", "s2"]
    found = []
    for s in selectors:
        name = f"{s}._domainkey.{root}"
        txts = dns_txt(name)
        for t in txts:
            if "v=dkim1" in t.lower():
                found.append((s, t))
    return found

# ============================================================
# CVE (BEST-EFFORT) via NVD keyword search
# ============================================================
def extract_version_tokens(headers: dict) -> list:
    """
    Estrae candidati "prodotto/versione" da Server e X-Powered-By.
    Esempi: "nginx/1.18.0", "Apache/2.4.49", "PHP/8.1.2"
    """
    tokens = []
    for k in ["Server", "X-Powered-By"]:
        v = headers.get(k)
        if not v:
            continue
        # prendi pattern tipo word/1.2.3
        for m in re.findall(r"([A-Za-z][A-Za-z0-9\-\_]+)\/(\d+(?:\.\d+){1,3})", v):
            prod, ver = m
            tokens.append(f"{prod} {ver}")
    # dedup
    out = []
    for t in tokens:
        if t not in out:
            out.append(t)
    return out[:3]  # limitiamo (performance)

@st.cache_data(ttl=3600, show_spinner=False)
def nvd_cve_keyword_search(query: str, limit: int = 6):
    """
    NVD API v2: keywordSearch
    Ritorna una lista di CVE (id, desc breve, severity se presente, url).
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": query,
        "resultsPerPage": limit,
    }
    try:
        r = requests.get(url, params=params, timeout=10)
        if r.status_code == 429:
            return {"error": "Rate limit NVD (429). Riprova tra poco."}
        if r.status_code >= 400:
            return {"error": f"Errore NVD ({r.status_code})."}
        data = r.json()
        items = []
        for it in data.get("vulnerabilities", [])[:limit]:
            cve = it.get("cve", {})
            cve_id = cve.get("id")
            # descrizione
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            if not desc and cve.get("descriptions"):
                desc = cve["descriptions"][0].get("value", "")
            desc = (desc or "").strip()
            if len(desc) > 180:
                desc = desc[:180] + "…"

            # severity (best-effort)
            sev = None
            metrics = cve.get("metrics", {})
            # prova CVSS v3.1 / v3.0 / v2
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    try:
                        sev = metrics[key][0].get("cvssData", {}).get("baseSeverity")
                    except Exception:
                        pass
                    if sev:
                        break

            items.append({
                "id": cve_id,
                "desc": desc,
                "severity": sev,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None
            })
        return {"items": items}
    except Exception:
        return {"error": "NVD non raggiungibile (timeout o blocco rete)."}

# ============================================================
# REMEDIATION ENGINE (CWE/OWASP + FIX + CTA)
# ============================================================
def add_finding(findings: list, key: str, title: str, severity: str, why: str, cwe: str, owasp: str, fix: str):
    findings.append({
        "key": key,
        "title": title,
        "severity": severity,  # LOW / MEDIUM / HIGH
        "why": why,
        "cwe": cwe,
        "owasp": owasp,
        "fix": fix
    })

def severity_badge(sev: str) -> str:
    sev = (sev or "").upper()
    if sev == "HIGH":
        return "🔴 HIGH"
    if sev == "MEDIUM":
        return "🟠 MEDIUM"
    return "🟢 LOW"

def render_remediation(findings: list):
    st.markdown("## Raccomandazioni & Remediation")
    if not findings:
        st.success("Ottimo: non risultano misconfigurazioni evidenti nei controlli attivi.")
        st.info(f"Per un assessment completo (WAF, hardening server, app security), contattami: {CONTACT_MAIL}")
        return

    for f in findings:
        st.markdown(
            f"""
            <div class="fix-card">
              <div class="fix-title">{severity_badge(f["severity"])} — {f["title"]}</div>
              <div class="fix-meta"><b>CWE:</b> {f["cwe"]} &nbsp;&nbsp; <b>OWASP:</b> {f["owasp"]}</div>
              <div style="margin-top:8px;"><b>Rischio:</b> {f["why"]}</div>
              <div style="margin-top:8px;"><b>Come risolvere:</b><br>{f["fix"]}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")
    st.markdown("### Vuoi sistemarlo in modo professionale?")
    st.markdown(
        f"""
        <div class="glass">
          <div style="font-weight:900; font-size:1.05rem;">📩 Contattami per la remediation</div>
          <div class="small">
            • Email: <a href="mailto:{CONTACT_MAIL}">{CONTACT_MAIL}</a><br>
            • Sito: <a href="https://{CONTACT_SITE}" target="_blank">{CONTACT_SITE}</a><br>
            • Posso fornire: hardening + policy headers + mail security (SPF/DMARC/DKIM) + report PDF per compliance.
          </div>
        </div>
        """,
        unsafe_allow_html=True
    )

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("## 🛡️ Security Quick Check Pro")
    try:
        st.image("assets/logo.png", use_container_width=True)
    except Exception:
        pass

    st.markdown("Verifica **passiva / best-effort** su dati pubblici (HTTP / DNS / SSL).")
    st.markdown("---")
    st.markdown("### Contatti")
    st.markdown(f"🌐 **Sito:** {CONTACT_SITE}")
    st.markdown(f"📩 **Email:** {CONTACT_MAIL}")
    st.markdown("---")
    st.markdown("### Note legali")
    st.markdown(
        "<div class='small'>"
        "• Controlli basati su informazioni pubbliche.<br>"
        "• Modalità porte solo con autorizzazione del proprietario.<br>"
        "• Nessun brute-force, nessun accesso, nessun exploit."
        "</div>",
        unsafe_allow_html=True,
    )
    st.markdown("---")
    advanced_ports = st.toggle("Abilita modalità tecnica (porte)", value=False)

    st.markdown("### DKIM (best-effort)")
    dkim_selector = st.text_input("Selector DKIM (opz.)", value="", placeholder="es: selector1")

    st.markdown("---")
    cve_mode = st.toggle("CVE Intelligence (best-effort)", value=True)
    st.caption("Mostra CVE SOLO se viene rilevata una versione da header (Server/X-Powered-By).")

# ============================================================
# STATE
# ============================================================
if "analyzed" not in st.session_state:
    st.session_state.analyzed = False
if "target_value" not in st.session_state:
    st.session_state.target_value = ""

# ============================================================
# HEADER
# ============================================================
st.markdown(
    """
    <div class="glass">
      <h1 style="margin:0;">Security Quick Check Pro</h1>
      <div class="small">Analisi su dati pubblici. Nessun test intrusivo. Modalità tecnica solo con autorizzazione.</div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.write("")

# ============================================================
# INPUT
# ============================================================
c_in1, c_in2 = st.columns([5, 1])
with c_in1:
    target_input = st.text_input(
        "Inserisci Dominio o IP pubblico",
        value=st.session_state.target_value,
        placeholder=f"es: {CONTACT_SITE} oppure 1.2.3.4",
    )
with c_in2:
    go = st.button("Analizza", use_container_width=True)

if go and target_input:
    st.session_state.analyzed = True
    st.session_state.target_value = target_input.strip()

if not st.session_state.analyzed or not st.session_state.target_value:
    st.info("Inserisci un dominio/IP e premi **Analizza**.")
    st.stop()

# ============================================================
# NORMALIZE TARGET
# ============================================================
raw = normalize_target(st.session_state.target_value)
is_ip = is_ip_target(raw)

host = raw
root = apex_domain(host) if not is_ip else None

resolved_ip = None
if is_ip:
    resolved_ip = host
else:
    a_records = dns_query(host, "A")
    if a_records:
        resolved_ip = a_records[0]

# ============================================================
# SUMMARY
# ============================================================
st.markdown("### Riepilogo")
sumc1, sumc2 = st.columns(2)
with sumc1:
    st.markdown('<div class="glass">', unsafe_allow_html=True)
    st.write(f"**Target:** {host}")
    st.write(f"**Tipo:** {'IP' if is_ip else 'Dominio'}")
    st.markdown("</div>", unsafe_allow_html=True)
with sumc2:
    st.markdown('<div class="glass">', unsafe_allow_html=True)
    st.write(f"**Apex:** {root if root else '—'}")
    st.write(f"**IP risolto:** {resolved_ip if resolved_ip else '—'}")
    st.markdown("</div>", unsafe_allow_html=True)

st.write("")
tab_web, tab_email, tab_dns, tab_remed, tab_score = st.tabs(
    ["🌐 Web", "📧 Email", "🧬 DNS", "🛠️ Fix", "📊 Score"]
)

# ============================================================
# ANALYSIS VARS
# ============================================================
findings = []

status = None
final_url = None
headers = {}
ssl_data = None
header_score = 0

spf = None
dmarc = None
mx = []
dkim_found = []

dnssec = False
caa = []

version_tokens = []  # per CVE

# ============================================================
# TAB WEB
# ============================================================
with tab_web:
    st.markdown("## Web Reachability & Security Headers")
    if is_ip:
        st.info("Per IP: la parte Web completa richiede un hostname (dominio).")
    else:
        try:
            final_url, status, headers, resp = fetch_https(host)
            st.success(f"HTTPS raggiungibile — Status: {status}")
            st.write(f"URL finale: **{final_url}**")

            # raccogli token versione per CVE
            version_tokens = extract_version_tokens(headers)

            st.markdown("### Security Headers (best-effort)")
            security_headers = [
                ("Strict-Transport-Security", "HSTS", "Protegge da downgrade HTTP→HTTPS"),
                ("Content-Security-Policy", "CSP", "Riduce XSS / injection lato browser"),
                ("X-Frame-Options", "XFO", "Riduce clickjacking"),
                ("X-Content-Type-Options", "XCTO", "Riduce MIME sniffing"),
                ("Referrer-Policy", "Referrer-Policy", "Riduce leakage informazioni referrer"),
            ]

            header_score = 0
            for h, label, desc in security_headers:
                if h in headers:
                    st.success(f"✔ {label} presente — {h}")
                    header_score += 1
                else:
                    st.warning(f"⚠ {label} mancante — {h} ({desc})")

                    # Remediation mapping (CWE/OWASP)
                    if h == "Content-Security-Policy":
                        add_finding(
                            findings, "missing_csp",
                            "Content-Security-Policy mancante",
                            "MEDIUM",
                            "Aumenta superficie XSS / injection lato browser.",
                            "CWE-79",
                            "A03:2021 Injection",
                            "Imposta una CSP baseline (es: `default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'`) e poi affinala in base alle risorse reali."
                        )
                    elif h == "X-Frame-Options":
                        add_finding(
                            findings, "missing_xfo",
                            "X-Frame-Options mancante",
                            "MEDIUM",
                            "Possibile clickjacking (embedding in iframe).",
                            "CWE-1021",
                            "A05:2021 Security Misconfiguration",
                            "Aggiungi `X-Frame-Options: DENY` oppure `SAMEORIGIN`. Meglio: usa CSP `frame-ancestors 'none'`."
                        )
                    elif h == "Strict-Transport-Security":
                        add_finding(
                            findings, "missing_hsts",
                            "HSTS mancante",
                            "LOW",
                            "Rischio downgrade/SSL-strip in scenari specifici.",
                            "CWE-319",
                            "A02:2021 Cryptographic Failures",
                            "Aggiungi `Strict-Transport-Security: max-age=15552000; includeSubDomains` (valuta preload dopo test)."
                        )
                    elif h == "X-Content-Type-Options":
                        add_finding(
                            findings, "missing_xcto",
                            "X-Content-Type-Options mancante",
                            "LOW",
                            "Maggior rischio di MIME sniffing su risorse statiche.",
                            "CWE-16",
                            "A05:2021 Security Misconfiguration",
                            "Aggiungi `X-Content-Type-Options: nosniff`."
                        )
                    elif h == "Referrer-Policy":
                        add_finding(
                            findings, "missing_refpol",
                            "Referrer-Policy mancante",
                            "LOW",
                            "Possibile leakage URL/path verso terze parti.",
                            "CWE-200",
                            "A01:2021 Broken Access Control",
                            "Aggiungi `Referrer-Policy: strict-origin-when-cross-origin` (o policy più restrittiva se compatibile)."
                        )

            leak = []
            server = headers.get("Server")
            powered = headers.get("X-Powered-By")

            if server:
                leak.append(f"Server: {server}")
            if powered:
                leak.append(f"X-Powered-By: {powered}")

            if leak:
                st.warning("Possibile **information leakage**: " + " | ".join(leak))
                add_finding(
                    findings, "version_leak",
                    "Information Leakage (Server/X-Powered-By)",
                    "LOW",
                    "Espone stack/tecnologie; utile per fingerprinting. Le CVE hanno senso solo con versione confermata.",
                    "CWE-200",
                    "A05:2021 Security Misconfiguration",
                    "Rimuovi o normalizza gli header (`server_tokens off` su Nginx, config su Apache/IIS/framework)."
                )
            else:
                st.success("Nessun header tipico di leakage rilevato.")

            # ---------------- CVE SECTION ----------------
            st.markdown("---")
            st.markdown("## CVE Intelligence (best-effort)")
            st.caption("Mostrata SOLO se rilevo prodotto/versione da header. Indicativo: va confermato con inventario/scan autorizzato.")

            if not cve_mode:
                st.info("CVE disattivate (toggle in sidebar).")
            else:
                if not version_tokens:
                    st.info("Nessuna versione rilevata negli header (quindi niente CVE).")
                    st.caption("Suggerimento: spesso le versioni sono nascoste: è una buona pratica.")
                else:
                    st.write("Versioni rilevate (best-effort):")
                    for vt in version_tokens:
                        st.code(vt)

                    for vt in version_tokens:
                        with st.spinner(f"Cerco CVE per: {vt} (NVD) ..."):
                            res = nvd_cve_keyword_search(vt, limit=6)

                        if res.get("error"):
                            st.warning(f"{vt}: {res['error']}")
                            continue

                        items = res.get("items", [])
                        if not items:
                            st.info(f"{vt}: nessuna CVE trovata via keywordSearch (non significa 'zero vulnerabilità').")
                            continue

                        st.markdown(f"### Risultati per **{vt}**")
                        for it in items:
                            sev = it.get("severity") or "N/D"
                            cid = it.get("id") or "CVE-N/D"
                            desc = it.get("desc") or ""
                            url = it.get("url") or ""
                            st.write(f"- **{cid}** (Severity: **{sev}**) — {desc}")
                            if url:
                                st.caption(url)

        except Exception:
            st.error("Impossibile analizzare via HTTPS (host non raggiungibile / TLS / redirect).")
            add_finding(
                findings, "https_unreachable",
                "HTTPS non verificabile",
                "MEDIUM",
                "Il servizio HTTPS non risponde o handshake fallisce. Potrebbe essere downtime, WAF, geo-block o config TLS.",
                "CWE-319",
                "A02:2021 Cryptographic Failures",
                "Verifica DNS, certificato, catena, TLS policy e reachability. Se vuoi, posso fare troubleshooting e fix."
            )

    st.markdown("---")
    st.markdown("## SSL / TLS (best-effort)")
    try:
        ssl_data = ssl_info(host)
        if ssl_data["days_left"] is None:
            st.warning("Scadenza certificato non determinabile.")
        elif ssl_data["days_left"] < 0:
            st.error(f"Certificato **SCADUTO** ({ssl_data['days_left']} giorni).")
            add_finding(
                findings, "ssl_expired",
                "Certificato SSL scaduto",
                "HIGH",
                "Servizio non trusted: rischio MITM e interruzioni.",
                "CWE-295",
                "A02:2021 Cryptographic Failures",
                "Rinnova subito il certificato (ACME/Let's Encrypt o CA), verifica catena e auto-renew."
            )
        elif ssl_data["days_left"] < 30:
            st.warning(f"Certificato in scadenza: **{ssl_data['days_left']} giorni**.")
            add_finding(
                findings, "ssl_expiring",
                "Certificato SSL in scadenza",
                "MEDIUM",
                "Rischio outage e warning browser a breve.",
                "CWE-295",
                "A02:2021 Cryptographic Failures",
                "Configura rinnovo automatico e monitoraggio scadenza (alert 30/14/7 giorni)."
            )
        else:
            st.success(f"Certificato valido: scade tra **{ssl_data['days_left']} giorni**.")

        if ssl_data.get("expires"):
            st.write(f"Scadenza: **{ssl_data['expires'].strftime('%Y-%m-%d %H:%M UTC')}**")
        st.write(f"TLS: **{ssl_data.get('tls','N/D')}**")
        st.write(f"Issuer: **{ssl_data.get('issuer','N/D')}**")
    except Exception:
        st.error("Impossibile verificare SSL (porta 443 non disponibile o handshake fallito).")

    st.markdown("---")
    st.markdown("## Modalità tecnica (porte) — solo con autorizzazione")
    if not advanced_ports:
        st.info("Attiva **“Abilita modalità tecnica (porte)”** nella sidebar per mostrare la sezione.")
    else:
        st.warning("Best-effort: TCP connect su poche porte. Nessuno scan aggressivo.")
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
                st.warning(f"⚠ Porta {p} ({name}) **aperta** (best-effort)")
                open_ports += 1
            else:
                st.success(f"✔ Porta {p} ({name}) chiusa")

        if open_ports > 0:
            add_finding(
                findings, "ports_exposed",
                "Porte comuni esposte",
                "MEDIUM",
                "Servizi esposti aumentano superficie d’attacco (brute-force e CVE su servizi reali).",
                "CWE-284",
                "A05:2021 Security Misconfiguration",
                "Chiudi porte non necessarie, limita via firewall, abilita VPN/ACL, MFA dove possibile (es. SSH), rate-limit e monitoring."
            )

# ============================================================
# TAB EMAIL
# ============================================================
with tab_email:
    st.markdown("## Email Security (MX / SPF / DMARC / DKIM best-effort)")
    if is_ip:
        st.info("Per IP: la sezione email non è applicabile senza dominio.")
    else:
        mx = dns_query(root, "MX")
        if mx:
            st.success(f"MX trovati: {len(mx)}")
            st.code("\n".join(mx))
        else:
            st.info("Nessun record MX: il dominio potrebbe non gestire posta (NON è un fail di sicurezza).")

        txts = dns_txt(root)
        spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
        dmarc = next((t for t in dns_txt(f"_dmarc.{root}") if t.lower().startswith("v=dmarc1")), None)

        st.markdown("### SPF")
        if spf:
            st.success("✔ SPF presente")
            st.code(spf)
        else:
            st.warning("⚠ SPF assente (se il dominio invia email è un rischio spoofing)")
            if mx:
                add_finding(
                    findings, "missing_spf",
                    "SPF mancante (dominio con MX)",
                    "HIGH",
                    "Senza SPF, aumenta rischio spoofing e phishing usando il tuo dominio.",
                    "CWE-290",
                    "A07:2021 Identification and Authentication Failures",
                    "Aggiungi record TXT SPF coerente con i tuoi provider (es. Microsoft 365 / Google / SMTP relay)."
                )

        st.markdown("### DMARC")
        if dmarc:
            st.success("✔ DMARC presente")
            st.code(dmarc)
            dl = dmarc.lower()
            if "p=none" in dl:
                add_finding(
                    findings, "dmarc_p_none",
                    "DMARC in monitor (p=none)",
                    "MEDIUM",
                    "DMARC monitora ma non blocca abusi (spoofing).",
                    "CWE-290",
                    "A07:2021 Identification and Authentication Failures",
                    "Passa gradualmente a `p=quarantine` e poi `p=reject` dopo aver controllato report e allineamenti SPF/DKIM."
                )
        else:
            st.warning("⚠ DMARC assente (se il dominio invia email, mancano policy e reporting)")
            if mx:
                add_finding(
                    findings, "missing_dmarc",
                    "DMARC mancante (dominio con MX)",
                    "HIGH",
                    "Senza DMARC manca enforcement e reporting anti-spoofing.",
                    "CWE-290",
                    "A07:2021 Identification and Authentication Failures",
                    "Aggiungi `_dmarc` con `v=DMARC1; p=none; rua=mailto:<report@...>` poi hardening fino a quarantine/reject."
                )

        st.markdown("### DKIM (best-effort)")
        dkim_found = best_effort_dkim(root, dkim_selector)
        if dkim_found:
            st.success(f"✔ DKIM trovato ({len(dkim_found)} record)")
            for sel, rec in dkim_found[:6]:
                st.write(f"Selector: **{sel}**")
                st.code(rec)
        else:
            st.info("DKIM non rilevato (può essere perché il selector è diverso).")
            if mx:
                add_finding(
                    findings, "dkim_not_found",
                    "DKIM non rilevato (best-effort)",
                    "MEDIUM",
                    "Se il dominio invia email, DKIM aiuta deliverability e anti-spoofing.",
                    "CWE-290",
                    "A07:2021 Identification and Authentication Failures",
                    "Verifica provider mail e selector DKIM. Posso configurarlo su Microsoft 365/Google/SMTP e validare allineamento DMARC."
                )

# ============================================================
# TAB DNS
# ============================================================
with tab_dns:
    st.markdown("## DNS Hardening (DNSSEC / CAA)")
    if is_ip:
        st.info("Per IP: DNSSEC/CAA non applicabili senza dominio.")
    else:
        dnssec = True if dns_query(root, "DS") else False
        caa = dns_query(root, "CAA")

        if dnssec:
            st.success("✔ DNSSEC: record DS trovato (best-effort)")
        else:
            st.warning("⚠ DNSSEC: record DS non trovato")
            add_finding(
                findings, "dnssec_off",
                "DNSSEC assente",
                "LOW",
                "Maggiore rischio di attacchi DNS (spoof/poisoning) in scenari specifici.",
                "CWE-345",
                "A08:2021 Software and Data Integrity Failures",
                "Valuta abilitazione DNSSEC presso registrar/DNS provider (attenzione: gestione chiavi e rotazione)."
            )

        if caa:
            st.success("✔ CAA presente")
            st.code("\n".join(caa))
        else:
            st.warning("⚠ CAA assente")
            add_finding(
                findings, "caa_missing",
                "CAA mancante",
                "LOW",
                "Senza CAA, qualunque CA potrebbe emettere certificati (se compromesse altre condizioni).",
                "CWE-295",
                "A02:2021 Cryptographic Failures",
                "Aggiungi record CAA per limitare le CA autorizzate (es. letsencrypt.org / digicert.com)."
            )

# ============================================================
# TAB REMEDIATION
# ============================================================
with tab_remed:
    render_remediation(findings)

# ============================================================
# TAB SCORE (NORMALIZZATO + NON PUNISCE MODULI NON APPLICABILI)
# ============================================================
with tab_score:
    st.markdown("## Cyber Exposure Index (best-effort)")

    WEB_W = 40
    EMAIL_W = 35
    DNS_W = 25

    score = 0
    weight_total = 0

    # WEB applicabile se dominio
    if not is_ip:
        weight_total += WEB_W
        web_points = 0
        if status in (200, 301, 302, 307, 308):
            web_points += 10
        if ssl_data and isinstance(ssl_data.get("days_left"), int) and ssl_data["days_left"] > 0:
            web_points += 10
        web_points += min(20, header_score * 4)
        score += min(WEB_W, web_points)

    # EMAIL applicabile solo se segnali mail
    email_applicable = (not is_ip) and (bool(mx) or bool(spf) or bool(dmarc) or bool(dkim_found))
    if email_applicable:
        weight_total += EMAIL_W
        ep = 0
        if spf: ep += 10
        if dmarc:
            ep += 15
            dl = dmarc.lower()
            if "p=quarantine" in dl: ep += 5
            if "p=reject" in dl: ep += 10
        if dkim_found: ep += 10
        score += min(EMAIL_W, ep)

    # DNS applicabile se dominio
    if not is_ip:
        weight_total += DNS_W
        dp = 0
        if dnssec: dp += 10
        if caa: dp += 10
        score += min(DNS_W, dp)

    if weight_total == 0:
        st.info("Score non calcolabile per questo target (mancano moduli applicabili).")
        st.stop()

    final = int(round((score / weight_total) * 100))

    st.markdown(
        f"""
        <div class="glass" style="display:flex; gap:22px; align-items:center; justify-content:space-between; flex-wrap:wrap;">
          <div>
            <div class="small">Punteggio normalizzato sui moduli applicabili</div>
            <h2 style="margin:6px 0 0 0;">{final}/100</h2>
            <div class="small">Non penalizza se il dominio non ha posta/sito (moduli non applicabili).</div>
          </div>
          <div class="radar" style="--p: {final}%;">
            <span>{final}</span>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Score grezzo", f"{int(score)}/{weight_total}")
    with c2:
        st.metric("Email applicabile", "Sì" if email_applicable else "No")
    with c3:
        if final < 40:
            st.error("Livello: ALTO")
        elif final < 70:
            st.warning("Livello: MEDIO")
        else:
            st.success("Livello: BASSO")

    st.markdown("---")
    report = f"""Security Quick Check Pro
Target: {host}
Apex: {root if root else '-'}
IP: {resolved_ip if resolved_ip else '-'}
Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Score: {final}/100

Findings: {len(findings)}
CVE mode: {"ON" if cve_mode else "OFF"}
Version tokens: {", ".join(version_tokens) if version_tokens else "-"}

Contatto: {CONTACT_MAIL} | {CONTACT_SITE}

DISCLAIMER:
- Analisi basata su dati pubblici/best-effort.
- Scansione porte solo con autorizzazione.
- CVE: risultati indicativi basati su keyword; richiede conferma su prodotto/versione effettivi.
"""
    st.download_button("📥 Scarica report (txt)", report, file_name="security_report.txt")
