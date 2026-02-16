import streamlit as st
import requests
import ssl
import socket
import ipaddress
import re
from datetime import datetime, timezone

import dns.resolver
import tldextract

# ============================================================
# CONFIG
# ============================================================
st.set_page_config(page_title="Security Quick Check Pro", page_icon="🛡️", layout="wide")

CONTACT_SITE = "tmconsulenza.it"
CONTACT_MAIL = "info@tmconsulenza.it"
UA = "SecurityQuickCheckPro/1.0"

# ============================================================
# MATRIX UI / CSS (fix caselle bianche)
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

        /* CUSTOM CODEBOX */
        .codebox {
            background: rgba(6, 12, 9, 0.82);
            border: 1px solid rgba(0,255,136,0.22);
            border-radius: 12px;
            padding: 14px 14px;
            color: rgba(235,255,245,0.94);
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.95rem;
            line-height: 1.45;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            box-shadow: 0 0 24px rgba(0,255,136,0.08);
        }
        .codebox .hint {
            color: rgba(0,255,136,0.95);
            font-weight: 900;
            text-shadow: 0 0 10px rgba(0,255,136,0.35);
            margin-bottom: 8px;
        }

        /* HARD OVERRIDES: elimina le "caselle bianche" Streamlit */
        [data-testid="stCodeBlock"] pre,
        [data-testid="stCodeBlock"] code,
        pre, code {
            background: rgba(6, 12, 9, 0.82) !important;
            color: rgba(235,255,245,0.94) !important;
            border: 1px solid rgba(0,255,136,0.18) !important;
            border-radius: 12px !important;
        }
        textarea {
            background: rgba(6, 12, 9, 0.82) !important;
            color: rgba(235,255,245,0.94) !important;
            border: 1px solid rgba(0,255,136,0.18) !important;
            border-radius: 12px !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

apply_matrix_style()

# ============================================================
# UI HELPERS
# ============================================================
def escape_html(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def codebox(text: str, title: str | None = None):
    t = escape_html(text or "")
    ttl = f'<div class="hint">{escape_html(title)}</div>' if title else ""
    st.markdown(f'<div class="codebox">{ttl}{t}</div>', unsafe_allow_html=True)

# ============================================================
# LOGIC HELPERS
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

def fetch_http_redirect_chain(host: str):
    chain = []
    try:
        r = requests.get(f"http://{host}", timeout=10, allow_redirects=True, headers={"User-Agent": UA})
        for h in r.history:
            chain.append(h.url)
        chain.append(r.url)
        ok = (r.url or "").lower().startswith("https://")
        return ok, chain
    except Exception:
        return None, []

def fetch_https(host: str):
    r = requests.get(f"https://{host}", timeout=10, allow_redirects=True, headers={"User-Agent": UA})
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

def analyze_cookies(response: requests.Response):
    cookies_data = []
    try:
        for cookie in response.cookies:
            httponly = ("httponly" in [k.lower() for k in cookie._rest.keys()]) or cookie.has_nonstandard_attr("HttpOnly")
            cookies_data.append({
                "name": cookie.name,
                "secure": bool(cookie.secure),
                "httponly": bool(httponly),
                "samesite": cookie._rest.get("SameSite", "None"),
            })
    except Exception:
        pass
    return cookies_data

def discover_saas(domain: str):
    txts = dns_txt(domain)
    sigs = {
        "google-site-verification": "Google (site verification)",
        "msverify": "Microsoft (domain verification)",
        "atlassian-domain-verification": "Atlassian",
        "facebook-domain-verification": "Meta/Facebook",
        "apple-domain-verification": "Apple",
        "stripe-verification": "Stripe",
        "v=spf1": "Email provider (SPF)",
    }
    found = []
    for t in txts:
        tl = t.lower()
        for k, v in sigs.items():
            if k in tl:
                found.append(v)
    out = []
    for x in found:
        if x not in out:
            out.append(x)
    return out

def extract_version_tokens(headers: dict) -> list:
    tokens = []
    for k in ["Server", "X-Powered-By"]:
        v = headers.get(k)
        if not v:
            continue
        for prod, ver in re.findall(r"([A-Za-z][A-Za-z0-9\-\_]+)\/(\d+(?:\.\d+){1,3})", v):
            tokens.append(f"{prod} {ver}")
    out = []
    for t in tokens:
        if t not in out:
            out.append(t)
    return out[:3]

@st.cache_data(ttl=3600, show_spinner=False)
def nvd_cve_keyword_search(query: str, limit: int = 6):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": limit}
    try:
        r = requests.get(url, params=params, timeout=10, headers={"User-Agent": UA})
        if r.status_code == 429:
            return {"error": "Rate limit NVD (429). Riprova tra poco."}
        if r.status_code >= 400:
            return {"error": f"Errore NVD ({r.status_code})."}
        data = r.json()
        items = []
        for it in data.get("vulnerabilities", [])[:limit]:
            cve = it.get("cve", {})
            cve_id = cve.get("id")
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

            sev = None
            metrics = cve.get("metrics", {})
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

def best_effort_dkim(root: str, selector: str = ""):
    selectors = [selector.strip()] if selector.strip() else ["selector1", "selector2", "default", "google", "k1", "mail", "s1", "s2"]
    found = []
    for s in selectors:
        name = f"{s}._domainkey.{root}"
        txts = dns_txt(name)
        for t in txts:
            if "v=dkim1" in t.lower():
                found.append((s, t))
    return found

def parse_dmarc_record(dmarc: str) -> dict:
    """
    Estrae p, rua, ruf, fo, adkim, aspf, sp, pct.
    """
    out = {}
    if not dmarc:
        return out
    parts = [p.strip() for p in dmarc.split(";") if p.strip()]
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out

@st.cache_data(ttl=3600, show_spinner=False)
def rdap_lookup(domain: str):
    url = f"https://rdap.iana.org/domain/{domain}"
    try:
        r = requests.get(url, timeout=12, allow_redirects=True, headers={"User-Agent": UA, "Accept": "application/rdap+json, application/json"})
        if r.status_code >= 400:
            return {"error": f"RDAP HTTP {r.status_code}"}
        return {"data": r.json(), "final_url": r.url}
    except Exception:
        return {"error": "RDAP non disponibile o non risponde (timeout/rete)."}

def rdap_extract_fields(data: dict):
    out = {"registrar": None, "status": [], "events": {}, "nameservers": []}
    try:
        out["status"] = data.get("status", []) or []
        for ev in data.get("events", []) or []:
            act = ev.get("eventAction")
            dt = ev.get("eventDate")
            if act and dt:
                out["events"][act] = dt
        for ns in data.get("nameservers", []) or []:
            ldh = ns.get("ldhName")
            if ldh:
                out["nameservers"].append(ldh)
        for ent in data.get("entities", []) or []:
            roles = ent.get("roles", []) or []
            if "registrar" in roles:
                v = ent.get("vcardArray")
                if isinstance(v, list) and len(v) == 2:
                    for row in v[1]:
                        if isinstance(row, list) and len(row) >= 4 and row[0] == "fn":
                            out["registrar"] = row[3]
                            break
    except Exception:
        pass
    out["nameservers"] = list(dict.fromkeys(out["nameservers"]))[:10]
    out["status"] = list(dict.fromkeys(out["status"]))[:10]
    return out

def get_geo_info(ip: str):
    try:
        return requests.get(f"https://ipapi.co/{ip}/json/", timeout=7, headers={"User-Agent": UA}).json()
    except Exception:
        return None

# ============================================================
# REMEDIATION
# ============================================================
def add_finding(findings: list, key: str, title: str, severity: str, why: str, cwe: str, owasp: str, fix: str):
    findings.append({"key": key, "title": title, "severity": severity, "why": why, "cwe": cwe, "owasp": owasp, "fix": fix})

def severity_badge(sev: str) -> str:
    sev = (sev or "").upper()
    if sev == "HIGH": return "🔴 HIGH"
    if sev == "MEDIUM": return "🟠 MEDIUM"
    return "🟢 LOW"

def render_remediation(findings: list):
    st.markdown("## Raccomandazioni & Remediation")
    if not findings:
        st.success("Ottimo: non risultano misconfigurazioni evidenti nei controlli attivi.")
        st.info(f"Per un assessment completo, contattami: {CONTACT_MAIL}")
        return

    for f in findings:
        st.markdown(
            f"""
            <div class="fix-card">
              <div class="fix-title">{severity_badge(f["severity"])} — {escape_html(f["title"])}</div>
              <div class="fix-meta"><b>CWE:</b> {escape_html(f["cwe"])} &nbsp;&nbsp; <b>OWASP:</b> {escape_html(f["owasp"])}</div>
              <div style="margin-top:8px;"><b>Rischio:</b> {escape_html(f["why"])}</div>
              <div style="margin-top:8px;"><b>Come risolvere:</b><br>{escape_html(f["fix"]).replace("\\n","<br>")}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("---")
    st.markdown(
        f"""
        <div class="glass">
          <div style="font-weight:900; font-size:1.05rem;">📩 Contattami per la remediation</div>
          <div class="small">
            • Email: <a href="mailto:{CONTACT_MAIL}">{CONTACT_MAIL}</a><br>
            • Sito: <a href="https://{CONTACT_SITE}" target="_blank">{CONTACT_SITE}</a><br>
            • Hardening + policy headers + mail security (SPF/DMARC/DKIM) + report per compliance.
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
        "• Controlli basati su info pubbliche.<br>"
        "• Modalità porte solo con autorizzazione.<br>"
        "• Nessun brute-force, accesso o exploit.<br>"
        "• CVE: indicativo (keyword), confermare su versione reale."
        "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("---")
    advanced_ports = st.toggle("Abilita modalità tecnica (porte)", value=False)
    show_geo = st.toggle("Mostra Geo/ASN (opzionale)", value=False)
    cve_mode = st.toggle("CVE Intelligence (best-effort)", value=True)

    st.markdown("---")
    st.markdown("### DKIM (best-effort)")
    dkim_selector = st.text_input("Selector DKIM (opz.)", value="", placeholder="es: selector1")

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
    if show_geo and resolved_ip:
        geo = get_geo_info(resolved_ip)
        if isinstance(geo, dict) and geo.get("error") is not True:
            st.write(f"**Geo:** {geo.get('city','-')}, {geo.get('country_name','-')}")
            st.write(f"**Org/ASN:** {geo.get('org','-')} | {geo.get('asn','-')}")
        else:
            st.caption("Geo/ASN non disponibile (best-effort).")
    st.markdown("</div>", unsafe_allow_html=True)

st.write("")

tab_web, tab_email, tab_dns, tab_whois, tab_remed, tab_score = st.tabs(
    ["🌐 Web", "📧 Email", "🧬 DNS", "📄 WHOIS/RDAP", "🛠️ Fix", "📊 Score"]
)

# ============================================================
# VARS
# ============================================================
findings = []

status = None
final_url = None
headers = {}
ssl_data = None
header_score = 0
version_tokens = []

spf = None
dmarc = None
dmarc_parsed = {}
mx = []
dkim_found = []

dnssec = False
caa = []

rdap_res = None
rdap_fields = None

# ============================================================
# WEB TAB
# ============================================================
with tab_web:
    st.markdown("## Web Reachability & Security Headers")

    if is_ip:
        st.info("Per IP: la parte Web completa richiede un hostname (dominio).")
    else:
        st.markdown("### HTTP → HTTPS Redirect (best-effort)")
        ok_redir, chain = fetch_http_redirect_chain(host)
        if ok_redir is True:
            st.success("✔ HTTP redirige correttamente a HTTPS")
        elif ok_redir is False:
            st.warning("⚠ HTTP non termina su HTTPS (valuta redirect 301 verso HTTPS)")
            add_finding(findings, "http_no_https", "HTTP non forza HTTPS", "MEDIUM",
                        "Traffico HTTP può essere intercettato/downgradato se qualcuno lo usa.",
                        "CWE-319", "A02:2021 Cryptographic Failures",
                        "Imposta redirect 301 da HTTP a HTTPS e abilita HSTS (dopo test).")
        else:
            st.info("HTTP non verificabile (best-effort).")
        if chain:
            codebox("\n".join(chain), title="Catena redirect")

        st.markdown("---")

        try:
            final_url, status, headers, resp = fetch_https(host)
            st.success(f"HTTPS raggiungibile — Status: {status}")
            st.write(f"URL finale: **{final_url}**")

            version_tokens = extract_version_tokens(headers)

            st.markdown("### Security Headers (best-effort)")
            security_headers = [
                ("Strict-Transport-Security", "HSTS", "Protegge da downgrade HTTP→HTTPS"),
                ("Content-Security-Policy", "CSP", "Riduce XSS / injection lato browser"),
                ("X-Frame-Options", "XFO", "Riduce clickjacking"),
                ("X-Content-Type-Options", "XCTO", "Riduce MIME sniffing"),
                ("Referrer-Policy", "Referrer-Policy", "Riduce leakage referrer"),
            ]

            header_score = 0
            for h, label, desc in security_headers:
                if h in headers:
                    st.success(f"✔ {label} presente — {h}")
                    header_score += 1
                else:
                    st.warning(f"⚠ {label} mancante — {h} ({desc})")
                    if h == "Content-Security-Policy":
                        add_finding(findings, "missing_csp", "Content-Security-Policy mancante", "MEDIUM",
                                    "Aumenta superficie XSS / injection lato browser.", "CWE-79", "A03:2021 Injection",
                                    "Imposta una CSP baseline e poi affinala sulle risorse reali.")
                    elif h == "X-Frame-Options":
                        add_finding(findings, "missing_xfo", "X-Frame-Options mancante", "MEDIUM",
                                    "Possibile clickjacking (embedding in iframe).", "CWE-1021", "A05:2021 Security Misconfiguration",
                                    "Aggiungi `X-Frame-Options: DENY` o `SAMEORIGIN` (meglio: CSP frame-ancestors).")
                    elif h == "Strict-Transport-Security":
                        add_finding(findings, "missing_hsts", "HSTS mancante", "LOW",
                                    "Rischio downgrade/SSL-strip in scenari specifici.", "CWE-319", "A02:2021 Cryptographic Failures",
                                    "Aggiungi `Strict-Transport-Security: max-age=15552000; includeSubDomains` (valuta preload).")
                    elif h == "X-Content-Type-Options":
                        add_finding(findings, "missing_xcto", "X-Content-Type-Options mancante", "LOW",
                                    "Rischio MIME sniffing su risorse statiche.", "CWE-16", "A05:2021 Security Misconfiguration",
                                    "Aggiungi `X-Content-Type-Options: nosniff`.")
                    elif h == "Referrer-Policy":
                        add_finding(findings, "missing_refpol", "Referrer-Policy mancante", "LOW",
                                    "Possibile leakage URL/path verso terze parti.", "CWE-200", "A01:2021 Broken Access Control",
                                    "Aggiungi `Referrer-Policy: strict-origin-when-cross-origin` (o più restrittiva).")

            st.markdown("### Fingerprinting / Leakage (best-effort)")
            leak = []
            if headers.get("Server"): leak.append(f"Server: {headers.get('Server')}")
            if headers.get("X-Powered-By"): leak.append(f"X-Powered-By: {headers.get('X-Powered-By')}")
            if leak:
                st.warning("Possibile information leakage: " + " | ".join(leak))
                add_finding(findings, "version_leak", "Information Leakage (Server/X-Powered-By)", "LOW",
                            "Espone stack/tecnologie; utile per fingerprinting.", "CWE-200", "A05:2021 Security Misconfiguration",
                            "Rimuovi/normalizza gli header (nginx: server_tokens off; Apache/IIS/framework config).")
            else:
                st.success("Nessun header tipico di leakage rilevato.")

            st.markdown("### 🍪 Cookie Security (best-effort)")
            cookies = analyze_cookies(resp)
            if not cookies:
                st.info("Nessun cookie rilevato (o non accessibile via risposta).")
            else:
                for c in cookies[:15]:
                    ok = c["secure"] and c["httponly"]
                    if ok:
                        st.success(f"✔ {c['name']} — Secure/HttpOnly OK (SameSite: {c['samesite']})")
                    else:
                        st.warning(f"⚠ {c['name']} — Secure={c['secure']} HttpOnly={c['httponly']} (SameSite: {c['samesite']})")
                        add_finding(findings, f"cookie_{c['name']}", f"Cookie debole: {c['name']}", "MEDIUM",
                                    "Cookie senza Secure/HttpOnly aumenta rischio furto sessione.", "CWE-614", "A05:2021 Security Misconfiguration",
                                    "Imposta cookie con `Secure; HttpOnly; SameSite=Lax/Strict` dove possibile.")

            st.markdown("---")
            st.markdown("## CVE Intelligence (best-effort)")
            st.caption("Mostrata SOLO se rilevo prodotto/versione da header. Indicativo: confermare su versione reale.")
            if not cve_mode:
                st.info("CVE disattivate (toggle in sidebar).")
            else:
                if not version_tokens:
                    st.info("Nessuna versione rilevata negli header (quindi niente CVE).")
                else:
                    for vt in version_tokens:
                        codebox(vt, title="Version token")
                    for vt in version_tokens:
                        with st.spinner(f"Cerco CVE per: {vt} (NVD) ..."):
                            res = nvd_cve_keyword_search(vt, limit=6)
                        if res.get("error"):
                            st.warning(f"{vt}: {res['error']}")
                            continue
                        items = res.get("items", [])
                        if not items:
                            st.info(f"{vt}: nessuna CVE trovata via keywordSearch.")
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
            add_finding(findings, "https_unreachable", "HTTPS non verificabile", "MEDIUM",
                        "Il servizio HTTPS non risponde o handshake fallisce.", "CWE-319", "A02:2021 Cryptographic Failures",
                        "Verifica DNS, certificato, catena, TLS policy e reachability. Posso fare troubleshooting e fix.")

    st.markdown("---")
    st.markdown("## SSL / TLS (best-effort)")
    try:
        ssl_data = ssl_info(host)
        if ssl_data["days_left"] is None:
            st.warning("Scadenza certificato non determinabile.")
        elif ssl_data["days_left"] < 0:
            st.error(f"Certificato **SCADUTO** ({ssl_data['days_left']} giorni).")
            add_finding(findings, "ssl_expired", "Certificato SSL scaduto", "HIGH",
                        "Servizio non trusted: rischio MITM e interruzioni.", "CWE-295", "A02:2021 Cryptographic Failures",
                        "Rinnova subito il certificato e verifica auto-renew.")
        elif ssl_data["days_left"] < 30:
            st.warning(f"Certificato in scadenza: **{ssl_data['days_left']} giorni**.")
            add_finding(findings, "ssl_expiring", "Certificato SSL in scadenza", "MEDIUM",
                        "Rischio outage e warning browser a breve.", "CWE-295", "A02:2021 Cryptographic Failures",
                        "Configura rinnovo automatico e monitoraggio scadenza.")
        else:
            st.success(f"Certificato valido: scade tra **{ssl_data['days_left']} giorni**.")
        if ssl_data.get("expires"):
            st.write(f"Scadenza: **{ssl_data['expires'].strftime('%Y-%m-%d %H:%M UTC')}**")
        st.write(f"TLS: **{ssl_data.get('tls','N/D')}**")
        st.write(f"Issuer: **{ssl_data.get('issuer','N/D')}**")
        if ssl_data.get("san"):
            codebox("\n".join(ssl_data["san"][:30]), title="SAN (SubjectAltName)")
    except Exception:
        st.error("Impossibile verificare SSL (porta 443 non disponibile o handshake fallito).")

    st.markdown("---")
    st.markdown("## Modalità tecnica (porte) — solo con autorizzazione")
    if not advanced_ports:
        st.info("Attiva **“Abilita modalità tecnica (porte)”** nella sidebar.")
    else:
        st.warning("Best-effort: TCP connect su poche porte. Nessuno scan aggressivo.")
        common_ports = [(21,"FTP"),(22,"SSH"),(25,"SMTP"),(80,"HTTP"),(443,"HTTPS"),(3306,"MySQL"),(3389,"RDP")]
        open_ports = 0
        for p, name in common_ports:
            if tcp_connect(host, p):
                st.warning(f"⚠ Porta {p} ({name}) **aperta** (best-effort)")
                open_ports += 1
            else:
                st.success(f"✔ Porta {p} ({name}) chiusa")
        if open_ports > 0:
            add_finding(findings, "ports_exposed", "Porte comuni esposte", "MEDIUM",
                        "Servizi esposti aumentano superficie d’attacco.", "CWE-284", "A05:2021 Security Misconfiguration",
                        "Chiudi porte non necessarie, limita via firewall/VPN/ACL, MFA dove possibile, rate-limit e monitoring.")

# ============================================================
# EMAIL TAB (completo + DMARC policy)
# ============================================================
with tab_email:
    st.markdown("## Email Security (MX / SPF / DMARC / DKIM best-effort)")
    if is_ip:
        st.info("Per IP: la sezione email non è applicabile senza dominio.")
    else:
        mx = dns_query(root, "MX")
        if mx:
            st.success(f"MX trovati: {len(mx)}")
            codebox("\n".join(mx), title="MX records")
        else:
            st.info("Nessun record MX: il dominio potrebbe non gestire posta (NON è un fail).")

        txts = dns_txt(root)
        spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
        dmarc = next((t for t in dns_txt(f"_dmarc.{root}") if t.lower().startswith("v=dmarc1")), None)
        dmarc_parsed = parse_dmarc_record(dmarc) if dmarc else {}

        st.markdown("### SPF")
        if spf:
            st.success("✔ SPF presente")
            codebox(spf, title="SPF record")
        else:
            st.warning("⚠ SPF assente (se invii email: rischio spoofing)")
            if mx:
                add_finding(findings, "missing_spf", "SPF mancante (dominio con MX)", "HIGH",
                            "Senza SPF aumenta rischio spoofing/phishing.", "CWE-290", "A07:2021 Identification and Authentication Failures",
                            "Aggiungi record TXT SPF coerente con i provider (M365/Google/relay).")

        st.markdown("### DMARC")
        if dmarc:
            st.success("✔ DMARC presente")
            codebox(dmarc, title="DMARC record")

            policy = (dmarc_parsed.get("p") or "").lower()
            aspf = (dmarc_parsed.get("aspf") or "r").lower()
            adkim = (dmarc_parsed.get("adkim") or "r").lower()
            rua = dmarc_parsed.get("rua", "-")
            ruf = dmarc_parsed.get("ruf", "-")
            fo = dmarc_parsed.get("fo", "-")
            pct = dmarc_parsed.get("pct", "100")

            # ✅ QUI c'è il pezzo che ti mancava: p=reject/quarantine/none ben visibile
            st.markdown("#### Stato DMARC (interpretazione)")
            if policy == "reject":
                st.success("✔ Policy: **p=reject** (massima protezione anti-spoofing)")
            elif policy == "quarantine":
                st.warning("⚠ Policy: **p=quarantine** (buona protezione, non massima)")
            elif policy == "none":
                st.info("ℹ Policy: **p=none** (solo monitor, non blocca)")
                add_finding(findings, "dmarc_p_none", "DMARC in monitor (p=none)", "MEDIUM",
                            "DMARC monitora ma non blocca abusi.", "CWE-290", "A07:2021 Identification and Authentication Failures",
                            "Passa gradualmente a `p=quarantine` e poi `p=reject` dopo analisi report.")
            else:
                st.info(f"ℹ Policy DMARC: p={policy or 'N/D'}")

            st.write(f"**Alignment:** adkim={adkim} | aspf={aspf} | pct={pct}")
            st.write(f"**Reporting:** rua={rua} | ruf={ruf} | fo={fo}")

        else:
            st.warning("⚠ DMARC assente (se invii email: mancano policy e reporting)")
            if mx:
                add_finding(findings, "missing_dmarc", "DMARC mancante (dominio con MX)", "HIGH",
                            "Senza DMARC manca enforcement e reporting anti-spoofing.", "CWE-290",
                            "A07:2021 Identification and Authentication Failures",
                            "Aggiungi `_dmarc` con `v=DMARC1; p=none; rua=mailto:<report@...>` poi hardening fino a reject.")

        st.markdown("### DKIM (best-effort)")
        dkim_found = best_effort_dkim(root, dkim_selector)
        if dkim_found:
            st.success(f"✔ DKIM trovato ({len(dkim_found)} record)")
            for sel, rec in dkim_found[:8]:
                st.write(f"Selector: **{sel}**")
                codebox(rec, title=f"{sel}._domainkey.{root}")
        else:
            st.info("DKIM non rilevato (può essere perché il selector è diverso).")
            if mx:
                add_finding(findings, "dkim_not_found", "DKIM non rilevato (best-effort)", "MEDIUM",
                            "Se invii email, DKIM aiuta deliverability e anti-spoofing.", "CWE-290",
                            "A07:2021 Identification and Authentication Failures",
                            "Verifica provider mail e selector DKIM. Posso configurarlo e validare allineamento DMARC.")

# ============================================================
# DNS TAB
# ============================================================
with tab_dns:
    st.markdown("## DNS Hardening (DNSSEC / CAA) + Discovery")
    if is_ip:
        st.info("Per IP: DNSSEC/CAA non applicabili senza dominio.")
    else:
        dnssec = True if dns_query(root, "DS") else False
        caa = dns_query(root, "CAA")

        if dnssec:
            st.success("✔ DNSSEC: record DS trovato (best-effort)")
        else:
            st.warning("⚠ DNSSEC: record DS non trovato")
            add_finding(findings, "dnssec_off", "DNSSEC assente", "LOW",
                        "Maggiore rischio attacchi DNS in scenari specifici.", "CWE-345",
                        "A08:2021 Software and Data Integrity Failures",
                        "Valuta abilitazione DNSSEC presso registrar/DNS provider.")

        if caa:
            st.success("✔ CAA presente")
            codebox("\n".join(caa), title="CAA")
        else:
            st.warning("⚠ CAA assente")
            add_finding(findings, "caa_missing", "CAA mancante", "LOW",
                        "Senza CAA, qualunque CA potrebbe emettere certificati (in certe condizioni).",
                        "CWE-295", "A02:2021 Cryptographic Failures",
                        "Aggiungi record CAA per limitare le CA autorizzate (es. letsencrypt.org).")

        st.markdown("---")
        st.markdown("### SaaS / Verifiche dominio (best-effort)")
        saas = discover_saas(root)
        if saas:
            st.success("Impronte trovate:")
            for s in saas:
                st.write(f"- {s}")
        else:
            st.info("Nessuna impronta comune trovata nei TXT (non significa 'nessun SaaS').")

# ============================================================
# WHOIS/RDAP TAB
# ============================================================
with tab_whois:
    st.markdown("## WHOIS / RDAP (best-effort)")
    st.caption("RDAP è lo standard moderno. L’intestatario può essere oscurato (GDPR). Estraggo date/registrar quando disponibili.")

    if is_ip:
        st.info("Per IP servirebbe RDAP/RIR (RIPE/ARIN). Lo aggiungiamo dopo se vuoi.")
    else:
        with st.spinner("Interrogo RDAP (IANA bootstrap) ..."):
            rdap_res = rdap_lookup(root)

        if rdap_res.get("error"):
            st.warning(f"RDAP non disponibile: {rdap_res['error']}")
        else:
            data = rdap_res.get("data", {})
            final_rdap_url = rdap_res.get("final_url", "")
            rdap_fields = rdap_extract_fields(data)

            st.success("RDAP OK (best-effort)")
            if final_rdap_url:
                st.caption(f"Endpoint RDAP: {final_rdap_url}")

            c1, c2 = st.columns(2)
            with c1:
                st.markdown("### Date (se presenti)")
                events = rdap_fields.get("events", {}) or {}
                if events:
                    for k in ["registration", "expiration", "last changed", "transfer"]:
                        if k in events:
                            st.write(f"**{k}:** {events[k]}")
                    for k, v in events.items():
                        if k not in ["registration", "expiration", "last changed", "transfer"]:
                            st.write(f"**{k}:** {v}")
                else:
                    st.info("Nessun evento/data disponibile via RDAP (best-effort).")

            with c2:
                st.markdown("### Registrar / Status")
                if rdap_fields.get("registrar"):
                    st.write(f"**Registrar:** {rdap_fields['registrar']}")
                else:
                    st.info("Registrar non disponibile (best-effort).")
                if rdap_fields.get("status"):
                    codebox("\n".join(rdap_fields["status"]), title="Status")

            st.markdown("---")
            st.markdown("### Nameserver (se presenti)")
            ns = rdap_fields.get("nameservers", []) or []
            if ns:
                codebox("\n".join(ns), title="Nameservers")
            else:
                st.info("Nameserver non disponibili via RDAP (best-effort).")

# ============================================================
# FIX TAB
# ============================================================
with tab_remed:
    render_remediation(findings)

# ============================================================
# SCORE TAB (normalizzato)
# ============================================================
with tab_score:
    st.markdown("## Cyber Exposure Index (best-effort)")

    WEB_W = 40
    EMAIL_W = 35
    DNS_W = 25
    WHOIS_W = 10

    score = 0
    weight_total = 0

    if not is_ip:
        weight_total += WEB_W
        wp = 0
        if status in (200, 301, 302, 307, 308): wp += 10
        if ssl_data and isinstance(ssl_data.get("days_left"), int) and ssl_data["days_left"] > 0: wp += 10
        wp += min(20, header_score * 4)
        score += min(WEB_W, wp)

    email_applicable = (not is_ip) and (bool(mx) or bool(spf) or bool(dmarc) or bool(dkim_found))
    if email_applicable:
        weight_total += EMAIL_W
        ep = 0
        if spf: ep += 10
        if dmarc:
            ep += 15
            pol = (dmarc_parsed.get("p") or "").lower()
            if pol == "quarantine": ep += 5
            if pol == "reject": ep += 10
        if dkim_found: ep += 10
        score += min(EMAIL_W, ep)

    if not is_ip:
        weight_total += DNS_W
        dp = 0
        if dnssec: dp += 10
        if caa: dp += 10
        score += min(DNS_W, dp)

    if not is_ip:
        weight_total += WHOIS_W
        hp = 0
        if rdap_res and rdap_res.get("data"): hp += 6
        if rdap_fields and rdap_fields.get("events", {}).get("expiration"): hp += 2
        if rdap_fields and rdap_fields.get("registrar"): hp += 2
        score += min(WHOIS_W, hp)

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
          <div class="radar" style="--p: {final}%;"><span>{final}</span></div>
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
        if final < 40: st.error("Livello: ALTO")
        elif final < 70: st.warning("Livello: MEDIO")
        else: st.success("Livello: BASSO")

    st.markdown("---")
    report = f"""Security Quick Check Pro
Target: {host}
Apex: {root if root else '-'}
IP: {resolved_ip if resolved_ip else '-'}
Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Score: {final}/100

Findings: {len(findings)}
CVE mode: {"ON" if cve_mode else "OFF"}
RDAP: {"OK" if (rdap_res and rdap_res.get("data")) else "N/A"}

Contatto: {CONTACT_MAIL} | {CONTACT_SITE}

DISCLAIMER:
- Analisi basata su dati pubblici/best-effort.
- Scansione porte solo con autorizzazione.
- CVE: indicativo, richiede conferma su versione reale.
"""
    st.download_button("📥 Scarica report (txt)", report, file_name="security_report.txt")
