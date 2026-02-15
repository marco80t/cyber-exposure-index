import streamlit as st
import requests
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
import dns.resolver
import tldextract
import dns.reversename

# ------------------------------------------------
# CONFIG / UI
# ------------------------------------------------
st.set_page_config(page_title="Security Quick Check Pro", page_icon="🛡️", layout="wide")

def load_css():
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.6rem; }
        .metric-box {
            padding: 14px 16px;
            border-radius: 12px;
            border: 1px solid rgba(49,51,63,0.18);
            background: rgba(255,255,255,0.02);
        }
        .small { opacity: 0.85; font-size: 0.92rem; }
        .badge {
            display:inline-block; padding:2px 10px; border-radius:999px;
            border:1px solid rgba(49,51,63,0.2);
            font-size: 0.85rem; opacity:0.9;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

load_css()

# ------------------------------------------------
# SIDEBAR
# ------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ Security Quick Check Pro")
    try:
        st.image("assets/logo.png", use_container_width=True)
    except Exception:
        pass

    st.markdown("Verifica avanzata basata su **dati pubblici** (HTTP / DNS / SSL / Intelligence).")
    st.markdown("---")
    st.markdown("### Contatti")
    st.markdown("🌐 **Sito:** tmconsulenza.it")
    st.markdown("📩 **Email:** info@tmconsulenza.it")
    st.markdown("---")
    st.markdown("### Note legali")
    st.markdown("<div class='small'>Strumento passivo/best-effort. La modalità tecnica richiede autorizzazione.</div>", unsafe_allow_html=True)

# ------------------------------------------------
# HELPERS (ORIGINALI + NUOVI)
# ------------------------------------------------
def is_ip_target(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except: return False

def normalize_target(d: str) -> str:
    d = (d or "").strip().lower()
    d = d.replace("https://", "").replace("http://", "").split("/")[0]
    return d

def apex_domain(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname

# --- NUOVO: Geo-IP & ASN ---
def get_geo_info(ip: str):
    try:
        return requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
    except: return None

# --- NUOVO: Analisi Cookie ---
def analyze_cookies(response):
    cookies_data = []
    for cookie in response.cookies:
        cookies_data.append({
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": 'httponly' in [k.lower() for k in cookie._rest.keys()] or cookie.has_nonstandard_attr('HttpOnly'),
            "samesite": cookie._rest.get('SameSite', 'None')
        })
    return cookies_data

# --- NUOVO: SaaS Discovery ---
def discover_saas(domain: str):
    txts = dns_txt(domain)
    sigs = {"google-site": "Google Workspace", "msverify": "Microsoft 365", "atlassian": "Atlassian", "spf": "Mail Service"}
    found = []
    for t in txts:
        for k, v in sigs.items():
            if k in t.lower(): found.append(v)
    return list(set(found))

def fetch_https(host: str):
    r = requests.get(f"https://{host}", timeout=8, allow_redirects=True, headers={"User-Agent": "SecurityQuickCheck/1.0"})
    return r.url, r.status_code, r.headers, r.history, r

def parse_hsts(hsts_value: str) -> dict:
    out = {"max_age": None, "include_subdomains": False, "preload": False}
    if not hsts_value: return out
    parts = [p.strip() for p in hsts_value.split(";")]
    for p in parts:
        pl = p.lower()
        if pl.startswith("max-age"):
            try: out["max_age"] = int(p.split("=", 1)[1])
            except: pass
        if pl == "includesubdomains": out["include_subdomains"] = True
        if pl == "preload": out["preload"] = True
    return out

def ssl_info(host: str):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=6) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            tls_ver = ssock.version()
    not_after = cert.get("notAfter")
    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return {
        "expires": expires,
        "days_left": (expires - datetime.now(timezone.utc)).days,
        "issuer": ", ".join("=".join(x) for item in cert.get("issuer", []) for x in item),
        "tls_version": tls_ver,
        "san": [v for t, v in cert.get("subjectAltName", []) if t.lower() == "dns"]
    }

def dns_query(name: str, rtype: str):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout, resolver.lifetime = 2.0, 3.0
        return [str(r) for r in resolver.resolve(name, rtype)]
    except: return []

def dns_txt(name: str):
    try:
        ans = dns.resolver.resolve(name, "TXT")
        return ["".join([p.decode("utf-8") if isinstance(p, bytes) else str(p) for p in r.strings]) for r in ans]
    except: return []

def tcp_connect(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.2): return True
    except: return False

# ------------------------------------------------
# MAIN APP
# ------------------------------------------------
st.title("Security Quick Check Pro")
target = st.text_input("Dominio o IP", value=st.session_state.get('target_value', ""))

if st.button("Analizza") and target:
    st.session_state.target_value = target.strip()
    raw = normalize_target(target)
    is_ip = is_ip_target(raw)
    host = raw
    root = apex_domain(host) if not is_ip else None

    # ESECUZIONE ANALISI
    st.divider()
    
    # --- COLONNA INTELLIGENCE (NUOVA) ---
    if is_ip or not is_ip:
        ip_per_geo = raw if is_ip else (dns_query(host, "A")[0] if dns_query(host, "A") else None)
        if ip_per_geo:
            geo = get_geo_info(ip_per_geo)
            if geo:
                c1, c2, c3 = st.columns(3)
                c1.metric("🌍 Posizione", f"{geo.get('city')}, {geo.get('country_name')}")
                c2.metric("🏢 ISP", geo.get('org'))
                c3.metric("📌 ASN", geo.get('asn'))

    tab1, tab2, tab3, tab4 = st.tabs(["🌐 Web & Cookie", "📧 Email", "🧬 DNS & SaaS", "📊 Score & Report"])

    with tab1:
        st.subheader("Web Reachability & Headers")
        if not is_ip:
            try:
                final_url, status, headers, history, resp_obj = fetch_https(host)
                st.write(f"URL finale: **{final_url}** (Status: {status})")
                
                # Cookie Analysis (Nuovo)
                st.markdown("#### 🍪 Security Cookies")
                cookies = analyze_cookies(resp_obj)
                if cookies:
                    for c in cookies:
                        status_c = "✅ OK" if c['secure'] and c['httponly'] else "⚠️ Debole"
                        st.write(f"- `{c['name']}`: {status_c} (Secure: {c['secure']}, HttpOnly: {c['httponly']})")
                
                # Headers (Originale + Leakage)
                st.markdown("#### 🛡️ Headers")
                for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
                    if h in headers: st.success(f"✔ {h} presente")
                    else: st.warning(f"⚠ {h} mancante")
                
                if "Server" in headers:
                    st.error(f"⚠️ Information Leakage: Il server rivela software v. `{headers['Server']}`")
            except: st.error("Impossibile analizzare via HTTPS.")
        else: st.info("Inserisci un dominio per i test Web.")

    with tab2:
        if not is_ip:
            mx = dns_query(root, "MX")
            if mx:
                st.write("Record MX:", mx)
                spf = next((t for t in dns_txt(root) if "v=spf1" in t.lower()), None)
                dmarc = next((t for t in dns_txt(f"_dmarc.{root}") if "v=dmarc1" in t.lower()), None)
                st.success(f"SPF: {spf}") if spf else st.error("SPF Mancante")
                st.success(f"DMARC: {dmarc}") if dmarc else st.error("DMARC Mancante")
            else: st.info("Nessun record MX.")

    with tab3:
        st.subheader("DNS & SaaS Discovery")
        if not is_ip:
            saas = discover_saas(root)
            if saas: st.info(f"Servizi rilevati: {', '.join(saas)}")
            
            ds = dns_query(root, "DS")
            st.success("✔ DNSSEC Attivo") if ds else st.warning("⚠ DNSSEC non rilevato")
            
            a_rec = dns_query(host, "A")
            if a_rec: st.write(f"Record A: {a_rec}")

    with tab4:
        # Qui potresti reinserire la tua logica di calcolo score estesa
        st.subheader("Scansione Porte (Tecnica)")
        advanced = st.checkbox("Abilita scansione porte autorizzata")
        if advanced:
            for p in [22, 80, 443, 3306, 3389]:
                if tcp_connect(host, p): st.warning(f"Porta {p} APERTA")
                else: st.success(f"Porta {p} chiusa")
        
        st.download_button("Scarica Report", "Report di sicurezza generato.", file_name="report.txt")
