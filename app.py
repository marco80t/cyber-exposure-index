import streamlit as st
import requests
import ssl
import socket
import ipaddress
from datetime import datetime, timezone

import dns.resolver
import tldextract

# ==============================================================
# CONFIG / UI
# ==============================================================
st.set_page_config(page_title="Security Quick Check Pro", page_icon="🛡️", layout="wide")
import base64
from pathlib import Path
import streamlit as st

def inject_matrix_ui(bg_path: str = "assets/bg.png"):
    # Carico bg.png e lo embeddo in CSS (così funziona anche su Streamlit Cloud)
    bg_css = ""
    p = Path(bg_path)
    if p.exists():
        b64 = base64.b64encode(p.read_bytes()).decode("utf-8")
        ext = p.suffix.lower().replace(".", "")
        mime = "png" if ext == "png" else "jpeg"
        bg_css = f"""
        .stApp {{
          background-image:
            radial-gradient(1200px 700px at 20% 10%, rgba(0,255,140,0.20), transparent 55%),
            radial-gradient(900px 650px at 80% 20%, rgba(0,170,90,0.16), transparent 52%),
            linear-gradient(180deg, #05080F, #070B12),
            url("data:image/{mime};base64,{b64}");
          background-size: cover;
          background-position: center;
          background-attachment: fixed;
        }}
        """
    else:
        # fallback se bg non c'è
        bg_css = """
        .stApp{
          background:
            radial-gradient(1200px 700px at 20% 10%, rgba(0,255,140,0.18), transparent 55%),
            radial-gradient(900px 650px at 80% 20%, rgba(0,170,90,0.14), transparent 52%),
            linear-gradient(180deg, #05080F, #070B12);
        }
        """

    st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=Orbitron:wght@500;700&display=swap');

    :root{{
      --bg1:#05080F;
      --bg2:#070B12;
      --card: rgba(255,255,255,0.06);
      --card2: rgba(255,255,255,0.10);
      --stroke: rgba(0,255,140,0.18);
      --text: rgba(255,255,255,0.92);
      --muted: rgba(255,255,255,0.68);
      --accent: #00FF8C;      /* Matrix green */
      --accent2:#00AA5A;      /* deep green */
      --danger:#ff4d6d;
      --warn:#f7b955;
    }}

    {bg_css}

    /* generale */
    .stApp {{
      color: var(--text);
      font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    }}
    .block-container {{ padding-top: 1.2rem; }}

    /* Sidebar */
    section[data-testid="stSidebar"] {{
      background: linear-gradient(180deg, rgba(5,10,18,0.88), rgba(5,10,18,0.58));
      border-right: 1px solid rgba(0,255,140,0.16);
      backdrop-filter: blur(10px);
    }}
    section[data-testid="stSidebar"] * {{
      color: var(--text);
    }}

    /* Titoli “tech” */
    h1, h2, h3 {{
      font-family: Orbitron, Inter, sans-serif;
      letter-spacing: 0.4px;
    }}

    /* Inputs */
    .stTextInput input, .stTextArea textarea {{
      background: rgba(255,255,255,0.06) !important;
      border: 1px solid rgba(0,255,140,0.18) !important;
      border-radius: 12px !important;
      color: var(--text) !important;
    }}

    /* Button */
    .stButton button {{
      border-radius: 12px !important;
      border: 1px solid rgba(0,255,140,0.35) !important;
      background: linear-gradient(90deg, rgba(0,255,140,0.20), rgba(0,170,90,0.18)) !important;
      color: var(--text) !important;
      box-shadow: 0 0 0 rgba(0,255,140,0.0);
      transition: all .2s ease;
    }}
    .stButton button:hover {{
      box-shadow: 0 0 22px rgba(0,255,140,0.20);
      transform: translateY(-1px);
    }}

    /* Tabs */
    button[data-baseweb="tab"] {{
      background: rgba(255,255,255,0.04) !important;
      border: 1px solid rgba(0,255,140,0.16) !important;
      border-radius: 999px !important;
      margin-right: 8px !important;
      padding: 10px 14px !important;
    }}
    button[data-baseweb="tab"][aria-selected="true"] {{
      border: 1px solid rgba(0,255,140,0.38) !important;
      box-shadow: 0 0 18px rgba(0,255,140,0.14) !important;
    }}

    /* Metric */
    [data-testid="stMetric"] {{
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(0,255,140,0.16);
      border-radius: 16px;
      padding: 14px 16px;
      backdrop-filter: blur(10px);
      box-shadow: 0 10px 28px rgba(0,0,0,0.20);
    }}

    /* Alert box */
    div[data-testid="stAlert"] {{
      border-radius: 14px !important;
      border: 1px solid rgba(0,255,140,0.14) !important;
      background: rgba(255,255,255,0.06) !important;
      backdrop-filter: blur(10px);
    }}

    /* Card helper */
    .neo-card {{
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(0,255,140,0.16);
      border-radius: 16px;
      padding: 16px 18px;
      backdrop-filter: blur(10px);
      box-shadow: 0 10px 35px rgba(0,0,0,0.22);
    }}
    .neo-title {{
      font-family: Orbitron, Inter, sans-serif;
      letter-spacing: .4px;
      font-size: 1.05rem;
      margin: 0 0 8px 0;
    }}
    .neo-muted {{ color: var(--muted); font-size: 0.92rem; }}
    .badge {{
      display:inline-block; padding:2px 10px; border-radius:999px;
      border:1px solid rgba(0,255,140,0.22);
      font-size:0.85rem; opacity:0.92;
      background: rgba(0,255,140,0.06);
    }}
    .glow {{
      text-shadow: 0 0 14px rgba(0,255,140,0.22);
    }}
    </style>
    """, unsafe_allow_html=True)

def hero_matrix(title: str, subtitle: str, badge_text: str = "PASSIVE / BEST-EFFORT"):
    st.markdown(f"""
    <div class="neo-card">
      <div class="neo-title glow">{title} <span class="badge">{badge_text}</span></div>
      <div class="neo-muted">{subtitle}</div>
    </div>
    """, unsafe_allow_html=True)

# USO:
# inject_matrix_ui("assets/bg.png")
# hero_matrix("Security Quick Check Pro", "Analisi su dati pubblici (HTTP / DNS / SSL). Modalità tecnica solo con autorizzazione.")


UA = {"User-Agent": "SecurityQuickCheckPro/1.0"}

def load_css():
    st.markdown(
        """
        <style>
        .block-container { padding-top: 1.4rem; }
        .metric-box {
            padding: 14px 16px;
            border-radius: 12px;
            border: 1px solid rgba(49,51,63,0.18);
            background: rgba(255,255,255,0.02);
        }
        .small { opacity: 0.85; font-size: 0.92rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )
load_css()

# ==============================================================
# SIDEBAR
# ==============================================================
with st.sidebar:
    st.markdown("## 🛡️ Security Quick Check Pro")
    try:
        st.image("assets/logo.png", use_container_width=True)
    except Exception:
        pass

    st.markdown("Verifica **passiva / best-effort** basata su **dati pubblici** (HTTP / DNS / SSL).")
    st.markdown("---")
    st.markdown("### Contatti")
    st.markdown("🌐 **Sito:** tmconsulenza.it")
    st.markdown("📩 **Email:** info@tmconsulenza.it")
    st.markdown("---")
    st.markdown("### Note legali")
    st.markdown(
        "<div class='small'>"
        "Questo strumento non esegue test intrusivi. La modalità tecnica (porte) "
        "effettua solo un semplice TCP connect su poche porte comuni e va usata "
        "solo con autorizzazione del proprietario del target."
        "</div>",
        unsafe_allow_html=True,
    )

st.title("Security Quick Check Pro")
st.write("Analisi su informazioni **pubbliche**. Nessun brute-force, nessun exploit, nessuna autenticazione.")

# ==============================================================
# HELPERS
# ==============================================================
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
    r = requests.get(f"https://{host}", timeout=10, allow_redirects=True, headers=UA)
    return r.url, r.status_code, r.headers

def fetch_text(url: str, max_chars=2500):
    try:
        r = requests.get(url, timeout=8, allow_redirects=True, headers=UA)
        if r.status_code >= 400:
            return None
        return r.text[:max_chars]
    except Exception:
        return None

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

    issuer = ", ".join("=".join(x) for item in cert.get("issuer", []) for x in item) or "N/D"
    san = [v for t, v in cert.get("subjectAltName", []) if str(t).lower() == "dns"]

    return {"expires": expires, "days_left": days_left, "issuer": issuer, "tls_version": tls_ver, "san": san}

def get_caa(domain: str):
    try:
        answers = dns.resolver.resolve(domain, "CAA")
        return [str(r) for r in answers]
    except Exception:
        return []

def dnssec_enabled(domain: str):
    try:
        dns.resolver.resolve(domain, "DS")
        return True
    except Exception:
        return False

def tcp_connect(host: str, port: int, timeout=1.2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def check_security_txt(host: str):
    urls = [f"https://{host}/.well-known/security.txt", f"https://{host}/security.txt"]
    for u in urls:
        txt = fetch_text(u)
        if txt:
            return u, txt
    return None, None

def check_robots_sitemap(host: str):
    robots_url = f"https://{host}/robots.txt"
    robots_txt = fetch_text(robots_url)
    sitemaps = []
    if robots_txt:
        for line in robots_txt.splitlines():
            if line.lower().startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
    return robots_url, robots_txt, sitemaps

def parse_hsts(hsts_value: str) -> dict:
    out = {"max_age": None, "include_subdomains": False, "preload": False}
    if not hsts_value:
        return out
    parts = [p.strip() for p in hsts_value.split(";")]
    for p in parts:
        pl = p.lower()
        if pl.startswith("max-age"):
            try:
                out["max_age"] = int(p.split("=", 1)[1])
            except Exception:
                pass
        if pl == "includesubdomains":
            out["include_subdomains"] = True
        if pl == "preload":
            out["preload"] = True
    return out

def dkim_best_effort(domain_root: str):
    selectors = ["default", "selector1", "selector2", "google", "smtp", "mail", "dkim", "s1", "s2"]
    found = []
    for s in selectors:
        name = f"{s}._domainkey.{domain_root}"
        txts = dns_txt(name)
        for t in txts:
            if "v=dkim1" in t.lower():
                found.append((s, t))
                break
    return found

def fingerprint_from_dns_and_headers(host: str, root: str, headers: dict):
    hints = []

    cn_host = dns_query(host, "CNAME")
    cn_root = dns_query(root, "CNAME")
    ns = dns_query(root, "NS")
    dns_blob = " | ".join(cn_host + cn_root + ns).lower()

    cdn_sigs = {
        "Cloudflare": ["cloudflare", "cf-", "cf-ray"],
        "Akamai": ["akamai", "edgesuite", "akam.net"],
        "Fastly": ["fastly"],
        "Imperva/Incapsula": ["incapsula", "imperva"],
        "Azure Front Door": ["azurefd.net"],
        "AWS CloudFront": ["cloudfront.net"],
    }
    for name, sigs in cdn_sigs.items():
        if any(s in dns_blob for s in sigs):
            hints.append(f"Possibile CDN/WAF: **{name}** (hint DNS)")

    server = (headers or {}).get("Server")
    powered = (headers or {}).get("X-Powered-By")
    if server:
        hints.append(f"Header **Server** presente: `{server}` (possibile leakage)")
    if powered:
        hints.append(f"Header **X-Powered-By** presente: `{powered}` (possibile leakage)")

    if not hints:
        hints.append("Nessun fingerprint evidente (best-effort).")

    return {"cname_host": cn_host, "cname_root": cn_root, "ns": ns, "hints": list(dict.fromkeys(hints))}

def geo_ip_lookup(ip: str):
    try:
        return requests.get(f"https://ipapi.co/{ip}/json/", timeout=5, headers=UA).json()
    except Exception:
        return None

# ==============================================================
# SESSION STATE
# ==============================================================
if "analyzed" not in st.session_state:
    st.session_state.analyzed = False
if "target_value" not in st.session_state:
    st.session_state.target_value = ""
if "advanced" not in st.session_state:
    st.session_state.advanced = False

# ==============================================================
# INPUT
# ==============================================================
target_input = st.text_input(
    "Inserisci Dominio o IP",
    value=st.session_state.target_value,
    placeholder="es. tmconsulenza.it oppure 1.2.3.4"
)
go = st.button("Analizza")

if go and target_input:
    st.session_state.analyzed = True
    st.session_state.target_value = target_input.strip()

if not st.session_state.analyzed or not st.session_state.target_value:
    st.info("Inserisci un dominio o IP e premi *Analizza*.")
    st.stop()

raw = normalize_target(st.session_state.target_value)
is_ip = is_ip_target(raw)
host = raw
root = None if is_ip else apex_domain(host)

# Resolve IP (best-effort)
resolved_ip = None
if is_ip:
    resolved_ip = host
else:
    arec = dns_query(host, "A")
    if arec:
        resolved_ip = arec[0]

st.markdown("---")
st.subheader("Riepilogo")
c1, c2, c3 = st.columns(3)
with c1:
    st.write(f"**Target:** `{host}`")
with c2:
    st.write(f"**Tipo:** `{'IP' if is_ip else 'Dominio'}`")
with c3:
    st.write(f"**IP risolto:** `{resolved_ip or 'N/D'}`")

# ==============================================================
# TABS
# ==============================================================
tab_web, tab_email, tab_dns, tab_score = st.tabs(["🌐 Web", "📧 Email", "🧬 DNS & Fingerprint", "📊 Score & Report"])

# ==============================================================
# TAB WEB
# ==============================================================
with tab_web:
    st.markdown("## 1) Web Reachability & Security Headers")

    final_url = None
    status = None
    headers = {}
    header_score = 0

    try:
        final_url, status, headers = fetch_https(host)
        st.success(f"HTTPS raggiungibile (status: {status})")
        st.write(f"URL finale: **{final_url}**")
    except Exception:
        st.info("HTTPS non verificabile (best-effort).")

    security_headers = [
        ("Strict-Transport-Security", "HSTS"),
        ("Content-Security-Policy", "CSP"),
        ("X-Frame-Options", "XFO"),
        ("X-Content-Type-Options", "XCTO"),
        ("Referrer-Policy", "Referrer-Policy"),
        ("Permissions-Policy", "Permissions-Policy"),
        ("Cross-Origin-Opener-Policy", "COOP"),
        ("Cross-Origin-Embedder-Policy", "COEP"),
        ("Cross-Origin-Resource-Policy", "CORP"),
    ]

    st.markdown("### Security Headers (best-effort)")
    if headers:
        for h, label in security_headers:
            if h in headers:
                st.success(f"✔ {label} presente")
                header_score += 1
            else:
                st.warning(f"⚠ {label} mancante")
        st.caption(f"Headers: {header_score}/{len(security_headers)}")

        if "Strict-Transport-Security" in headers:
            hsts = parse_hsts(headers.get("Strict-Transport-Security", ""))
            st.markdown("### HSTS (dettagli)")
            st.write(f"max-age: `{hsts['max_age']}` | includeSubDomains: `{hsts['include_subdomains']}` | preload: `{hsts['preload']}`")

        # Leakage (solo segnale)
        if "Server" in headers or "X-Powered-By" in headers:
            server = headers.get("Server", "")
            powered = headers.get("X-Powered-By", "")
            st.warning(f"Possibile leakage: `Server={server}` `X-Powered-By={powered}`")
    else:
        st.caption("Header non disponibili (HTTPS non verificato).")

    st.markdown("## 2) SSL/TLS (certificato)")
    try:
        s = ssl_info(host)
        dl = s.get("days_left")
        if dl is None:
            st.info("Scadenza certificato non determinabile.")
        elif dl < 0:
            st.error(f"Certificato SCADUTO ({dl} giorni).")
        elif dl < 30:
            st.warning(f"Certificato in scadenza: {dl} giorni.")
        else:
            st.success(f"Certificato valido: scade tra {dl} giorni.")
        st.write(f"Issuer: `{s.get('issuer')}`")
        st.write(f"TLS version (handshake): `{s.get('tls_version')}`")
        if s.get("expires"):
            st.write(f"Scadenza: `{s['expires'].strftime('%Y-%m-%d %H:%M UTC')}`")
    except Exception:
        st.info("SSL non verificabile (best-effort).")

    st.markdown("## 3) Public Security Files (security.txt / robots / sitemap)")
    if not is_ip:
        sec_url, sec_txt = check_security_txt(host)
        if sec_txt:
            st.success("✔ security.txt trovato")
            st.write(f"URL: {sec_url}")
            st.code(sec_txt)
        else:
            st.info("security.txt non trovato (best practice).")

        robots_url, robots_txt, sitemaps = check_robots_sitemap(host)
        if robots_txt:
            st.success("✔ robots.txt trovato")
            st.write(f"URL: {robots_url}")
            st.code(robots_txt)
            if sitemaps:
                st.success("✔ Sitemap dichiarate")
                for sm in sitemaps:
                    st.write(f"- {sm}")
        else:
            st.info("robots.txt non trovato (non è obbligatorio).")
    else:
        st.info("Questi file richiedono un dominio.")

# ==============================================================
# TAB EMAIL
# ==============================================================
with tab_email:
    st.markdown("## 4) Email Security (MX / SPF / DMARC / DKIM best-effort)")

    if is_ip:
        st.info("Per email security serve un dominio.")
        st.stop()

    mx = dns_query(root, "MX")
    if not mx:
        st.info("Nessun record MX rilevato. **Possibile** che il dominio non gestisca posta. (Email = N/A)")
        st.stop()

    st.success(f"✔ Record MX trovati: {len(mx)}")
    st.code("\n".join(mx))

    txt_root = dns_txt(root)
    spf = next((t for t in txt_root if t.lower().startswith("v=spf1")), None)
    dmarc = next((t for t in dns_txt(f"_dmarc.{root}") if t.lower().startswith("v=dmarc1")), None)

    st.markdown("### SPF")
    if spf:
        st.success("✔ SPF presente")
        st.code(spf)
    else:
        st.warning("⚠ SPF mancante (rischio spoofing se il dominio invia posta).")

    st.markdown("### DMARC")
    if dmarc:
        st.success("✔ DMARC presente")
        st.code(dmarc)
    else:
        st.warning("⚠ DMARC mancante (monitoring/anti-abuso limitato se il dominio invia posta).")

    st.markdown("### DKIM (best-effort)")
    dkim = dkim_best_effort(root)
    if dkim:
        st.success(f"✔ DKIM trovato (selector comuni): {len(dkim)}")
        for sel, rec in dkim:
            st.write(f"Selector: `{sel}`")
            st.code(rec)
    else:
        st.info("DKIM non trovato nei selector comuni (potrebbe esserci con selector custom).")

# ==============================================================
# TAB DNS & FINGERPRINT
# ==============================================================
with tab_dns:
    st.markdown("## 5) DNS Hardening (DNSSEC / CAA)")

    if is_ip:
        st.info("DNS hardening richiede un dominio.")
    else:
        dnssec = dnssec_enabled(root)
        caa = get_caa(root)

        if dnssec:
            st.success("✔ DNSSEC: record DS trovato (best-effort: zona probabilmente firmata)")
        else:
            st.info("DNSSEC non rilevato (comune).")

        if caa:
            st.success("✔ CAA presente")
            st.code("\n".join(caa))
        else:
            st.info("CAA non presente (best-effort).")

        st.markdown("## 6) Fingerprint (CDN/WAF/Stack hints) — passivo")
        h = {}
        try:
            _, _, h = fetch_https(host)
        except Exception:
            pass

        fp = fingerprint_from_dns_and_headers(host, root, h)

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("### DNS")
            if fp["cname_host"]:
                st.write("CNAME host:")
                st.code("\n".join(fp["cname_host"]))
            if fp["cname_root"]:
                st.write("CNAME root:")
                st.code("\n".join(fp["cname_root"]))
            if fp["ns"]:
                st.write("NS:")
                st.code("\n".join(fp["ns"]))
            if not fp["cname_host"] and not fp["cname_root"] and not fp["ns"]:
                st.info("Nessun record CNAME/NS leggibile (best-effort).")
        with c2:
            st.markdown("### Hints")
            for hh in fp["hints"]:
                st.write(f"- {hh}")

    st.markdown("## 7) Geo-IP (opzionale)")
    st.caption("OFF di default. Usa un servizio terzo (ipapi). Non influisce sul punteggio.")
    enable_geo = st.toggle("Mostra Geo-IP (servizio terzo, best-effort)", value=False)

    if enable_geo and resolved_ip:
        geo = geo_ip_lookup(resolved_ip)
        if isinstance(geo, dict) and geo:
            st.success("Geo-IP (best-effort)")
            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric("Paese", geo.get("country_name") or "N/D")
            with c2:
                st.metric("Città", geo.get("city") or "N/D")
            with c3:
                st.metric("Org/ISP", geo.get("org") or geo.get("asn") or "N/D")
            st.caption("Nota: può riflettere POP/CDN/ISP e non la sede reale.")
        else:
            st.info("Geo-IP non disponibile (best-effort).")
    elif enable_geo and not resolved_ip:
        st.info("Nessun IP disponibile per Geo-IP.")

# ==============================================================
# TAB SCORE & REPORT
# ==============================================================
with tab_score:
    st.markdown("## 8) Modalità tecnica (solo con autorizzazione)")
    st.caption("Abilita controlli aggiuntivi best-effort. Solo TCP connect su poche porte comuni.")

    st.session_state.advanced = st.checkbox(
        "Modalità tecnica avanzata (richiede autorizzazione del proprietario)",
        value=st.session_state.advanced,
        key="advanced_checkbox",
    )
    advanced = st.session_state.advanced

    st.markdown("### 9) Exposure — Porte comuni (best-effort)")
    open_ports = None
    if not advanced:
        st.info("Attiva la modalità tecnica avanzata per visualizzare i controlli sulle porte.")
    else:
        st.info("Controllo leggero: solo TCP connect. Nessun tentativo di accesso/autenticazione.")
        common_ports = [(21, "FTP"), (22, "SSH"), (25, "SMTP"), (80, "HTTP"), (443, "HTTPS"), (3306, "MySQL"), (3389, "RDP")]
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
            st.warning("⚠ Alcune porte risultano esposte: verifica protezioni (firewall/VPN/ACL).")

    st.markdown("## 10) Cyber Exposure Index (best-effort)")

    # ---- Scoring FAIR:
    # - Web non raggiungibile => "non valutabile" => penalità minima
    # - Email senza MX => N/A => non penalizza (neutral)
    # - Porte contano solo se advanced (se no non entrano)

    web_score = 0      # max 40
    email_score = 0    # max 35
    dns_score = 0      # max 25

    # Web
    status = None
    headers = {}
    header_score = 0
    ssl_days = None

    try:
        _, status, headers = fetch_https(host)
    except Exception:
        pass

    try:
        s = ssl_info(host)
        ssl_days = s.get("days_left")
    except Exception:
        pass

    if status in (200, 301, 302, 307, 308):
        web_score += 10
    else:
        web_score += 3  # non valutabile

    if isinstance(ssl_days, int) and ssl_days > 0:
        web_score += 10
    else:
        web_score += 3  # non valutabile

    header_list = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Embedder-Policy",
        "Cross-Origin-Resource-Policy",
    ]
    if headers:
        for hh in header_list:
            if hh in headers:
                header_score += 1
        web_score += min(20, int((header_score / len(header_list)) * 20))
    else:
        web_score += 5

    # Email (solo se dominio)
    if is_ip:
        email_score += 20  # N/A neutral
    else:
        mx = dns_query(root, "MX")
        if not mx:
            email_score += 20  # N/A neutral
        else:
            txt_root = dns_txt(root)
            spf = next((t for t in txt_root if t.lower().startswith("v=spf1")), None)
            dmarc = next((t for t in dns_txt(f"_dmarc.{root}") if t.lower().startswith("v=dmarc1")), None)

            if spf:
                email_score += 10
            if dmarc:
                email_score += 15
                dl = dmarc.lower()
                if "p=quarantine" in dl:
                    email_score += 5
                if "p=reject" in dl:
                    email_score += 10

    # DNS (solo se dominio)
    if is_ip:
        dns_score += 12
    else:
        dnssec = dnssec_enabled(root)
        caa = get_caa(root)
        dns_score += 10 if dnssec else 5
        dns_score += 10 if caa else 5
        dns_score = min(dns_score, 25)

    # Ports penalty (only if advanced)
    ports_penalty = 0
    if advanced and isinstance(open_ports, int):
        if open_ports >= 3:
            ports_penalty = 8
        elif open_ports == 2:
            ports_penalty = 5
        elif open_ports == 1:
            ports_penalty = 2

    total = min(max(web_score + email_score + dns_score - ports_penalty, 0), 100)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Web", f"{web_score}/40")
    with c2:
        st.metric("Email", f"{email_score}/35")
    with c3:
        st.metric("DNS", f"{dns_score}/25")

    st.markdown(f"<div class='metric-box'><b>Punteggio Totale:</b> {total}/100</div>", unsafe_allow_html=True)

    if total < 40:
        st.error("Livello di esposizione: ALTO (best-effort)")
    elif total < 70:
        st.warning("Livello di esposizione: MEDIO (best-effort)")
    else:
        st.success("Livello di esposizione: BASSO (best-effort)")

    st.markdown("### Report rapido (testo)")
    report_lines = [
        "Security Quick Check Pro - Report (best-effort)",
        f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Target: {host}",
        f"Tipo: {'IP' if is_ip else 'Dominio'}",
        f"IP risolto: {resolved_ip or 'N/D'}",
        f"Score: {total}/100",
        "",
        "Nota legale: analisi passiva. Modalità tecnica porte richiede autorizzazione."
    ]
    report_text = "\n".join(report_lines)

    st.download_button("Scarica Report Rapido", report_text, file_name="security_quick_check_report.txt")

