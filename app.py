import streamlit as st
import requests
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
import dns.resolver
import tldextract

# ============================================================
# CONFIG
# ============================================================
st.set_page_config(page_title="Security Quick Check Pro", page_icon="🛡️", layout="wide")

# ============================================================
# MATRIX UI / CSS (FIX SIDEBAR + CONTRASTO)
# ============================================================
def apply_matrix_style():
    st.markdown(
        """
        <style>
        /* ---------- APP BACKGROUND ---------- */
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

        /* ---------- SIDEBAR (FIX VISIBILITÀ) ---------- */
        [data-testid="stSidebar"] {
            background: rgba(8, 14, 11, 0.96) !important;
            border-right: 1px solid rgba(0,255,136,0.22);
        }
        [data-testid="stSidebar"] * {
            color: rgba(235,255,245,0.92) !important;
        }
        [data-testid="stSidebar"] a {
            color: #00ff88 !important;
        }
        [data-testid="stSidebar"] .stMarkdown h1,
        [data-testid="stSidebar"] .stMarkdown h2,
        [data-testid="stSidebar"] .stMarkdown h3 {
            color: #00ff88 !important;
            text-shadow: 0 0 10px rgba(0,255,136,0.45);
        }
        [data-testid="stSidebar"] hr {
            border-color: rgba(0,255,136,0.18) !important;
        }

        /* ---------- GLOBAL TEXT ---------- */
        html, body, [class*="st-"], .stMarkdown, .stText, .stCaption, .stWrite {
            color: rgba(235,255,245,0.92) !important;
        }
        h1, h2, h3, h4 {
            color: #00ff88 !important;
            text-shadow: 0 0 12px rgba(0,255,136,0.55);
        }
        .small { opacity: 0.85; font-size: 0.92rem; }

        /* ---------- GLASS CARDS ---------- */
        .glass {
            padding: 16px 18px;
            border-radius: 14px;
            border: 1px solid rgba(0,255,136,0.28);
            background: rgba(10, 18, 14, 0.58);
            box-shadow: 0 0 30px rgba(0,255,136,0.10);
            backdrop-filter: blur(10px);
        }
        .glass * { color: rgba(235,255,245,0.94) !important; }

        /* ---------- METRICS ---------- */
        [data-testid="stMetric"] {
            background: rgba(10, 18, 14, 0.58) !important;
            border: 1px solid rgba(0,255,136,0.28) !important;
            border-radius: 14px !important;
            padding: 12px !important;
        }

        /* ---------- INPUTS ---------- */
        .stTextInput label { color: rgba(235,255,245,0.85) !important; }
        .stTextInput input {
            color: rgba(235,255,245,0.95) !important;
            border-radius: 10px !important;
            border: 1px solid rgba(0,255,136,0.28) !important;
            background: rgba(10, 18, 14, 0.58) !important;
        }

        /* ---------- TABS ---------- */
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

        /* ---------- BUTTONS ---------- */
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

        /* ---------- RADAR ---------- */
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

def get_geo_info(ip: str):
    try:
        return requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
    except Exception:
        return None

# ---------------- RDAP / WHOIS (best-effort) ----------------
def rdap_request_json(url: str):
    """Prova a ottenere JSON RDAP. Ritorna dict o None."""
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": "SecurityQuickCheckPro/1.0"})
        if r.status_code == 200:
            ct = (r.headers.get("content-type") or "").lower()
            if "json" in ct or ct.startswith("application/"):
                return r.json()
        return None
    except Exception:
        return None

def rdap_request_via_proxy(url: str):
    """
    Fallback best-effort: usa r.jina.ai per aggirare blocchi di rete.
    Non sempre funziona, ma spesso sì su Streamlit Cloud.
    """
    try:
        prox = "https://r.jina.ai/http://"+url.replace("https://", "").replace("http://", "")
        r = requests.get(prox, timeout=10, headers={"User-Agent": "SecurityQuickCheckPro/1.0"})
        if r.status_code != 200:
            return None
        txt = r.text.strip()
        # r.jina.ai spesso restituisce il JSON “pulito” come testo
        return requests.models.complexjson.loads(txt)
    except Exception:
        return None

def rdap_extract_dates(rdap_json: dict):
    created = None
    updated = None
    expires = None
    for ev in rdap_json.get("events", []):
        action = (ev.get("eventAction") or "").lower()
        date = ev.get("eventDate")
        if not date:
            continue
        if "registration" in action:
            created = date
        elif "expiration" in action:
            expires = date
        elif "last changed" in action or "last update" in action:
            updated = date
    return created, updated, expires

def parse_iso_date(d: str):
    if not d:
        return None
    try:
        return datetime.fromisoformat(d.replace("Z", "+00:00"))
    except Exception:
        return None

def days_until(dt: datetime):
    if not dt:
        return None
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - now).days

def rdap_domain_best_effort(domain: str):
    """
    Ordine:
    1) .it -> rdap.nic.it
    2) rdap.org
    3) bootstrap IANA -> endpoint tld
    4) proxy (r.jina.ai) su rdap.nic.it e rdap.org (best-effort)
    """
    domain = domain.strip().lower()
    tld = domain.split(".")[-1]

    # 1) .it
    if tld == "it":
        url = f"https://rdap.nic.it/domain/{domain}"
        data = rdap_request_json(url)
        if data:
            return data, "rdap.nic.it"
        # proxy fallback
        data = rdap_request_via_proxy(url)
        if data:
            return data, "rdap.nic.it (proxy)"

    # 2) rdap.org
    url = f"https://rdap.org/domain/{domain}"
    data = rdap_request_json(url)
    if data:
        return data, "rdap.org"
    data = rdap_request_via_proxy(url)
    if data:
        return data, "rdap.org (proxy)"

    # 3) IANA bootstrap
    boot = rdap_request_json("https://data.iana.org/rdap/dns.json")
    if boot:
        services = boot.get("services", [])
        for item in services:
            tlds, urls = item[0], item[1]
            if tld in [x.strip(".").lower() for x in tlds]:
                for base in urls:
                    base = base.rstrip("/")
                    url = f"{base}/domain/{domain}"
                    data = rdap_request_json(url)
                    if data:
                        return data, base
                    data = rdap_request_via_proxy(url)
                    if data:
                        return data, f"{base} (proxy)"

    return None, None

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
    st.markdown("🌐 **Sito:** tmconsulenza.it")
    st.markdown("📩 **Email:** info@tmconsulenza.it")
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
    show_geo = st.toggle("Mostra Geo/ASN (opzionale)", value=False)
    advanced_ports = st.toggle("Abilita modalità tecnica (porte)", value=False)
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
        placeholder="es: tmconsulenza.it oppure 1.2.3.4",
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
sumc1, sumc2, sumc3 = st.columns([2, 2, 2])
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
with sumc3:
    st.markdown('<div class="glass">', unsafe_allow_html=True)
    if show_geo and resolved_ip:
        geo = get_geo_info(resolved_ip)
        if geo:
            st.write(f"**Geo:** {geo.get('city')}, {geo.get('country_name')}")
            st.write(f"**Org:** {geo.get('org')}")
        else:
            st.write("**Geo:** non disponibile")
    else:
        st.write("**Geo/ASN:** disattivato")
    st.markdown("</div>", unsafe_allow_html=True)

st.write("")
tab_web, tab_email, tab_dns, tab_whois, tab_score = st.tabs(
    ["🌐 Web", "📧 Email", "🧬 DNS", "🧾 WHOIS/RDAP", "📊 Score"]
)

# ============================================================
# ANALYSIS VARS
# ============================================================
status = None
final_url = None
headers = {}
ssl_data = None

spf = None
dmarc = None
mx = []
dkim_found = []

dnssec = False
caa = []
header_score = 0

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

            st.markdown("### Security Headers (best-effort)")
            security_headers = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-Frame-Options": "Clickjacking",
                "X-Content-Type-Options": "MIME sniffing",
                "Referrer-Policy": "Referrer control",
            }
            header_score = 0
            for h, label in security_headers.items():
                if h in headers:
                    st.success(f"✔ {label} — {h} presente")
                    header_score += 1
                else:
                    st.warning(f"⚠ {label} — {h} mancante")

            leak = []
            if headers.get("Server"):
                leak.append(f"Server: {headers.get('Server')}")
            if headers.get("X-Powered-By"):
                leak.append(f"X-Powered-By: {headers.get('X-Powered-By')}")
            if leak:
                st.warning("Possibile **information leakage**: " + " | ".join(leak))
            else:
                st.success("Nessun header tipico di leakage rilevato.")
        except Exception:
            st.error("Impossibile analizzare via HTTPS (host non raggiungibile / TLS / redirect).")
            header_score = 0

    st.markdown("---")
    st.markdown("## SSL / TLS (best-effort)")
    try:
        ssl_data = ssl_info(host)
        if ssl_data["days_left"] is None:
            st.warning("Scadenza certificato non determinabile.")
        elif ssl_data["days_left"] < 0:
            st.error(f"Certificato **SCADUTO** ({ssl_data['days_left']} giorni).")
        elif ssl_data["days_left"] < 30:
            st.warning(f"Certificato in scadenza: **{ssl_data['days_left']} giorni**.")
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
        if open_ports == 0:
            st.success("✔ Nessuna porta comune risulta esposta (best-effort).")
        else:
            st.warning("⚠ Porte esposte: verifica firewall/VPN/ACL e che sia voluto.")

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

        st.markdown("### DMARC")
        if dmarc:
            st.success("✔ DMARC presente")
            st.code(dmarc)
        else:
            st.warning("⚠ DMARC assente (se il dominio invia email, mancano policy e reporting)")

        st.markdown("### DKIM (best-effort)")
        dkim_found = best_effort_dkim(root, dkim_selector)
        if dkim_found:
            st.success(f"✔ DKIM trovato ({len(dkim_found)} record)")
            for sel, rec in dkim_found[:6]:
                st.write(f"Selector: **{sel}**")
                st.code(rec)
            if len(dkim_found) > 6:
                st.info("Altri record DKIM trovati (output troncato).")
        else:
            st.info("DKIM non rilevato (può essere perché il selector è diverso).")
            st.caption("Suggerimento: se sai il selector del provider, inseriscilo in sidebar.")

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

        if caa:
            st.success("✔ CAA presente")
            st.code("\n".join(caa))
        else:
            st.warning("⚠ CAA assente")

# ============================================================
# TAB WHOIS/RDAP (CON PULSANTI FALLBACK)
# ============================================================
with tab_whois:
    st.markdown("## WHOIS / RDAP (best-effort)")
    if is_ip:
        st.info("WHOIS dominio non applicabile a un IP qui (servirebbe WHOIS ASN/RIR separato).")
    else:
        # link fallback SEMPRE visibili
        st.markdown("### Link rapidi (fallback)")
        cL1, cL2, cL3 = st.columns(3)
        with cL1:
            st.link_button("Apri RDAP (NIC.it)", f"https://rdap.nic.it/domain/{root}", use_container_width=True)
        with cL2:
            st.link_button("Apri RDAP (rdap.org)", f"https://rdap.org/domain/{root}", use_container_width=True)
        with cL3:
            st.link_button("Apri WHOIS (Registro.it)", "https://www.registro.it/ricerca-whois/", use_container_width=True)

        st.markdown("---")

        rd, source = rdap_domain_best_effort(root)
        if not rd:
            st.warning("RDAP non disponibile o non risponde dal server (best-effort). Usa i link sopra.")
            st.caption("Nota: spesso è un limite di rete/egress del deploy. I dati registrant possono essere redatti (GDPR).")
        else:
            created, updated, expires = rdap_extract_dates(rd)
            d_created = parse_iso_date(created)
            d_updated = parse_iso_date(updated)
            d_expires = parse_iso_date(expires)
            left = days_until(d_expires) if d_expires else None

            st.success(f"RDAP OK (fonte: {source})")

            st.markdown("### Dati principali")
            cA, cB, cC, cD = st.columns(4)
            with cA:
                st.metric("Creato", (created or "N/D")[:10])
            with cB:
                st.metric("Aggiornato", (updated or "N/D")[:10])
            with cC:
                st.metric("Scadenza", (expires or "N/D")[:10])
            with cD:
                st.metric("Giorni alla scadenza", str(left) if left is not None else "N/D")

            if left is not None:
                if left < 0:
                    st.error("⚠ Dominio risulta SCADUTO (o data RDAP incoerente).")
                elif left < 30:
                    st.warning("⚠ Dominio in scadenza < 30 giorni.")
                elif left < 90:
                    st.info("ℹ️ Dominio in scadenza < 90 giorni.")

            st.markdown("### Registrar / Status / Nameserver")
            reg_name = rd.get("registrarName") or "N/D"
            st.write(f"**Registrar:** {reg_name}")

            statuses = rd.get("status", [])
            if statuses:
                st.write("**Status:**")
                st.code("\n".join(statuses))

            ns = [n.get("ldhName") for n in rd.get("nameservers", []) if n.get("ldhName")]
            if ns:
                st.write("**Nameserver:**")
                st.code("\n".join(ns))

            st.caption("Intestatario/registrant: spesso **redatto** (GDPR).")

# ============================================================
# TAB SCORE (NORMALIZZATO)
# ============================================================
with tab_score:
    st.markdown("## Cyber Exposure Index (best-effort)")

    score = 0
    weight_total = 0

    # Web (solo dominio)
    web_w = 40
    if not is_ip:
        weight_total += web_w
        web_points = 0
        if status in (200, 301, 302, 307, 308):
            web_points += 10
        if ssl_data and isinstance(ssl_data.get("days_left"), int) and ssl_data["days_left"] > 0:
            web_points += 10
        web_points += min(20, header_score * 4)  # max 20
        score += min(web_w, web_points)

    # Email applicabile solo se c'è almeno un segnale (MX/SPF/DMARC/DKIM)
    email_w = 35
    email_applicable = (not is_ip) and (bool(mx) or bool(spf) or bool(dmarc) or bool(dkim_found))
    if email_applicable:
        weight_total += email_w
        ep = 0
        if spf: ep += 10
        if dmarc:
            ep += 15
            dl = dmarc.lower()
            if "p=quarantine" in dl: ep += 5
            if "p=reject" in dl: ep += 10
        if dkim_found: ep += 10
        score += min(email_w, ep)

    # DNS (solo dominio)
    dns_w = 25
    if not is_ip:
        weight_total += dns_w
        dp = 0
        if dnssec: dp += 10
        if caa: dp += 10
        score += min(dns_w, dp)

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
            <div class="small">Non penalizza se il dominio non ha posta o sito (moduli non applicabili).</div>
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

DISCLAIMER:
- Analisi basata su dati pubblici/best-effort.
- Scansione porte solo con autorizzazione.
"""
    st.download_button("📥 Scarica report (txt)", report, file_name="security_report.txt")
