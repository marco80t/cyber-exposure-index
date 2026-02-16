import streamlit as st
import requests
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
import dns.resolver
import tldextract

# ============================================================
# CONFIG
# ============================================================
st.set_page_config(page_title="Security Quick Check Pro", page_icon="🛡️", layout="wide")

# ============================================================
# MATRIX UI / CSS (FUTURISTICO)
# ============================================================
def apply_matrix_style():
    st.markdown(
        """
        <style>
        /* Background matrix + overlay scuro */
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

        /* “Grid” tech overlay */
        .stApp:before {
            content: "";
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image:
                linear-gradient(to right, rgba(0,255,136,0.06) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(0,255,136,0.05) 1px, transparent 1px);
            background-size: 60px 60px;
            opacity: 0.20;
            z-index: 0;
        }

        /* Porta avanti il contenuto */
        section.main > div { position: relative; z-index: 1; }

        /* Titoli neon */
        h1, h2, h3, h4 {
            color: #00ff88 !important;
            text-shadow: 0 0 12px rgba(0,255,136,0.55);
            letter-spacing: 0.2px;
        }

        /* Card glass */
        .glass {
            padding: 16px 18px;
            border-radius: 14px;
            border: 1px solid rgba(0,255,136,0.20);
            background: rgba(255,255,255,0.03);
            box-shadow: 0 0 30px rgba(0,255,136,0.07);
            backdrop-filter: blur(8px);
        }

        /* Metric box */
        .stMetric {
            background: rgba(0,255,136,0.05) !important;
            border: 1px solid rgba(0,255,136,0.22) !important;
            border-radius: 14px !important;
            padding: 12px !important;
        }

        /* Bottoni */
        .stButton>button {
            background: linear-gradient(135deg, #00ff88, #00cc6a);
            color: #06120b;
            border-radius: 10px;
            font-weight: 800;
            border: 0;
            box-shadow: 0 0 18px rgba(0,255,136,0.22);
        }
        .stButton>button:hover {
            filter: brightness(1.05);
            box-shadow: 0 0 26px rgba(0,255,136,0.32);
        }

        /* Input */
        .stTextInput input {
            border-radius: 10px !important;
            border: 1px solid rgba(0,255,136,0.25) !important;
            background: rgba(255,255,255,0.03) !important;
        }

        /* Tabs */
        button[data-baseweb="tab"] {
            border-radius: 999px !important;
            margin-right: 8px;
            border: 1px solid rgba(0,255,136,0.15) !important;
            background: rgba(255,255,255,0.02) !important;
        }

        /* Link */
        a { color: #00ff88 !important; }

        /* Piccolo */
        .small { opacity: 0.85; font-size: 0.92rem; }

        /* Radar progress (circolare finto con CSS) */
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
            color:#00ff88;
            text-shadow: 0 0 10px rgba(0,255,136,0.45);
        }

        </style>
        """,
        unsafe_allow_html=True,
    )

apply_matrix_style()

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
        "• I controlli sono basati su informazioni pubbliche.<br>"
        "• La verifica porte è opzionale e va usata <b>solo con autorizzazione</b> del proprietario.<br>"
        "• Nessun brute-force, nessun accesso, nessun exploit."
        "</div>",
        unsafe_allow_html=True
    )
    st.markdown("---")
    show_geo = st.toggle("Mostra Geo/ASN (opzionale)", value=False)
    advanced_ports = st.toggle("Abilita modalità tecnica (porte)", value=False)
    st.markdown("### DKIM (best-effort)")
    dkim_selector = st.text_input("Selector DKIM (opz.)", value="", placeholder="es: selector1")

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
    v = v.split("/")[0]
    return v

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

# WHOIS via RDAP (più “moderno” e spesso meglio del WHOIS classico)
def rdap_domain(domain: str):
    """
    RDAP pubblico. Nota: spesso i dati registrant sono redatti (GDPR).
    """
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=8)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None

def rdap_extract_dates(rdap_json: dict):
    created = None
    expires = None
    updated = None
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

def best_effort_dkim(root: str, selector: str = ""):
    # se non hai selector, proviamo alcuni comuni
    selectors = []
    if selector.strip():
        selectors = [selector.strip()]
    else:
        selectors = ["default", "selector1", "selector2", "google", "k1", "mail", "s1", "s2"]

    found = []
    for s in selectors:
        name = f"{s}._domainkey.{root}"
        txts = dns_txt(name)
        for t in txts:
            if "v=dkim1" in t.lower():
                found.append((s, t))
    return found

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
    target_input = st.text_input("Inserisci Dominio o IP pubblico", value=st.session_state.target_value, placeholder="es: tmconsulenza.it oppure 1.2.3.4")
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
# SUMMARY CARD
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

# ============================================================
# TAB WEB
# ============================================================
with tab_web:
    st.markdown("## 1) Web Reachability & Security Headers")
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

        except Exception as e:
            st.error("Impossibile analizzare via HTTPS (host non raggiungibile / TLS / redirect).")
            header_score = 0

    st.markdown("---")
    st.markdown("## 2) SSL / TLS (best-effort)")
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
    st.markdown("## 3) Modalità tecnica (porte) — solo con autorizzazione")
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
            for sel, rec in dkim_found[:5]:
                st.write(f"Selector: **{sel}**")
                st.code(rec)
            if len(dkim_found) > 5:
                st.info("Altri record DKIM trovati (troncati in output).")
        else:
            st.info("DKIM non rilevato (può essere perché il selector è diverso).")
            st.caption("Suggerimento: se sai il selector del provider (es. Google: selector1/selector2) inseriscilo in sidebar.")

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

        st.markdown("---")
        st.markdown("### SaaS / TXT footprint (soft)")
        txts = dns_txt(root)
        hints = []
        sigs = {
            "google-site-verification": "Google (verification)",
            "ms=": "Microsoft (verification)",
            "atlassian-domain-verification": "Atlassian",
            "v=spf1": "Email (SPF)",
            "stripe-verification": "Stripe",
        }
        for t in txts:
            tl = t.lower()
            for k, v in sigs.items():
                if k in tl:
                    hints.append(v)
        hints = sorted(list(set(hints)))
        if hints:
            st.info("Possibili servizi rilevati: " + ", ".join(hints))
        else:
            st.caption("Nessuna impronta comune trovata nei TXT (ok).")

# ============================================================
# TAB WHOIS/RDAP
# ============================================================
with tab_whois:
    st.markdown("## WHOIS / RDAP (best-effort)")
    if is_ip:
        st.info("WHOIS dominio non applicabile a un IP qui (servirebbe WHOIS ASN/RIR separato).")
    else:
        rd = rdap_domain(root)
        if not rd:
            st.warning("RDAP non disponibile o non risponde per questo dominio.")
        else:
            created, updated, expires = rdap_extract_dates(rd)
            registrar = rd.get("registrarName") or rd.get("entities", [{}])[0].get("vcardArray", ["", []])

            st.markdown("### Dati principali")
            cA, cB, cC = st.columns(3)
            with cA:
                st.metric("Creato", (created or "N/D")[:10])
            with cB:
                st.metric("Aggiornato", (updated or "N/D")[:10])
            with cC:
                st.metric("Scadenza", (expires or "N/D")[:10])

            st.markdown("### Registrar / Status / Nameserver")
            reg_name = rd.get("registrarName") or "N/D"
            st.write(f"**Registrar:** {reg_name}")

            statuses = rd.get("status", [])
            if statuses:
                st.write("**Status:**")
                st.code("\n".join(statuses))
            else:
                st.caption("Status non disponibili.")

            ns = [n.get("ldhName") for n in rd.get("nameservers", []) if n.get("ldhName")]
            if ns:
                st.write("**Nameserver:**")
                st.code("\n".join(ns))
            else:
                st.caption("Nameserver non disponibili.")

            st.markdown("---")
            st.caption("Intestatario/registrant: spesso **redatto** (GDPR). Se il registry lo fornisce, apparirà nei dati RDAP.")
            # Mostra solo un minimo (senza spammare)
            ent = rd.get("entities", [])
            public_roles = []
            for e in ent:
                roles = e.get("roles", [])
                if roles:
                    public_roles.extend(roles)
            if public_roles:
                st.write("Ruoli presenti nel RDAP:")
                st.code(", ".join(sorted(set(public_roles))))

# ============================================================
# TAB SCORE
# ============================================================
with tab_score:
    st.markdown("## Cyber Exposure Index (best-effort)")
    # Score che NON penalizza se non hai posta o non hai sito
    # Logica: se un “modulo” non è applicabile => non pesa sul totale.
    score = 0
    weight_total = 0

    # Web module (solo se dominio)
    web_w = 40
    if not is_ip:
        weight_total += web_w
        web_points = 0
        if status in (200, 301, 302, 307, 308):
            web_points += 10
        if ssl_data and isinstance(ssl_data.get("days_left"), int) and ssl_data["days_left"] > 0:
            web_points += 10
        # headers: fino a 20
        try:
            # header_score definito nella tab web (se errore, ricavo qui)
            sec_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]
            hs = 0
            for h in sec_headers:
                if h in headers:
                    hs += 1
            web_points += min(20, hs * 4)  # 5 headers -> max 20
        except Exception:
            pass
        score += min(web_w, web_points)

    # Email module (solo se hai MX o se trovi SPF/DMARC)
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

    # DNS module (solo se dominio)
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

    # Radar
    st.markdown(
        f"""
        <div class="glass" style="display:flex; gap:22px; align-items:center; justify-content:space-between; flex-wrap:wrap;">
          <div>
            <div class="small">Punteggio normalizzato sui moduli applicabili</div>
            <h2 style="margin:6px 0 0 0;">{final}/100</h2>
            <div class="small">Web/Email/DNS: pesano solo se applicabili (niente “falsi allarmi” se non hai posta o sito).</div>
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
        st.metric("Moduli attivi", f"{int((weight_total>0)) + int(email_applicable) + int((not is_ip))}")
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
