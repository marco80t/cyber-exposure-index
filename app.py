import streamlit as st
import requests
import ssl
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import dns.reversename
import tldextract

# ------------------------------------------------
# CONFIG / UI
# ------------------------------------------------
st.set_page_config(page_title="Security Quick Check Pro", page_icon="🛡️", layout="wide")

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

# ------------------------------------------------
# SIDEBAR
# ------------------------------------------------
with st.sidebar:
    st.markdown("## 🛡️ Security Quick Check Pro")
    try:
        st.image("assets/logo.png", use_container_width=True)
    except Exception:
        pass

    st.markdown("Verifica basata su **dati pubblici** (HTTP / DNS / SSL).")
    st.markdown("---")
    st.markdown("### Contatti")
    st.markdown("🌐 **Sito:** tmconsulenza.it")
    st.markdown("📩 **Email:** info@tmconsulenza.it")
    st.markdown("---")
    st.markdown("### Note legali")
    st.markdown(
        "<div class='small'>"
        "Strumento passivo/best-effort. Nessun test intrusivo. "
        "La modalità tecnica (porte) esegue solo TCP connect su poche porte comuni: "
        "nessun brute-force, nessun exploit, nessun tentativo di accesso. "
        "Usare la modalità tecnica solo con autorizzazione del proprietario."
        "</div>",
        unsafe_allow_html=True
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
    d = d.replace("https://", "").replace("http://", "").split("/")[0]
    return d

def apex_domain(hostname: str) -> str:
    ext = tldextract.extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname

def dns_query(name: str, rtype: str):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout, resolver.lifetime = 2.0, 3.0
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

def reverse_ptr(ip: str):
    try:
        ptr_name = dns.reversename.from_address(ip).to_text()
        return dns_query(ptr_name, "PTR")
    except Exception:
        return []

def fetch_https(host: str):
    r = requests.get(
        f"https://{host}",
        timeout=10,
        allow_redirects=True,
        headers={"User-Agent": "SecurityQuickCheckPro/1.0"},
    )
    return r.url, r.status_code, dict(r.headers), r.history, r

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

def ssl_info(host: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                try:
                    tls_ver = ssock.version()
                except Exception:
                    tls_ver = "N/D"

        not_after = cert.get("notAfter")
        if not not_after:
            return None

        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

        issuer = cert.get("issuer", [])
        issuer_str = ", ".join("=".join(x) for item in issuer for x in item) if issuer else "N/D"
        subject = cert.get("subject", [])
        subject_str = ", ".join("=".join(x) for item in subject for x in item) if subject else "N/D"

        sans = [v for t, v in cert.get("subjectAltName", []) if str(t).lower() == "dns"]

        return {
            "expires": expires,
            "days_left": (expires - datetime.now(timezone.utc)).days,
            "issuer": issuer_str,
            "subject": subject_str,
            "tls_version": tls_ver,
            "san": sans,
        }
    except Exception:
        return None

def analyze_set_cookie(headers: dict):
    raw = headers.get("Set-Cookie")
    if not raw:
        return []

    candidates = raw.split("\n") if "\n" in raw else [raw]
    cookies = []
    for c in candidates:
        cl = c.lower()
        cookies.append({
            "raw": c.strip(),
            "secure": "secure" in cl,
            "httponly": "httponly" in cl,
            "samesite": "samesite=" in cl,
        })
    return cookies

def discover_saas(domain: str):
    txts = dns_txt(domain)
    sigs = {
        "google-site-verification": "Google (Site Verification)",
        "msverify": "Microsoft (Verification)",
        "atlassian-domain-verification": "Atlassian",
        "facebook-domain-verification": "Facebook Business",
        "apple-domain-verification": "Apple Business",
        "stripe": "Stripe",
        "v=spf1": "Email Service (SPF)",
    }
    found = set()
    for t in txts:
        tl = t.lower()
        for k, v in sigs.items():
            if k in tl:
                found.add(v)
    return sorted(list(found))

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
    selectors = ["default", "selector1", "selector2", "google", "smtp", "mail", "dkim", "s1", "s2"]
    found = []
    for s in selectors:
        name = f"{s}._domainkey.{domain_root}"
        for t in dns_txt(name):
            if "v=dkim1" in t.lower():
                found.append((s, t))
                break
    return found

def tcp_connect(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.2):
            return True
    except Exception:
        return False

# ------------------------------------------------
# SESSION STATE (evita UI che “salta” dopo i rerun)
# ------------------------------------------------
if "analyzed" not in st.session_state:
    st.session_state.analyzed = False
if "target_value" not in st.session_state:
    st.session_state.target_value = ""
if "advanced" not in st.session_state:
    st.session_state.advanced = False
if "show_debug" not in st.session_state:
    st.session_state.show_debug = False

# ------------------------------------------------
# MAIN
# ------------------------------------------------
st.title("Security Quick Check Pro")
target = st.text_input(
    "Dominio o IP",
    value=st.session_state.target_value,
    placeholder="esempio.it oppure 8.8.8.8"
)
go = st.button("Analizza")

if go and target:
    st.session_state.analyzed = True
    st.session_state.target_value = target.strip()

# Prima di Analizza: niente sezioni, niente checkbox sparse
if not st.session_state.analyzed or not st.session_state.target_value:
    st.info("Inserisci un dominio/IP e premi **Analizza**.")
    st.stop()

# ------------------------------------------------
# TARGET RESOLUTION
# ------------------------------------------------
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

st.divider()
st.subheader("Riepilogo")
r1, r2, r3 = st.columns(3)
r1.markdown(f"**Target:** `{host}`")
r2.markdown(f"**Tipo:** {'IP' if is_ip else 'Dominio'}")
r3.markdown(f"**IP:** `{resolved_ip}`" if resolved_ip else "**IP:** N/D")

if is_ip and resolved_ip:
    ptr = reverse_ptr(resolved_ip)
    if ptr:
        st.caption(f"PTR (reverse): {ptr[0]}")

# ------------------------------------------------
# IMPOSTAZIONI (unico posto per le “opzioni”)
# ------------------------------------------------
with st.expander("⚙️ Impostazioni", expanded=False):
    st.session_state.advanced = st.checkbox(
        "Modalità tecnica: controllo porte (TCP connect su porte comuni) — solo con autorizzazione",
        value=st.session_state.advanced
    )
    st.session_state.show_debug = st.checkbox(
        "Mostra dettagli tecnici (errori/exception) — solo per troubleshooting",
        value=st.session_state.show_debug
    )

advanced = st.session_state.advanced
show_debug = st.session_state.show_debug

# ------------------------------------------------
# VAR DEFAULT
# ------------------------------------------------
web_applicable = False
email_applicable = False
dns_applicable = False

final_url = None
status = None
headers = {}
history = []
ssl_data = None
h_score = 0
cookie_findings = []

mx = []
spf = None
dmarc = None
dkim_found = []

dnssec = False
caa = []
ns = []
soa = []
aaaa = []
txts = []
saas = []

open_ports_count = None

# ------------------------------------------------
# TABS
# ------------------------------------------------
tab1, tab2, tab3, tab4 = st.tabs(
    ["🌐 Web & Cookie", "📧 Email (SPF/DMARC/DKIM)", "🧬 DNS & SaaS", "📊 Score & Report"]
)

# ---------------- TAB 1: WEB ----------------
with tab1:
    st.subheader("Web Reachability, Redirect Chain, Headers & Cookies")

    if is_ip:
        st.info("N/A: i test Web completi sono affidabili solo su dominio (virtual host / SNI).")
    else:
        try:
            final_url, status, headers, history, resp_obj = fetch_https(host)
            web_applicable = True

            st.success(f"HTTPS OK — Status: {status}")
            st.write(f"URL finale: **{final_url}**")

            if history:
                st.markdown("#### 🔁 Redirect chain")
                for h in history:
                    st.write(f"- {h.status_code} → {h.url}")

            st.markdown("#### 🧾 TLS / SSL (best-effort)")
            ssl_data = ssl_info(host)
            if ssl_data:
                if ssl_data["days_left"] < 0:
                    st.error(f"Certificato SCADUTO ({ssl_data['days_left']} giorni).")
                elif ssl_data["days_left"] < 30:
                    st.warning(f"Certificato in scadenza: {ssl_data['days_left']} giorni.")
                else:
                    st.success(f"Certificato valido: {ssl_data['days_left']} giorni rimanenti.")

                st.write(f"TLS: **{ssl_data['tls_version']}**")
                st.write(f"Issuer: {ssl_data['issuer']}")
                st.write(f"Scadenza: {ssl_data['expires'].strftime('%Y-%m-%d %H:%M UTC')}")
                if ssl_data.get("san"):
                    st.caption(
                        "SAN (DNS): " + ", ".join(ssl_data["san"][:10]) + (" ..." if len(ssl_data["san"]) > 10 else "")
                    )
            else:
                st.warning("TLS non verificabile (best-effort).")

            st.markdown("#### 🛡️ Security Headers")
            security_headers = {
                "Strict-Transport-Security": "HSTS (anti-downgrade)",
                "Content-Security-Policy": "CSP (riduce XSS)",
                "X-Frame-Options": "anti-clickjacking",
                "X-Content-Type-Options": "anti-MIME sniffing",
            }
            h_score = 0
            for h, desc in security_headers.items():
                if h in headers:
                    st.success(f"✔ {h} presente")
                    h_score += 1
                else:
                    st.warning(f"⚠ {h} mancante — {desc}")

            if "Strict-Transport-Security" in headers:
                st.markdown("#### 🔒 HSTS details")
                hsts = parse_hsts(headers.get("Strict-Transport-Security"))
                st.write(f"max-age: **{hsts['max_age']}**")
                st.write(f"includeSubDomains: **{hsts['include_subdomains']}**")
                st.write(f"preload: **{hsts['preload']}**")

            st.markdown("#### 🕵️ Information leakage")
            server = headers.get("Server")
            powered = headers.get("X-Powered-By")
            if server or powered:
                st.warning(
                    f"Leakage: "
                    f"{('Server: ' + server) if server else ''}"
                    f"{(' | X-Powered-By: ' + powered) if powered else ''}"
                )
            else:
                st.success("Nessun header Server/X-Powered-By rilevato.")

            st.markdown("#### 🍪 Cookie security (best-effort da Set-Cookie)")
            cookie_findings = analyze_set_cookie(headers)
            if cookie_findings:
                for c in cookie_findings:
                    flags = []
                    if not c["secure"]:
                        flags.append("Secure mancante")
                    if not c["httponly"]:
                        flags.append("HttpOnly mancante")
                    if not c["samesite"]:
                        flags.append("SameSite mancante")
                    st.code(c["raw"])
                    st.write("✅ OK" if not flags else "⚠ " + " | ".join(flags))
            else:
                st.info("Nessun Set-Cookie rilevato sulla home (può essere normale).")

        except Exception as e:
            web_applicable = False
            st.info("N/A: sito non raggiungibile via HTTPS (non penalizzato).")
            if show_debug:
                st.caption(f"Dettaglio tecnico: {e}")

    st.divider()
    st.markdown("### Porte comuni (solo se Modalità tecnica attiva)")
    if not advanced:
        st.info("Attiva la Modalità tecnica in **Impostazioni** per visualizzare il controllo porte.")
    else:
        st.info("TCP connect su poche porte comuni. Nessun brute-force, nessun exploit, nessun accesso.")
        common_ports = [
            (21, "FTP"), (22, "SSH"), (25, "SMTP"), (53, "DNS"),
            (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
            (443, "HTTPS"), (465, "SMTPS"), (587, "Submission"),
            (993, "IMAPS"), (995, "POP3S"), (3306, "MySQL"), (3389, "RDP"),
        ]
        open_ports_count = 0
        for p, name in common_ports:
            if tcp_connect(host, p):
                st.warning(f"⚠ Porta {p} ({name}) aperta (best-effort)")
                open_ports_count += 1
            else:
                st.success(f"✔ Porta {p} ({name}) chiusa")
        if open_ports_count == 0:
            st.success("✔ Nessuna porta comune risulta esposta (best-effort).")

# ---------------- TAB 2: EMAIL ----------------
with tab2:
    st.subheader("Email Security: MX / SPF / DMARC / DKIM (best-effort)")

    if is_ip:
        st.info("N/A: controlli Email richiedono un dominio.")
    else:
        mx = dns_query(root, "MX")
        email_applicable = bool(mx)

        if not email_applicable:
            st.info("N/A: nessun record MX rilevato → il dominio probabilmente NON gestisce posta (non penalizzato).")
        else:
            st.markdown("#### MX")
            for m in mx:
                st.write(f"- {m}")

            st.markdown("#### SPF / DMARC")
            spf = find_spf(root)
            dmarc = find_dmarc(root)

            if spf:
                st.success("✅ SPF presente")
                st.code(spf)
            else:
                st.error("❌ SPF mancante (rischio spoofing più alto)")

            if dmarc:
                st.success("✅ DMARC presente")
                st.code(dmarc)
            else:
                st.warning("⚠ DMARC mancante (nessuna policy/monitoring)")

            st.markdown("#### DKIM (best-effort)")
            dkim_found = dkim_best_effort(root)
            if dkim_found:
                st.success(f"✅ DKIM trovato (best-effort) — {len(dkim_found)} selector")
                for sel, rec in dkim_found:
                    st.write(f"Selector: **{sel}**")
                    st.code(rec)
            else:
                st.warning("⚠ DKIM non trovato nei selector comuni (potrebbe esserci con selector custom).")

# ---------------- TAB 3: DNS ----------------
with tab3:
    st.subheader("DNS Posture & SaaS Discovery (best-effort)")

    if is_ip:
        st.info("N/A: DNS posture richiede un dominio (su IP usiamo PTR).")
    else:
        ns = dns_query(root, "NS")
        soa = dns_query(root, "SOA")
        caa = dns_query(root, "CAA")
        ds = dns_query(root, "DS")
        a_rec = dns_query(host, "A")
        aaaa = dns_query(host, "AAAA")
        txts = dns_txt(root)

        dnssec = bool(ds)
        dns_applicable = bool(ns) or bool(soa) or bool(caa) or bool(ds) or bool(a_rec) or bool(aaaa)

        if not dns_applicable:
            st.info("N/A/Inconclusivo: DNS non risponde alle query principali (timeout/policy). (Non penalizzato).")
        else:
            st.markdown("#### NS / SOA")
            if ns:
                st.write("**NS:**")
                for n in ns:
                    st.write(f"- {n}")
            if soa:
                st.write("**SOA:**")
                st.write(f"- {soa[0]}")

            st.markdown("#### Records A / AAAA")
            if a_rec:
                st.write(f"A: {a_rec}")
            if aaaa:
                st.write(f"AAAA: {aaaa}")

            st.markdown("#### DNSSEC / CAA")
            if dnssec:
                st.success("✅ DNSSEC attivo (DS presente)")
            else:
                st.info("ℹ️ DNSSEC non attivo (comune, ma meno sicuro)")

            if caa:
                st.success("✅ CAA presente")
                st.code("\n".join(caa))
            else:
                st.warning("⚠ CAA mancante")

        st.divider()
        st.markdown("#### SaaS / Third-party hints (TXT)")
        saas = discover_saas(root)
        if saas:
            st.write("Servizi potenzialmente rilevati:")
            for s in saas:
                st.write(f"- {s}")
        else:
            st.info("Nessuna impronta SaaS comune trovata nei TXT (best-effort).")

# ---------------- TAB 4: SCORE ----------------
with tab4:
    st.subheader("Score normalizzato (non penalizza N/A)")

    # WEB max 40, EMAIL max 35, DNS max 25
    web_points = 0
    web_possible = 0

    email_points = 0
    email_possible = 0

    dns_points = 0
    dns_possible = 0

    # WEB (solo se applicabile e target è dominio)
    if web_applicable and not is_ip:
        web_possible = 40
        if status in (200, 301, 302, 307, 308):
            web_points += 10
        if ssl_data and isinstance(ssl_data.get("days_left"), int) and ssl_data["days_left"] > 0:
            web_points += 10
        web_points += min(20, h_score * 5)

    # EMAIL (solo se MX)
    if email_applicable and not is_ip:
        email_possible = 35
        if spf:
            email_points += 10
        if dmarc:
            email_points += 15
            dl = dmarc.lower()
            if "p=quarantine" in dl:
                email_points += 5
            if "p=reject" in dl:
                email_points += 10
        if dkim_found:
            email_points += 5
        email_points = min(email_points, 35)

    # DNS (solo se applicabile)
    if dns_applicable and not is_ip:
        dns_possible = 25
        if dnssec:
            dns_points += 10
        if caa:
            dns_points += 10
        dns_points = min(dns_points, 25)

    earned = web_points + email_points + dns_points
    possible = web_possible + email_possible + dns_possible

    if possible == 0:
        total = 0
        st.warning("Valutazione NON conclusiva: pochi controlli applicabili o target non raggiungibile.")
    else:
        total = round((earned / possible) * 100)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Web", f"{web_points}/{web_possible}" if web_possible else "N/A")
    with c2:
        st.metric("Email", f"{email_points}/{email_possible}" if email_possible else "N/A")
    with c3:
        st.metric("DNS", f"{dns_points}/{dns_possible}" if dns_possible else "N/A")

    st.progress(total / 100)
    st.metric("Punteggio", f"{total}/100")

    if possible < 40:
        st.info("Coverage basso: alcuni controlli non applicabili (es. no web/no email).")
    else:
        if total < 40:
            st.error("Livello di esposizione: ALTO")
        elif total < 75:
            st.warning("Livello di esposizione: MEDIO")
        else:
            st.success("Livello di esposizione: BASSO")

    st.divider()
    report_lines = []
    report_lines.append("Security Quick Check Pro - Report")
    report_lines.append(f"Data: {datetime.now().isoformat()}")
    report_lines.append(f"Target: {host} ({'IP' if is_ip else 'Dominio'})")
    if root:
        report_lines.append(f"Root: {root}")
    if resolved_ip:
        report_lines.append(f"IP: {resolved_ip}")
    report_lines.append("")
    report_lines.append(f"SCORE: {total}/100 (coverage: {possible})")
    report_lines.append(f"Web: {web_points}/{web_possible} | Email: {email_points}/{email_possible} | DNS: {dns_points}/{dns_possible}")
    report_lines.append("")
    report_lines.append("Note: analisi passiva/best-effort su dati pubblici. Porte: TCP connect su porte comuni (se abilitato).")
    report = "\n".join(report_lines)

    st.download_button("Scarica Report (TXT)", report, file_name="security_report.txt")
