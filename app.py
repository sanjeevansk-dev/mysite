"""
Nimbus - professional login & register website (Python standard library only).

Run locally:  python app.py   ->  http://localhost:8000
On hosting (Render etc.) the PORT is picked up automatically.

Features
  - Split-screen responsive design, automatic dark mode
  - Register (full name, username, email, password) and login with username OR email
  - Show/hide password, live password-strength meter, live "passwords match" check
  - Remember me, secure logout, protected dashboard
  - Security: PBKDF2 password hashing, CSRF tokens, login rate-limiting,
    HttpOnly + SameSite cookies, session expiry, security headers
"""
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import threading
import time
import urllib.request
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BRAND = "Sanjeevan"
PORT = int(os.environ.get("PORT", 8000))
HOST = "0.0.0.0" if "PORT" in os.environ else "localhost"
DB_FILE = os.environ.get(
    "DB_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
)

SESSIONS = {}            # token -> {"uid": int, "exp": float}
ATTEMPTS = {}            # (ip, login) -> [timestamps of failed logins]
MAX_ATTEMPTS, WINDOW = 5, 300          # 5 failures per 5 minutes
SHORT_SESSION, LONG_SESSION = 12 * 3600, 30 * 24 * 3600

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ------------------------------------------------------------------ database
# Uses Postgres when DATABASE_URL is set (Render); falls back to a local
# SQLite file so `python app.py` still works on your own computer.
_url = os.environ.get("DATABASE_URL", "").strip()
if _url:
    for _prefix in ("postgres://", "postgresql://"):
        if _url.startswith(_prefix):
            _url = "postgresql+psycopg://" + _url[len(_prefix):]
            break
else:
    _url = "sqlite:///" + DB_FILE
engine = create_engine(_url, pool_pre_ping=True)
IS_PG = engine.dialect.name == "postgresql"


def init_db():
    pk = "SERIAL PRIMARY KEY" if IS_PG else "INTEGER PRIMARY KEY AUTOINCREMENT"
    blob = "BYTEA" if IS_PG else "BLOB"
    with engine.begin() as conn:
        conn.execute(text(
            f"""CREATE TABLE IF NOT EXISTS users (
                   id {pk},
                   username TEXT UNIQUE NOT NULL,
                   email TEXT UNIQUE NOT NULL,
                   salt {blob} NOT NULL,
                   password_hash {blob} NOT NULL,
                   fullname TEXT DEFAULT '',
                   created_at TEXT DEFAULT ''
               )"""
        ))
        conn.execute(text(
            f"""CREATE TABLE IF NOT EXISTS login_events (
                   id {pk},
                   username TEXT NOT NULL,
                   event TEXT NOT NULL,
                   ip TEXT DEFAULT '',
                   city TEXT DEFAULT '',
                   region TEXT DEFAULT '',
                   country TEXT DEFAULT '',
                   created_at TEXT DEFAULT ''
               )"""
        ))


def _fetch_json(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (compatible; SanjeevanSite/1.0)",
        "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=4) as r:
        return json.loads(r.read().decode())


def lookup_geo(ip):
    """Approximate (city, region, country) for a public IP; blanks if unavailable.
    Tries several free services in turn and logs why each one failed."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        print("geo skipped: not a valid IP:", repr(ip))
        return "", "", ""
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
        print("geo skipped: private/local IP", addr)
        return "", "", ""
    providers = (
        (f"https://ipwho.is/{addr}",
         lambda d: (d.get("city"), d.get("region"), d.get("country")) if d.get("success") else None),
        (f"https://ipapi.co/{addr}/json/",
         lambda d: (d.get("city"), d.get("region"), d.get("country_name")) if not d.get("error") else None),
        (f"http://ip-api.com/json/{addr}?fields=status,country,regionName,city",
         lambda d: (d.get("city"), d.get("regionName"), d.get("country")) if d.get("status") == "success" else None),
    )
    for url, pick in providers:
        try:
            d = _fetch_json(url)
            got = pick(d)
            if got and any(got):
                return tuple(x or "" for x in got)
            print("geo no result from", url.split("/")[2], str(d)[:150])
        except Exception as e:
            print("geo lookup failed:", url.split("/")[2], e)
    return "", "", ""


def record_event(username, event, ip):
    """Save IP + location in the background so the page never waits for the lookup."""
    def work():
        city, region, country = lookup_geo(ip)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text("INSERT INTO login_events (username,event,ip,city,region,country,created_at) "
                         "VALUES (:u,:ev,:ip,:ci,:re,:co,:c)"),
                    {"u": username, "ev": event, "ip": (ip or "")[:45], "ci": city,
                     "re": region, "co": country, "c": now_iso()},
                )
        except Exception as e:
            print("login_events insert failed:", e)
    threading.Thread(target=work, daemon=True).start()


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)


# ------------------------------------------------------------------ design
ICON = {
    "user": '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    "mail": '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/>',
    "lock": '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "eye": '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    "bolt": '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
    "users": '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
    "logout": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
    "alert": '<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>',
    "check": '<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
    "clock": '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
}


def icon(name, size=18):
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
            f'stroke-linejoin="round" aria-hidden="true">{ICON[name]}</svg>')


STYLE = """
:root{--bg:#f4f6fb;--card:#fff;--text:#0f172a;--muted:#64748b;--line:#e2e8f0;
--primary:#4f46e5;--primary2:#7c3aed;--primary-dark:#4338ca;--ring:rgba(79,70,229,.25);
--err-bg:#fef2f2;--err:#b91c1c;--ok-bg:#f0fdf4;--ok:#15803d;--input:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#0b1020;--card:#111831;--text:#e5e9f5;
--muted:#94a3b8;--line:#25304f;--ring:rgba(129,140,248,.35);--err-bg:#3b1219;--err:#fca5a5;
--ok-bg:#0f2a1c;--ok:#86efac;--input:#0b1226}}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
background:var(--bg);color:var(--text);-webkit-font-smoothing:antialiased}
a{color:var(--primary);text-decoration:none;font-weight:600}a:hover{text-decoration:underline}
.logo{display:flex;align-items:center;gap:10px;font-weight:800;font-size:20px;letter-spacing:-.3px}
.logo i{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;color:#fff;
background:linear-gradient(135deg,var(--primary),var(--primary2));box-shadow:0 6px 16px var(--ring)}

/* split layout */
.split{display:grid;grid-template-columns:1.05fr 1fr;min-height:100vh}
.brand{position:relative;overflow:hidden;color:#fff;padding:48px 56px;display:flex;
flex-direction:column;justify-content:space-between;
background:radial-gradient(900px 500px at 10% -10%,#6366f1 0,transparent 60%),
radial-gradient(700px 500px at 100% 100%,#a855f7 0,transparent 55%),#1e1b4b}
.brand:before,.brand:after{content:"";position:absolute;border-radius:50%;
border:1px solid rgba(255,255,255,.12)}
.brand:before{width:520px;height:520px;right:-180px;top:-140px}
.brand:after{width:360px;height:360px;left:-120px;bottom:-120px}
.brand .logo i{background:rgba(255,255,255,.16);box-shadow:none;backdrop-filter:blur(6px)}
.brand h2{font-size:38px;line-height:1.15;margin:0 0 14px;letter-spacing:-1px;max-width:460px}
.brand p.lead{margin:0 0 34px;color:#c7d2fe;font-size:16px;max-width:430px;line-height:1.6}
.feat{display:flex;gap:14px;margin-bottom:18px;align-items:flex-start;position:relative;z-index:1}
.feat span{flex:none;width:40px;height:40px;border-radius:12px;display:grid;place-items:center;
background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.18)}
.feat b{display:block;font-size:15px}.feat small{color:#c7d2fe;font-size:13.5px}
.brand footer{color:#a5b4fc;font-size:13px;position:relative;z-index:1}
.panel{display:flex;align-items:center;justify-content:center;padding:32px 24px}
.box{width:100%;max-width:410px}
.box .logo.m{display:none;margin-bottom:28px}
.box h1{font-size:30px;margin:0 0 6px;letter-spacing:-.8px}
.box .sub{color:var(--muted);margin:0 0 26px;font-size:15px}

/* form */
label{display:block;font-size:13.5px;font-weight:600;margin:16px 0 7px}
.field{position:relative}
.field>svg{position:absolute;left:13px;top:50%;transform:translateY(-50%);color:var(--muted);pointer-events:none}
.field input{width:100%;height:46px;padding:0 44px 0 42px;border:1px solid var(--line);
border-radius:11px;background:var(--input);color:var(--text);font:inherit;font-size:15px;
transition:border-color .15s,box-shadow .15s}
.field input::placeholder{color:#94a3b8}
.field input:focus{outline:0;border-color:var(--primary);box-shadow:0 0 0 4px var(--ring)}
.toggle{position:absolute;right:6px;top:50%;transform:translateY(-50%);border:0;background:none;
color:var(--muted);cursor:pointer;padding:8px;border-radius:8px;display:grid}
.toggle:hover{color:var(--text);background:var(--line)}
.row{display:flex;justify-content:space-between;align-items:center;margin-top:16px;font-size:14px}
.check{display:flex;gap:9px;align-items:flex-start;font-weight:500;color:var(--muted);font-size:14px;margin:0;cursor:pointer}
.check input{width:17px;height:17px;margin:1px 0 0;accent-color:var(--primary)}
.btn{width:100%;height:48px;margin-top:22px;border:0;border-radius:11px;cursor:pointer;color:#fff;
font:inherit;font-size:15.5px;font-weight:700;display:flex;align-items:center;justify-content:center;gap:10px;
background:linear-gradient(135deg,var(--primary),var(--primary2));box-shadow:0 8px 20px var(--ring);
transition:transform .1s,filter .15s}
.btn:hover{filter:brightness(1.07)}.btn:active{transform:translateY(1px)}
.btn[disabled]{opacity:.75;cursor:wait}
.btn.ghost{background:var(--card);color:var(--text);border:1px solid var(--line);box-shadow:none;margin-top:0;width:auto;
height:40px;padding:0 16px;font-size:14px}
.spin{width:16px;height:16px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;
animation:r .7s linear infinite;display:none}.btn[disabled] .spin{display:block}
@keyframes r{to{transform:rotate(360deg)}}
.alt{text-align:center;margin-top:24px;font-size:14.5px;color:var(--muted)}
.alert{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:11px;font-size:14px;margin-bottom:6px;line-height:1.45}
.alert svg{flex:none;margin-top:1px}
.alert.err{background:var(--err-bg);color:var(--err)}.alert.ok{background:var(--ok-bg);color:var(--ok)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.meter{display:flex;gap:5px;margin-top:9px}.meter i{flex:1;height:5px;border-radius:5px;background:var(--line);transition:background .2s}
.hint{font-size:12.5px;color:var(--muted);margin-top:6px;min-height:16px}
.hint.bad{color:var(--err)}.hint.good{color:var(--ok)}

/* dashboard */
.top{display:flex;align-items:center;justify-content:space-between;padding:14px 32px;background:var(--card);
border-bottom:1px solid var(--line);position:sticky;top:0}
.user{display:flex;align-items:center;gap:12px}
.avatar{width:38px;height:38px;border-radius:50%;display:grid;place-items:center;color:#fff;font-weight:700;
background:linear-gradient(135deg,var(--primary),var(--primary2))}
.wrap{max-width:1040px;margin:0 auto;padding:36px 24px}
.hero{border-radius:20px;padding:34px;color:#fff;margin-bottom:24px;
background:radial-gradient(600px 300px at 90% 0,#a855f7 0,transparent 60%),linear-gradient(135deg,#4f46e5,#3730a3)}
.hero h1{margin:0 0 8px;font-size:30px;letter-spacing:-.8px}.hero p{margin:0;color:#c7d2fe}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(290px,1fr));gap:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:24px}
.card h3{margin:0 0 16px;font-size:16px;display:flex;align-items:center;gap:10px}
.card h3 span{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;
background:var(--ring);color:var(--primary)}
dl{margin:0}dt{font-size:12.5px;color:var(--muted);margin-top:14px}dd{margin:3px 0 0;font-weight:600;word-break:break-all}
.badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:12.5px;font-weight:700;background:var(--ok-bg);color:var(--ok)}

@media(max-width:900px){.split{grid-template-columns:1fr}.brand{display:none}
.box .logo.m{display:flex}.top{padding:12px 18px}}
@media(max-width:420px){.two{grid-template-columns:1fr}}
"""

SCRIPT = """
document.querySelectorAll('.toggle').forEach(function(b){b.addEventListener('click',function(){
var i=document.getElementById(b.dataset.target);i.type=i.type==='password'?'text':'password';});});
document.querySelectorAll('form').forEach(function(f){f.addEventListener('submit',function(e){
if(f.dataset.bad){e.preventDefault();return;}
var btn=f.querySelector('.btn');if(btn){btn.disabled=true;}});});
var pw=document.getElementById('password'),cf=document.getElementById('confirm');
if(pw&&document.getElementById('meter')){
var bars=document.querySelectorAll('#meter i'),hint=document.getElementById('strength');
var cols=['#ef4444','#f59e0b','#84cc16','#22c55e'],names=['Weak','Fair','Good','Strong'];
pw.addEventListener('input',function(){var v=pw.value,s=0;
if(v.length>=8)s++;if(/[a-z]/.test(v)&&/[A-Z]/.test(v))s++;if(/\\d/.test(v))s++;if(/[^A-Za-z0-9]/.test(v))s++;
if(v.length<8)s=Math.min(s,1);
bars.forEach(function(b,i){b.style.background=(v&&i<s)?cols[s-1]:'';});
hint.textContent=v?names[Math.max(s-1,0)]+' password':'Use 8+ characters with letters and numbers';
hint.className='hint'+(v&&s>=3?' good':'');check();});
function check(){var m=document.getElementById('match');if(!cf.value){m.textContent='';m.className='hint';
cf.form.dataset.bad='';return;}
if(cf.value===pw.value){m.textContent='Passwords match';m.className='hint good';cf.form.dataset.bad='';}
else{m.textContent='Passwords do not match';m.className='hint bad';cf.form.dataset.bad='1';}}
cf.addEventListener('input',check);}
"""


def page(title, body, extra_body_class=""):
    return (f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{html.escape(title)} - {BRAND}</title><style>{STYLE}</style></head>'
            f'<body class="{extra_body_class}">{body}<script>{SCRIPT}</script></body></html>')


def logo(extra=""):
    return (f'<div class="logo {extra}"><i>{icon("shield", 20)}</i>{BRAND}</div>')


def alert(text, kind):
    if not text:
        return ""
    return (f'<div class="alert {kind}">{icon("alert" if kind == "err" else "check")}'
            f'<div>{html.escape(text)}</div></div>')


def field(name, label, itype, ico, placeholder, csrf_free=True, extra="", toggle=False, value=""):
    tog = (f'<button type="button" class="toggle" data-target="{name}" aria-label="Show or hide password">'
           f'{icon("eye")}</button>') if toggle else ""
    return (f'<label for="{name}">{label}</label><div class="field">{icon(ico)}'
            f'<input id="{name}" name="{name}" type="{itype}" placeholder="{placeholder}" '
            f'value="{html.escape(value)}" {extra}>{tog}</div>')


def split(heading, sub, form_html):
    side = f"""<section class="brand">
{logo()}
<div><h2>Everything you need, one secure account.</h2>
<p class="lead">Sign in to manage your account, keep your data safe and pick up right where you left off.</p>
<div class="feat"><span>{icon("shield", 20)}</span><div><b>Bank-grade protection</b><small>Passwords are salted and hashed with PBKDF2.</small></div></div>
<div class="feat"><span>{icon("bolt", 20)}</span><div><b>Fast and reliable</b><small>Lightweight, quick to load on any device.</small></div></div>
<div class="feat"><span>{icon("users", 20)}</span><div><b>Built for everyone</b><small>Works across phones, tablets and desktops.</small></div></div></div>
<footer>&copy; {datetime.now().year} {BRAND}. All rights reserved.</footer></section>"""
    main = (f'<section class="panel"><div class="box">{logo("m")}<h1>{heading}</h1>'
            f'<p class="sub">{sub}</p>{form_html}</div></section>')
    return f'<div class="split">{side}{main}</div>'


def submit(label):
    return f'<button class="btn" type="submit"><span class="spin"></span>{label}</button>'


def login_page(csrf, error="", ok="", login=""):
    form = f"""{alert(error, "err")}{alert(ok, "ok")}
<form method="post" action="/login" autocomplete="on">
<input type="hidden" name="csrf" value="{csrf}">
{field("login", "Username or email", "text", "user", "you@example.com", extra='required autofocus autocomplete="username"', value=login)}
{field("password", "Password", "password", "lock", "Enter your password", extra='required autocomplete="current-password"', toggle=True)}
<div class="row"><label class="check"><input type="checkbox" name="remember" value="1"> Remember me for 30 days</label></div>
{submit("Sign in")}
</form><div class="alt">New to {BRAND}? <a href="/register">Create an account</a></div>"""
    return page("Sign in", split("Welcome back", "Sign in to continue to your account.", form))


def register_page(csrf, error="", vals=None):
    v = vals or {}
    form = f"""{alert(error, "err")}
<form method="post" action="/register" autocomplete="on">
<input type="hidden" name="csrf" value="{csrf}">
{field("fullname", "Full name", "text", "user", "Jane Doe", extra='required maxlength="60" autofocus autocomplete="name"', value=v.get("fullname", ""))}
<div class="two">
<div>{field("username", "Username", "text", "user", "jane_doe", extra='required minlength="3" maxlength="20" pattern="[A-Za-z0-9_]+" autocomplete="username"', value=v.get("username", ""))}</div>
<div>{field("email", "Email", "email", "mail", "jane@mail.com", extra='required autocomplete="email"', value=v.get("email", ""))}</div></div>
{field("password", "Password", "password", "lock", "Create a password", extra='required minlength="8" autocomplete="new-password"', toggle=True)}
<div class="meter" id="meter"><i></i><i></i><i></i><i></i></div>
<div class="hint" id="strength">Use 8+ characters with letters and numbers</div>
{field("confirm", "Confirm password", "password", "lock", "Repeat your password", extra='required autocomplete="new-password"', toggle=True)}
<div class="hint" id="match"></div>
<div class="row"><label class="check"><input type="checkbox" name="terms" value="1" required> I agree to the Terms of Service and Privacy Policy</label></div>
{submit("Create account")}
</form><div class="alt">Already have an account? <a href="/login">Sign in</a></div>"""
    return page("Create account", split("Create your account", "It only takes a minute to get started.", form))


def dashboard_page(csrf, u):
    name = u["fullname"] or u["username"]
    initials = "".join(p[0] for p in name.split()[:2]).upper() or "U"
    since = u["created_at"][:10] if u["created_at"] else "-"
    body = f"""<header class="top">{logo()}<div class="user">
<div class="avatar">{html.escape(initials)}</div><div><b>{html.escape(name)}</b></div>
<form method="post" action="/logout" style="margin:0"><input type="hidden" name="csrf" value="{csrf}">
<button class="btn ghost" type="submit">{icon("logout", 16)} Log out</button></form></div></header>
<main class="wrap"><section class="hero"><h1>Welcome, {html.escape(name.split()[0])}!</h1>
<p>You are signed in securely. Here is an overview of your account.</p></section>
<div class="grid">
<div class="card"><h3><span>{icon("user")}</span>Profile</h3><dl>
<dt>Full name</dt><dd>{html.escape(u["fullname"] or "-")}</dd>
<dt>Username</dt><dd>@{html.escape(u["username"])}</dd>
<dt>Email</dt><dd>{html.escape(u["email"])}</dd></dl></div>
<div class="card"><h3><span>{icon("clock")}</span>Account</h3><dl>
<dt>Member since</dt><dd>{html.escape(since)}</dd>
<dt>Status</dt><dd><span class="badge">Active</span></dd>
<dt>Account ID</dt><dd>#{u["id"]}</dd></dl></div>
<div class="card"><h3><span>{icon("shield")}</span>Security</h3><dl>
<dt>Password storage</dt><dd>PBKDF2-SHA256, salted</dd>
<dt>Session</dt><dd>Protected cookie, auto-expires</dd>
<dt>Login protection</dt><dd>Rate limited, CSRF protected</dd></dl></div>
</div></main>"""
    return page("Dashboard", body)


def not_found_page():
    body = (f'<div class="panel" style="min-height:100vh"><div class="box" style="text-align:center">'
            f'{logo().replace("logo", "logo", 1)}<h1 style="margin-top:28px">404</h1>'
            f'<p class="sub">This page does not exist.</p><a href="/">Back to home</a></div></div>')
    return page("Not found", body)


# ------------------------------------------------------------------ server
def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class Handler(BaseHTTPRequestHandler):
    server_version = "Nimbus"

    # ---- helpers
    def cookie(self, name):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return jar[name].value if name in jar else None

    def client_ip(self):
        # Render sits behind Cloudflare, which sets True-Client-IP (cannot be faked
        # by visitors). X-Forwarded-For is only a fallback because it can be spoofed.
        for h in ("True-Client-IP", "CF-Connecting-IP"):
            v = (self.headers.get(h) or "").strip()
            if v:
                return v
        fwd = self.headers.get("X-Forwarded-For")
        return fwd.split(",")[0].strip() if fwd else self.client_address[0]

    def secure_flag(self):
        return "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""

    def current_user(self):
        token = self.cookie("session")
        s = SESSIONS.get(token)
        if not s or s["exp"] < time.time():
            SESSIONS.pop(token, None)
            return None
        with engine.connect() as conn:
            return conn.execute(text("SELECT * FROM users WHERE id=:id"),
                                {"id": s["uid"]}).mappings().first()

    def csrf_token(self):
        """Return (token, is_new). Token lives in a cookie and in a hidden form field."""
        t = self.cookie("csrf")
        return (t, False) if t else (secrets.token_urlsafe(24), True)

    def send_html(self, content, status=200, headers=(), csrf=None):
        data = content.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        if csrf and csrf[1]:
            self.send_header("Set-Cookie",
                             f"csrf={csrf[0]}; HttpOnly; SameSite=Strict; Path=/{self.secure_flag()}")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, path, headers=()):
        self.send_response(303)
        self.send_header("Location", path)
        self.send_header("Cache-Control", "no-store")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()

    def read_form(self):
        n = min(int(self.headers.get("Content-Length") or 0), 20_000)
        raw = parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        return {k: v[0] for k, v in raw.items()}

    def csrf_ok(self, form):
        a, b = self.cookie("csrf") or "", form.get("csrf", "")
        return bool(a) and hmac.compare_digest(a, b)

    # ---- GET
    def do_GET(self):
        path = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query)
        if path == "/health":
            return self.send_html("ok")
        user = self.current_user()
        csrf = self.csrf_token()
        if path in ("/", "/login"):
            if user:
                return self.redirect("/dashboard")
            ok = "Account created! Please sign in." if "registered" in q else (
                "You have been signed out." if "out" in q else "")
            return self.send_html(login_page(csrf[0], ok=ok), csrf=csrf)
        if path == "/register":
            if user:
                return self.redirect("/dashboard")
            return self.send_html(register_page(csrf[0]), csrf=csrf)
        if path == "/dashboard":
            if not user:
                return self.redirect("/login")
            return self.send_html(dashboard_page(csrf[0], user), csrf=csrf)
        self.send_html(not_found_page(), 404)

    # ---- POST
    def do_POST(self):
        path = urlparse(self.path).path
        form = self.read_form()
        csrf = self.csrf_token()
        if not self.csrf_ok(form):
            msg = "Your session expired. Please try again."
            if path == "/register":
                return self.send_html(register_page(csrf[0], msg), 403, csrf=csrf)
            return self.send_html(login_page(csrf[0], error=msg), 403, csrf=csrf)
        if path == "/register":
            return self.do_register(form, csrf)
        if path == "/login":
            return self.do_login(form, csrf)
        if path == "/logout":
            SESSIONS.pop(self.cookie("session"), None)
            return self.redirect("/login?out=1",
                                 [("Set-Cookie", f"session=; Max-Age=0; Path=/; HttpOnly{self.secure_flag()}")])
        self.send_html(not_found_page(), 404)

    def do_register(self, f, csrf):
        vals = {k: f.get(k, "").strip() for k in ("fullname", "username", "email")}
        password, confirm = f.get("password", ""), f.get("confirm", "")

        def fail(msg):
            self.send_html(register_page(csrf[0], msg, vals), 400, csrf=csrf)

        if not vals["fullname"]:
            return fail("Please enter your full name.")
        if not USERNAME_RE.match(vals["username"]):
            return fail("Username must be 3-20 characters: letters, numbers or underscore.")
        if not EMAIL_RE.match(vals["email"]):
            return fail("Please enter a valid email address.")
        if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
            return fail("Password must be at least 8 characters and include a letter and a number.")
        if password != confirm:
            return fail("Passwords do not match.")
        if not f.get("terms"):
            return fail("You must accept the Terms of Service.")
        salt = os.urandom(16)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text("INSERT INTO users (username,email,salt,password_hash,fullname,created_at) "
                         "VALUES (:u,:e,:s,:p,:f,:c)"),
                    {"u": vals["username"], "e": vals["email"].lower(), "s": salt,
                     "p": hash_password(password, salt), "f": vals["fullname"][:60],
                     "c": now_iso()},
                )
        except IntegrityError:
            return fail("That username or email is already registered.")
        record_event(vals["username"], "register", self.client_ip())
        self.redirect("/login?registered=1")

    def do_login(self, f, csrf):
        login, password = f.get("login", "").strip(), f.get("password", "")
        key = (self.client_ip(), login.lower())
        recent = [t for t in ATTEMPTS.get(key, []) if time.time() - t < WINDOW]
        ATTEMPTS[key] = recent
        if len(recent) >= MAX_ATTEMPTS:
            return self.send_html(login_page(csrf[0], error="Too many failed attempts. "
                                             "Please wait a few minutes and try again.", login=login),
                                  429, csrf=csrf)
        with engine.connect() as conn:
            row = conn.execute(text("SELECT * FROM users WHERE username=:u OR email=:e"),
                               {"u": login, "e": login.lower()}).mappings().first()
        salt = bytes(row["salt"]) if row else b"\x00" * 16   # same work either way
        digest = hash_password(password, salt)
        if not row or not hmac.compare_digest(digest, bytes(row["password_hash"])):
            ATTEMPTS[key].append(time.time())
            return self.send_html(login_page(csrf[0], error="Incorrect username/email or password.",
                                             login=login), 401, csrf=csrf)
        ATTEMPTS.pop(key, None)
        record_event(row["username"], "login", self.client_ip())
        ttl = LONG_SESSION if f.get("remember") else SHORT_SESSION
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = {"uid": row["id"], "exp": time.time() + ttl}
        age = f"; Max-Age={ttl}" if f.get("remember") else ""
        self.redirect("/dashboard", [("Set-Cookie",
                      f"session={token}; HttpOnly; SameSite=Strict; Path=/{age}{self.secure_flag()}")])

    def log_message(self, fmt, *args):
        print(f"{self.client_ip()} - {fmt % args}")


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"{BRAND} running at http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
