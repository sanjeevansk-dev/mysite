"""
Simple login + register website using only the Python standard library.

Run:   python app.py
Open:  http://localhost:8000
"""
import hashlib
import hmac
import html
import os
import secrets
import sqlite3
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

PORT = int(os.environ.get("PORT", 8000))  # hosting sites set PORT automatically
HOST = "0.0.0.0" if "PORT" in os.environ else "localhost"
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
SESSIONS = {}  # session token -> username (cleared when the server restarts)


# ---------- database ----------
def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   email TEXT UNIQUE NOT NULL,
                   salt BLOB NOT NULL,
                   password_hash BLOB NOT NULL
               )"""
        )


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)


# ---------- html ----------
STYLE = """
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:linear-gradient(135deg,#4f46e5,#9333ea)}
.card{background:#fff;width:100%;max-width:380px;padding:32px;border-radius:16px;
box-shadow:0 20px 50px rgba(0,0,0,.25)}
h1{margin:0 0 20px;font-size:26px;color:#111827}
label{display:block;font-size:14px;color:#374151;margin:14px 0 6px}
input{width:100%;padding:11px 12px;border:1px solid #d1d5db;border-radius:8px;font-size:15px}
input:focus{outline:2px solid #6366f1;border-color:transparent}
button{width:100%;margin-top:22px;padding:12px;border:0;border-radius:8px;
background:#4f46e5;color:#fff;font-size:16px;font-weight:600;cursor:pointer}
button:hover{background:#4338ca}
.msg{padding:10px 12px;border-radius:8px;font-size:14px;margin-bottom:8px}
.err{background:#fee2e2;color:#991b1b}.ok{background:#dcfce7;color:#166534}
.alt{text-align:center;margin-top:18px;font-size:14px;color:#6b7280}
a{color:#4f46e5;text-decoration:none;font-weight:600}
"""


def page(title, body):
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{STYLE}</style></head>
<body><div class="card">{body}</div></body></html>"""


def message(text, kind):
    return f'<div class="msg {kind}">{html.escape(text)}</div>' if text else ""


def login_page(error="", ok=""):
    return page("Login", f"""<h1>Welcome back</h1>{message(error, "err")}{message(ok, "ok")}
<form method="post" action="/login">
<label>Username</label><input name="username" required autofocus>
<label>Password</label><input name="password" type="password" required>
<button>Log in</button></form>
<div class="alt">No account? <a href="/register">Register</a></div>""")


def register_page(error=""):
    return page("Register", f"""<h1>Create account</h1>{message(error, "err")}
<form method="post" action="/register">
<label>Username</label><input name="username" required minlength="3" autofocus>
<label>Email</label><input name="email" type="email" required>
<label>Password</label><input name="password" type="password" required minlength="6">
<label>Confirm password</label><input name="confirm" type="password" required>
<button>Register</button></form>
<div class="alt">Already registered? <a href="/login">Log in</a></div>""")


def dashboard_page(username):
    return page("Dashboard", f"""<h1>Hello, {html.escape(username)}!</h1>
<p style="color:#4b5563">You are logged in.</p>
<form method="post" action="/logout"><button>Log out</button></form>""")


# ---------- server ----------
class Handler(BaseHTTPRequestHandler):
    def current_user(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        token = jar["session"].value if "session" in jar else None
        return SESSIONS.get(token), token

    def send_html(self, content, status=200, extra_headers=()):
        data = content.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, path, extra_headers=()):
        self.send_response(303)
        self.send_header("Location", path)
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()

    def form(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(min(length, 10_000)).decode()
        return {k: v[0].strip() if k != "password" and k != "confirm" else v[0]
                for k, v in parse_qs(raw).items()}

    def do_GET(self):
        user, _ = self.current_user()
        if self.path == "/register":
            return self.send_html(register_page())
        if self.path == "/dashboard":
            return self.send_html(dashboard_page(user)) if user else self.redirect("/login")
        if self.path in ("/", "/login"):
            return self.redirect("/dashboard") if user else self.send_html(login_page())
        self.send_html(page("Not found", "<h1>404</h1><div class='alt'><a href='/'>Go home</a></div>"), 404)

    def do_POST(self):
        data = self.form()
        if self.path == "/register":
            return self.handle_register(data)
        if self.path == "/login":
            return self.handle_login(data)
        if self.path == "/logout":
            _, token = self.current_user()
            SESSIONS.pop(token, None)
            return self.redirect("/login", [("Set-Cookie", "session=; Max-Age=0; Path=/")])
        self.send_html(page("Not found", "<h1>404</h1>"), 404)

    def handle_register(self, d):
        username, email = d.get("username", ""), d.get("email", "")
        password, confirm = d.get("password", ""), d.get("confirm", "")
        if len(username) < 3:
            return self.send_html(register_page("Username must be at least 3 characters."))
        if "@" not in email:
            return self.send_html(register_page("Enter a valid email."))
        if len(password) < 6:
            return self.send_html(register_page("Password must be at least 6 characters."))
        if password != confirm:
            return self.send_html(register_page("Passwords do not match."))
        salt = os.urandom(16)
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO users (username, email, salt, password_hash) VALUES (?,?,?,?)",
                    (username, email.lower(), salt, hash_password(password, salt)),
                )
        except sqlite3.IntegrityError:
            return self.send_html(register_page("Username or email already taken."))
        self.send_html(login_page(ok="Account created! Please log in."))

    def handle_login(self, d):
        username, password = d.get("username", ""), d.get("password", "")
        with db() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row or not hmac.compare_digest(
            hash_password(password, row["salt"]), row["password_hash"]
        ):
            return self.send_html(login_page(error="Wrong username or password."))
        token = secrets.token_urlsafe(32)
        SESSIONS[token] = row["username"]
        self.redirect("/dashboard", [("Set-Cookie", f"session={token}; HttpOnly; SameSite=Strict; Path=/")])


if __name__ == "__main__":
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Site running at http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
