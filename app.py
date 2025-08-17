
import os, json, sqlite3, secrets, time, smtplib, ssl, csv, io
from email.message import EmailMessage
from datetime import datetime
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, send_from_directory, Response

APP_NAME = "MDXX Pro"
PRIMARY_COLOR = "#d3b057"   # gold
ACCENT_DARK = "#111111"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-"+secrets.token_hex(16))

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "teacher@example.com").strip().lower()
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ChangeMe123!")
DB_PATH = os.environ.get("DB_PATH", "mdxx.db")

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587") or "587")
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_FROM = os.environ.get("SMTP_FROM", f"MDXX Pro <{SMTP_USER or 'no-reply@example.com'}>")

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(p):
    import hashlib
    salt = "mdxx"
    return hashlib.sha256((salt+p).encode()).hexdigest()

def check_pw(p, h):
    return hash_pw(p) == h

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_confirmed INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        usdt REAL DEFAULT 10000,
        btc REAL DEFAULT 0,
        eth REAL DEFAULT 0,
        ltc REAL DEFAULT 0,
        bnb REAL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        kind TEXT,
        detail TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS confirmations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        code TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        side TEXT,
        symbol TEXT,
        base TEXT,
        quote TEXT,
        qty REAL,
        price REAL,
        value_usdt REAL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS overrides (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        symbol TEXT,
        active INTEGER DEFAULT 0,
        data TEXT,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur.execute("SELECT id FROM users WHERE is_admin=1 LIMIT 1")
    if not cur.fetchone():
        cur.execute("INSERT OR IGNORE INTO users(email,password_hash,is_confirmed,is_admin,usdt) VALUES(?,?,?,?,?)",
                    (ADMIN_EMAIL, hash_pw(ADMIN_PASSWORD), 1, 1, 0))
    conn.commit(); conn.close()

def log_action(user_id, kind, detail):
    conn = db()
    conn.execute("INSERT INTO actions(user_id,kind,detail) VALUES(?,?,?)", (user_id, kind, detail))
    conn.commit(); conn.close()

init_db()

def send_email(to_email, subject, body):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        print(f"[EMAIL SIM] To:{to_email} | Subject:{subject}\n{body}\n")
        return True
    try:
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls(context=context)
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        print("SMTP error:", e)
        return False

BINANCE = "https://api.binance.com"

def fetch_binance_price(symbol="BTCUSDT"):
    try:
        r = requests.get(f"{BINANCE}/api/v3/ticker/price", params={"symbol":symbol}, timeout=8)
        return float(r.json()["price"])
    except Exception:
        return None

def fetch_binance_klines(symbol="BTCUSDT", interval="1m", limit=200):
    try:
        r = requests.get(f"{BINANCE}/api/v3/klines", params={"symbol":symbol,"interval":interval,"limit":limit}, timeout=8)
        arr = r.json()
        candles = []
        for k in arr:
            candles.append({"t": int(k[0]), "o": float(k[1]), "h": float(k[2]), "l": float(k[3]), "c": float(k[4])})
        return candles
    except Exception as e:
        return []

def get_override(symbol):
    conn = db()
    row = conn.execute("SELECT active, data FROM overrides WHERE symbol=?", (symbol,)).fetchone()
    conn.close()
    if row:
        return bool(row["active"]), json.loads(row["data"] or "[]")
    return False, []

def current_user():
    uid = session.get("user_id")
    if not uid: return None
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return user

from flask import render_template

@app.route("/")
def home():
    syms = ["BTCUSDT","ETHUSDT","LTCUSDT","BNBUSDT"]
    prices = {}
    for s in syms:
        p = fetch_binance_price(s)
        if p is None: p = 0.0
        prices[s] = p
    return render_template("home.html", app_name=APP_NAME, primary=PRIMARY_COLOR, prices=prices)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        if not email or not password:
            flash("Email and password required.","danger"); return redirect(url_for("register"))
        conn = db()
        try:
            conn.execute("INSERT INTO users(email,password_hash) VALUES(?,?)", (email, hash_pw(password)))
            conn.commit()
            uid = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
        except sqlite3.IntegrityError:
            flash("Email already registered.","warning"); conn.close(); return redirect(url_for("register"))
        conn.close()
        code = f"{secrets.randbelow(999999):06d}"
        conn = db(); conn.execute("INSERT INTO confirmations(user_id,code) VALUES(?,?)", (uid, code)); conn.commit(); conn.close()
        send_email(email, "Your MDXX Pro confirmation code", f"Your code is: {code}")
        flash("Registered. Check your email for the confirmation code.","success")
        session["pending_email"] = email
        log_action(uid, "register", f"user {email} registered")
        return redirect(url_for("confirm"))
    return render_template("register.html", app_name=APP_NAME, primary=PRIMARY_COLOR)

@app.route("/confirm", methods=["GET","POST"])
def confirm():
    email = session.get("pending_email","")
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        code = request.form.get("code","").strip()
        conn = db()
        row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not row: flash("No such user.","danger"); conn.close(); return redirect(url_for("confirm"))
        uid = row["id"]
        r2 = conn.execute("SELECT code FROM confirmations WHERE user_id=? ORDER BY id DESC LIMIT 1", (uid,)).fetchone()
        if r2 and r2["code"] == code:
            conn.execute("UPDATE users SET is_confirmed=1 WHERE id=?", (uid,)); conn.commit(); conn.close()
            log_action(uid, "confirm", "email confirmed")
            flash("Email confirmed. Please log in.","success"); return redirect(url_for("login"))
        else:
            conn.close(); flash("Incorrect code.","danger")
    return render_template("confirm.html", app_name=APP_NAME, primary=PRIMARY_COLOR, email=email)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        conn = db(); user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone(); conn.close()
        if user and check_pw(password, user["password_hash"]):
            if not user["is_confirmed"] and not user["is_admin"]:
                flash("Please confirm your email first.","warning"); return redirect(url_for("confirm"))
            session["user_id"]=user["id"]; session["email"]=user["email"]; session["is_admin"]=bool(user["is_admin"])
            log_action(user["id"], "login", "user logged in")
            return redirect(url_for("admin" if user["is_admin"] else "student"))
        flash("Invalid credentials.","danger")
    return render_template("login.html", app_name=APP_NAME, primary=PRIMARY_COLOR)

@app.route("/logout")
def logout():
    uid = session.get("user_id"); session.clear()
    if uid: log_action(uid, "logout", "user logged out")
    return redirect(url_for("home"))

@app.route("/student")
def student():
    if not session.get("user_id"): return redirect(url_for("login"))
    conn = db(); bal = conn.execute("SELECT usdt,btc,eth,ltc,bnb FROM users WHERE id=?", (session["user_id"],)).fetchone(); conn.close()
    return render_template("student.html", app_name=APP_NAME, primary=PRIMARY_COLOR, balances=bal)

@app.route("/api/candles")
def api_candles():
    symbol = request.args.get("symbol","BTCUSDT").upper()
    interval = request.args.get("interval","1m")
    active, data = get_override(symbol)
    if active and data:
        return jsonify({"symbol":symbol, "source":"override", "candles":data})
    candles = fetch_binance_klines(symbol, interval, 200)
    return jsonify({"symbol":symbol, "source":"binance", "candles":candles})

@app.route("/api/price")
def api_price():
    symbol = request.args.get("symbol","BTCUSDT").upper()
    p = fetch_binance_price(symbol) or 0.0
    return jsonify({"symbol":symbol,"price":p})

@app.route("/api/trade", methods=["POST"])
def api_trade():
    if not session.get("user_id"): return jsonify({"ok":False,"error":"Unauthorized"}), 401
    symbol = request.form.get("symbol","BTCUSDT").upper()
    side = request.form.get("side","BUY").upper()
    qty = float(request.form.get("qty","0") or 0)
    if qty <= 0: return jsonify({"ok":False,"error":"Qty>0"}), 400
    base = symbol.replace("USDT","")
    quote = "USDT"
    p = fetch_binance_price(symbol) or 0.0
    if p <= 0: return jsonify({"ok":False,"error":"Price unavailable"}), 400
    conn = db()
    bal = conn.execute("SELECT usdt,btc,eth,ltc,bnb FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if side == "BUY":
        need = qty * p
        if bal["usdt"] < need - 1e-9:
            conn.close(); return jsonify({"ok":False,"error":"Insufficient USDT"}), 400
        field = base.lower()
        if field not in ("btc","eth","ltc","bnb"): conn.close(); return jsonify({"ok":False,"error":"Unsupported base"}), 400
        conn.execute(f"UPDATE users SET usdt=usdt-?, {field}={field}+? WHERE id=?", (need, qty, session["user_id"]))
    else:
        field = base.lower()
        if field not in ("btc","eth","ltc","bnb"): conn.close(); return jsonify({"ok":False,"error":"Unsupported base"}), 400
        if bal[field] < qty - 1e-9:
            conn.close(); return jsonify({"ok":False,"error":"Insufficient "+field.upper()}), 400
        conn.execute(f"UPDATE users SET {field}={field}-?, usdt=usdt+? WHERE id=?", (qty, qty*p, session["user_id"]))
    conn.execute("INSERT INTO orders(user_id,side,symbol,base,quote,qty,price,value_usdt) VALUES(?,?,?,?,?,?,?,?)",
                 (session["user_id"], side, symbol, base, quote, qty, p, qty*p))
    conn.commit(); conn.close()
    log_action(session["user_id"], "trade", f"{side} {qty} {base} @ {p} ({symbol})")
    return jsonify({"ok":True,"price":p})

@app.route("/admin")
def admin():
    if not session.get("is_admin"):
        return render_template("login.html", app_name=APP_NAME, primary=PRIMARY_COLOR)
    conn = db()
    users = conn.execute("SELECT id,email,is_confirmed,usdt,btc,eth,ltc,bnb,created_at FROM users ORDER BY id DESC").fetchall()
    actions = conn.execute("SELECT a.created_at,u.email,a.kind,a.detail FROM actions a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.id DESC LIMIT 60").fetchall()
    overrides = conn.execute("SELECT symbol,active,updated_at FROM overrides ORDER BY symbol").fetchall()
    conn.close()
    return render_template("admin.html", app_name=APP_NAME, primary=PRIMARY_COLOR, users=users, actions=actions, overrides=overrides)

@app.route("/admin/login", methods=["POST"])
def admin_login():
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")
    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        conn = db(); row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            conn.execute("INSERT INTO users(email,password_hash,is_confirmed,is_admin,usdt) VALUES(?,?,?,?,?)",
                         (email, hash_pw(password), 1, 1, 0)); conn.commit()
            uid = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
        else:
            uid = row["id"]
        conn.close()
        session["user_id"]=uid; session["email"]=email; session["is_admin"]=True
        return redirect(url_for("admin"))
    flash("Invalid admin credentials.","danger")
    return redirect(url_for("admin"))

@app.route("/admin/set_balance", methods=["POST"])
def admin_set_balance():
    if not session.get("is_admin"): abort(403)
    user_id = int(request.form["user_id"])
    field = request.form["field"]
    amount = float(request.form["amount"])
    if field not in ("usdt","btc","eth","ltc","bnb"): abort(400)
    conn = db(); conn.execute(f"UPDATE users SET {field}=? WHERE id=?", (amount, user_id)); conn.commit(); conn.close()
    log_action(session.get("user_id"), "admin_set_balance", f"set {field} of user {user_id} to {amount}")
    return redirect(url_for('admin'))

@app.route("/admin/send_code", methods=["POST"])
def admin_send_code():
    if not session.get("is_admin"): abort(403)
    email = request.form["email"].strip().lower()
    conn = db(); row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if not row: flash("User not found","danger"); conn.close(); return redirect(url_for('admin'))
    uid = row["id"]; code = f"{secrets.randbelow(999999):06d}"
    conn.execute("INSERT INTO confirmations(user_id,code) VALUES(?,?)", (uid, code)); conn.commit(); conn.close()
    send_email(email, "Your MDXX Pro confirmation code", f"Your code is: {code}")
    log_action(session.get("user_id"), "admin_send_code", f"sent code to {email}")
    flash("Code sent (or printed to console if SMTP unset).","info")
    return redirect(url_for('admin'))

@app.route("/admin/override", methods=["POST"])
def admin_override():
    if not session.get("is_admin"): abort(403)
    symbol = request.form.get("symbol","BTCUSDT").upper().strip()
    active = 1 if request.form.get("active")=="on" else 0
    raw = request.form.get("data","").strip()
    parsed = []
    if raw:
        if raw.lstrip().startswith("["):
            try:
                parsed = json.loads(raw)
            except Exception:
                flash("Invalid JSON","danger"); return redirect(url_for("admin"))
        else:
            for line in raw.splitlines():
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 5 and parts[0].isdigit():
                    t,o,h,l,c = int(parts[0]), float(parts[1]), float(parts[2]), float(parts[3]), float(parts[4])
                    parsed.append({"t":t,"o":o,"h":h,"l":l,"c":c})
    conn = db()
    row = conn.execute("SELECT id FROM overrides WHERE symbol=?", (symbol,)).fetchone()
    if row:
        conn.execute("UPDATE overrides SET active=?, data=?, updated_at=CURRENT_TIMESTAMP WHERE symbol=?",
                     (active, json.dumps(parsed), symbol))
    else:
        conn.execute("INSERT INTO overrides(symbol,active,data) VALUES(?,?,?)", (symbol, active, json.dumps(parsed)))
    conn.commit(); conn.close()
    log_action(session.get("user_id"), "override", f"{'ON' if active else 'OFF'} {symbol} with {len(parsed)} candles")
    flash("Override saved.","success")
    return redirect(url_for("admin"))

@app.route("/admin/json/actions")
def admin_json_actions():
    if not session.get("is_admin"): abort(403)
    conn = db()
    rows = conn.execute("SELECT a.created_at,u.email,a.kind,a.detail FROM actions a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.id DESC LIMIT 60").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/admin/export/actions.csv")
def export_actions_csv():
    if not session.get("is_admin"): abort(403)
    conn = db()
    rows = conn.execute("SELECT a.created_at,u.email,a.kind,a.detail FROM actions a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.id DESC").fetchall()
    conn.close()
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["created_at","email","kind","detail"])
    for r in rows:
        w.writerow([r["created_at"], r["email"], r["kind"], r["detail"]])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=actions.csv"})

@app.route("/admin/export/users.csv")
def export_users_csv():
    if not session.get("is_admin"): abort(403)
    conn = db()
    rows = conn.execute("SELECT id,email,is_confirmed,usdt,btc,eth,ltc,bnb,created_at FROM users ORDER BY id").fetchall()
    conn.close()
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["id","email","is_confirmed","usdt","btc","eth","ltc","bnb","created_at"])
    for r in rows:
        w.writerow([r["id"], r["email"], r["is_confirmed"], r["usdt"], r["btc"], r["eth"], r["ltc"], r["bnb"], r["created_at"]])
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=users.csv"})

@app.route("/admin/reset", methods=["POST"])
def admin_reset_class():
    if not session.get("is_admin"): abort(403)
    conn = db()
    conn.execute("DELETE FROM actions")
    conn.execute("DELETE FROM orders")
    conn.execute("UPDATE users SET usdt=10000, btc=0, eth=0, ltc=0, bnb=0 WHERE is_admin=0")
    conn.commit(); conn.close()
    log_action(session.get("user_id"), "admin_reset", "class reset")
    flash("Class balances reset and logs cleared (students only).","warning")
    return redirect(url_for("admin"))

@app.route("/admin/impersonate")
def admin_impersonate():
    if not session.get("is_admin"): abort(403)
    uid = int(request.args.get("user_id"))
    conn = db(); user = conn.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone(); conn.close()
    if not user: abort(404)
    session["user_id"] = uid; session["is_admin"] = False
    flash("You are now viewing as that student. Logout to return to admin.","info")
    return redirect(url_for("student"))

@app.route("/static/<path:path>")
def send_static(path):
    return send_from_directory("static", path)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))  # Replit default port
    host = os.environ.get("HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False)
