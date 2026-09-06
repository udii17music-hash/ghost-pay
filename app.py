from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3, secrets, string, hashlib
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = "change-this-secret-key-in-production"
DB = "ghostpay.db"

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        balance REAL DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS payment_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT UNIQUE NOT NULL,
        pin_hash TEXT NOT NULL,
        amount REAL NOT NULL,
        created_by INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        status TEXT DEFAULT 'Active',
        redeemed_by INTEGER,
        redeemed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tx_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)
    # Demo account/data
    if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        now = datetime.now().isoformat(timespec="seconds")
        conn.execute(
            "INSERT INTO users(name,email,password_hash,balance,created_at) VALUES(?,?,?,?,?)",
            ("Demo User", "demo@ghostpay.local", hashlib.sha256(b"demo123").hexdigest(), 12450, now)
        )
        conn.commit()
    conn.close()

def current_user():
    if "user_id" not in session:
        return None
    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    return user

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def make_code():
    alphabet = string.ascii_uppercase + string.digits
    while True:
        raw = ''.join(secrets.choice(alphabet) for _ in range(8))
        code = f"GP-{raw[:4]}-{raw[4:]}"
        conn = db()
        exists = conn.execute("SELECT 1 FROM payment_codes WHERE code=?", (code,)).fetchone()
        conn.close()
        if not exists:
            return code

def make_pin():
    return f"{secrets.randbelow(10000):04d}"

def hash_value(value):
    return hashlib.sha256(value.encode()).hexdigest()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        conn = db()
        user = conn.execute(
            "SELECT * FROM users WHERE email=? AND password_hash=?",
            (email, hash_value(password))
        ).fetchone()
        conn.close()
        if user:
            session["user_id"] = user["id"]
            return redirect(url_for("home"))
        flash("Invalid demo login. Try demo@ghostpay.local / demo123", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    user = current_user()
    conn = db()
    txs = conn.execute(
        "SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 5",
        (user["id"],)
    ).fetchall()
    conn.close()
    return render_template("home.html", user=user, txs=txs)

@app.route("/create-code", methods=["GET", "POST"])
@login_required
def create_code():
    user = current_user()
    generated = None

    if request.method == "POST":
        try:
            amount = float(request.form["amount"])
            hours = int(request.form.get("expiry", "24"))
        except ValueError:
            flash("Enter a valid amount.", "error")
            return redirect(url_for("create_code"))

        if amount <= 0:
            flash("Amount must be greater than zero.", "error")
            return redirect(url_for("create_code"))
        if amount > user["balance"]:
            flash("Insufficient demo wallet balance.", "error")
            return redirect(url_for("create_code"))

        code = make_code()
        pin = make_pin()
        expires = datetime.now() + timedelta(hours=hours)

        conn = db()
        conn.execute(
            "INSERT INTO payment_codes(code,pin_hash,amount,created_by,expires_at) VALUES(?,?,?,?,?)",
            (code, hash_value(pin), amount, user["id"], expires.isoformat(timespec="minutes"))
        )
        conn.execute(
            "UPDATE users SET balance=balance-? WHERE id=?",
            (amount, user["id"])
        )
        conn.execute(
            "INSERT INTO transactions(tx_id,user_id,type,amount,status,created_at) VALUES(?,?,?,?,?,?)",
            ("TRX" + secrets.token_hex(5).upper(), user["id"], "Code Created", amount, "Success",
             datetime.now().strftime("%d %b %Y, %I:%M %p"))
        )
        conn.commit()
        conn.close()

        generated = {
            "code": code,
            "pin": pin,
            "amount": amount,
            "expires": expires.strftime("%d %b %Y, %I:%M %p")
        }

    return render_template("create_code.html", user=user, generated=generated)

@app.route("/redeem", methods=["GET", "POST"])
@login_required
def redeem():
    user = current_user()
    result = None
    if request.method == "POST":
        code = request.form["code"].strip().upper()
        pin = request.form["pin"].strip()

        conn = db()
        row = conn.execute(
            "SELECT * FROM payment_codes WHERE code=?", (code,)
        ).fetchone()

        if not row:
            flash("Payment code not found.", "error")
        elif row["status"] != "Active":
            flash("This payment code has already been redeemed or is inactive.", "error")
        elif datetime.fromisoformat(row["expires_at"]) < datetime.now():
            flash("This payment code has expired.", "error")
        elif hash_value(pin) != row["pin_hash"]:
            flash("Incorrect PIN.", "error")
        elif row["created_by"] == user["id"]:
            flash("For this demo, a user cannot redeem their own code.", "error")
        else:
            conn.execute(
                "UPDATE payment_codes SET status='Redeemed', redeemed_by=?, redeemed_at=? WHERE id=?",
                (user["id"], datetime.now().isoformat(timespec="minutes"), row["id"])
            )
            conn.execute("UPDATE users SET balance=balance+? WHERE id=?", (row["amount"], user["id"]))
            txid = "TRX" + secrets.token_hex(5).upper()
            conn.execute(
                "INSERT INTO transactions(tx_id,user_id,type,amount,status,created_at) VALUES(?,?,?,?,?,?)",
                (txid, user["id"], "Code Redeemed", row["amount"], "Success",
                 datetime.now().strftime("%d %b %Y, %I:%M %p"))
            )
            conn.commit()
            result = {"amount": row["amount"], "tx_id": txid, "created_at": datetime.now().strftime("%d %b %Y, %I:%M %p")}
        conn.close()

    return render_template("redeem.html", user=user, result=result)

@app.route("/history")
@login_required
def history():
    user = current_user()
    conn = db()
    txs = conn.execute(
        "SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    ).fetchall()
    conn.close()
    return render_template("history.html", user=user, txs=txs)

@app.route("/wallet")
@login_required
def wallet():
    return render_template("wallet.html", user=current_user())

@app.route("/admin")
@login_required
def admin():
    conn = db()
    stats = {
        "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "transactions": conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0],
        "volume": conn.execute("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE status='Success'").fetchone()[0],
        "codes": conn.execute("SELECT COUNT(*) FROM payment_codes WHERE status='Active'").fetchone()[0],
        "fees": conn.execute("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE type='Code Created'").fetchone()[0] * 0.02,
    }
    recent = conn.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT 8").fetchall()
    codes = conn.execute("SELECT * FROM payment_codes ORDER BY id DESC LIMIT 5").fetchall()
    conn.close()
    return render_template("admin.html", user=current_user(), stats=stats, recent=recent, codes=codes)

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "app": "GhostPay demo"})

init_db()
if __name__ == "__main__":
    app.run(debug=True)