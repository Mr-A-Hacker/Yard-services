import os
import random
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

# -----------------------------
# Flask Setup
# -----------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallbacksecret")
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

DB_NAME = "yard.db"

# -----------------------------
# Database Helpers
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        phone TEXT,
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Requests table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        address TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT NOT NULL,
        payment TEXT NOT NULL,
        note TEXT,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        token TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()

init_db()

# -----------------------------
# User Model
# -----------------------------
class User(UserMixin):
    def __init__(self, id, email, password_hash, is_admin=0):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.is_admin = bool(is_admin)

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password_hash, is_admin FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(*row)
    return None

# -----------------------------
# Admin Decorator
# -----------------------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def home():
    return render_template("home.html")

# --- Sign Up ---
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        phone = request.form["phone"]

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (email, password_hash, phone) VALUES (?, ?, ?)",
                           (email, password_hash, phone))
            conn.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already exists!", "danger")
        finally:
            conn.close()

    return render_template("signup.html")

# --- Login ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, password_hash, is_admin FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
        conn.close()

        if row and bcrypt.check_password_hash(row[2], password):
            user = User(row[0], row[1], row[2], row[3])
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials!", "danger")

    return render_template("login.html")

# --- Logout ---
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# --- Dashboard ---
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

# --- Service Request ---
@app.route("/request_service", methods=["GET", "POST"])
@login_required
def request_service():
    if request.method == "POST":
        address = request.form["address"]
        phone = request.form["phone"]
        email = request.form["email"]
        payment = request.form["payment"]
        note = request.form["note"]
        date = request.form["date"]
        time = request.form["time"]

        token = None
        if payment == "zelle":
            token = str(random.randint(100000, 999999))

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO requests (user_id, address, phone, email, payment, note, date, time, token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (current_user.id, address, phone, email, payment, note, date, time, token))
        conn.commit()
        conn.close()

        return render_template("confirmation.html", token=token, payment=payment)

    return render_template("request_form.html")

# --- Admin Dashboard ---
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT id, email, phone, created_at FROM users")
    users = cursor.fetchall()

    cursor.execute("SELECT id, user_id, address, phone, email, payment, note, date, time, token, created_at FROM requests")
    requests = cursor.fetchall()

    conn.close()

    return render_template("admin_dashboard.html", users=users, requests=requests)

# -----------------------------
# Run App
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
