import os
import random
import sqlite3
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallbacksecret")
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

DB_NAME = "yard.db"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin1")

# -----------------------------
# Database Setup
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Users
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        phone TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Services
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        price REAL NOT NULL
    )
    """)

    # Requests
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        service_id INTEGER,
        address TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT NOT NULL,
        payment TEXT NOT NULL,
        note TEXT,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        token TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(service_id) REFERENCES services(id)
    )
    """)

    # Ratings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        rating INTEGER NOT NULL,
        comment TEXT,
        submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Promotions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS promotions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        discount_percent INTEGER NOT NULL,
        active BOOLEAN DEFAULT 1,
        expires_at TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

init_db()
# -----------------------------
# User Model
# -----------------------------
class User(UserMixin):
    def __init__(self, id, email, password_hash):
        self.id = id
        self.email = email
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password_hash FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(*row)
    return None

# -----------------------------
# Routes: Signup / Login / Logout
# -----------------------------
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


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, password_hash FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
        conn.close()

        if row and bcrypt.check_password_hash(row[2], password):
            user = User(row[0], row[1], row[2])
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid credentials!", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))
# -----------------------------
# Dashboard
# -----------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Recent ratings
    cursor.execute("""
        SELECT ratings.rating, ratings.comment, ratings.submitted_at, users.email
        FROM ratings
        LEFT JOIN users ON ratings.user_id = users.id
        ORDER BY ratings.submitted_at DESC
        LIMIT 5
    """)
    ratings = cursor.fetchall()

    # Latest active promotion
    cursor.execute("SELECT token, discount_percent, expires_at FROM promotions WHERE active=1 ORDER BY created_at DESC LIMIT 1")
    promo = cursor.fetchone()

    conn.close()
    return render_template("dashboard.html", ratings=ratings, promo=promo)


@app.route("/")
def home():
    return render_template("home.html")



# -----------------------------
# Request Service
# -----------------------------
@app.route("/request_service", methods=["GET", "POST"])
@login_required
def request_service():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, price FROM services")
    services = cursor.fetchall()
    conn.close()

    if request.method == "POST":
        service_id = request.form["service"]
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT name, price FROM services WHERE id=?", (service_id,))
        service = cursor.fetchone()
        conn.close()

        address = request.form["address"]
        phone = request.form["phone"]
        email = request.form["email"]
        payment = request.form["payment"]
        note = request.form["note"]
        date = request.form["date"]
        time = request.form["time"]
        discount_token = request.form.get("discount_token", "").upper()

        discount = 0
        if discount_token:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT id, discount_percent, expires_at, active FROM promotions WHERE token=?", (discount_token,))
            promo = cursor.fetchone()
            if promo and promo[3] == 1:  # active
                expires_at = promo[2]
                today = datetime.date.today().isoformat()
                if not expires_at or today <= expires_at:
                    discount = promo[1]
                    flash(f"{discount}% discount applied!", "success")
                else:
                    flash("This discount token has expired.", "danger")
            else:
                flash("Invalid discount token.", "danger")
            conn.close()

        final_price = service[1] * (1 - discount / 100)

        token = None
        if payment == "zelle":
            token = str(random.randint(100000, 999999))

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO requests (user_id, service_id, address, phone, email, payment, note, date, time, token)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (current_user.id, service_id, address, phone, email, payment, note, date, time, token))
        conn.commit()
        conn.close()

        return render_template("confirmation.html", token=token, payment=payment, service=service,
                               discount=discount, final_price=final_price)

    return render_template("request_form.html", services=services)


# -----------------------------
# Rate Us
# -----------------------------
@app.route("/rate_us", methods=["GET", "POST"])
@login_required
def rate_us():
    if request.method == "POST":
        rating = request.form.get("rating")
        comment = request.form.get("comment")

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO ratings (user_id, rating, comment) VALUES (?, ?, ?)",
                       (current_user.id, rating, comment))
        conn.commit()
        conn.close()

        flash("Thanks for your feedback!", "success")
        return redirect(url_for("dashboard"))

    return render_template("rate_us.html")
# -----------------------------
# Admin Dashboard
# -----------------------------
@app.route("/admin", methods=["GET", "POST"])
def admin_dashboard():
    if request.method == "POST":
        password = request.form.get("password")
        if password == ADMIN_PASSWORD:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()

            # Users
            cursor.execute("SELECT id, email, phone, created_at FROM users")
            users = cursor.fetchall()

            # Requests
            cursor.execute("""
                SELECT requests.id, requests.user_id, services.name, services.price,
                       requests.address, requests.phone, requests.email, requests.payment,
                       requests.note, requests.date, requests.time, requests.token, requests.created_at
                FROM requests
                LEFT JOIN services ON requests.service_id = services.id
            """)
            requests = cursor.fetchall()

            # Services
            cursor.execute("SELECT id, name, price FROM services")
            services = cursor.fetchall()

            # Ratings
            cursor.execute("""
                SELECT ratings.id, users.email, ratings.rating, ratings.comment, ratings.submitted_at
                FROM ratings
                LEFT JOIN users ON ratings.user_id = users.id
            """)
            ratings = cursor.fetchall()

            # Promotions
            cursor.execute("SELECT id, name, token, discount_percent, active, expires_at, created_at FROM promotions")
            promotions = cursor.fetchall()

            conn.close()

            return render_template("admin_dashboard.html",
                                   users=users,
                                   requests=requests,
                                   services=services,
                                   ratings=ratings,
                                   promotions=promotions)

        flash("Invalid admin password!", "danger")

    return render_template("admin_login.html")


# -----------------------------
# Admin Utilities
# -----------------------------
@app.route("/delete_request/<int:request_id>", methods=["POST"])
def delete_request(request_id):
    password = request.form.get("password")
    if password != ADMIN_PASSWORD:
        flash("Invalid admin password!", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM requests WHERE id=?", (request_id,))
    conn.commit()
    conn.close()

    flash(f"Request {request_id} deleted successfully!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/services/add", methods=["POST"])
def add_service():
    name = request.form["name"]
    price = request.form["price"]

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO services (name, price) VALUES (?, ?)", (name, price))
    conn.commit()
    conn.close()

    flash("Service added!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/services/update/<int:service_id>", methods=["POST"])
def update_service(service_id):
    name = request.form["name"]
    price = request.form["price"]

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE services SET name=?, price=? WHERE id=?", (name, price, service_id))
    conn.commit()
    conn.close()

    flash("Service updated!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/services/delete/<int:service_id>", methods=["POST"])
def delete_service(service_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM services WHERE id=?", (service_id,))
    conn.commit()
    conn.close()

    flash("Service deleted!", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/promotions/add", methods=["POST"])
def add_promotion():
    name = request.form["name"]
    token = request.form["token"].upper()
    discount = int(request.form["discount"])
    expires_at = request.form["expires_at"]

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO promotions (name, token, discount_percent, expires_at) VALUES (?, ?, ?, ?)",
                   (name, token, discount, expires_at))
    conn.commit()
    conn.close()

    flash("Promotion added!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/promotions/delete/<int:promo_id>", methods=["POST"])
def delete_promotion(promo_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM promotions WHERE id=?", (promo_id,))
    conn.commit()
    conn.close()

    flash("Promotion deleted!", "info")
    return redirect(url_for("admin_dashboard"))
# -----------------------------
# Run the app
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
