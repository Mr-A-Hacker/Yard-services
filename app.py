import os
import csv
import random
import datetime
import calendar
import json
import sqlite3
import tempfile
from io import StringIO
from functools import wraps
from urllib import request as urllib_request

try:
    import requests
except ImportError:
    requests = None

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(dotenv_path=".env"):
        if not os.path.exists(dotenv_path):
            return False
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
        return True

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    Response,
    session,
    g,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename


# ============================================================
# SQLite3 datetime adapter / converter (so TIMESTAMP columns
# come back as datetime objects, matching what psycopg2 did)
# ============================================================

def _adapt_datetime(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def _convert_timestamp(ts_bytes):
    if ts_bytes is None:
        return None
    ts = ts_bytes.decode("utf-8")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return ts

sqlite3.register_adapter(datetime.datetime, _adapt_datetime)
sqlite3.register_converter("TIMESTAMP", _convert_timestamp)


# ============================================================
# APP SETUP
# ============================================================

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or "change-me-in-production"
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER", ""),
    MAIL_PORT=int(os.getenv("MAIL_PORT", 587)),
    MAIL_USE_TLS=os.getenv("MAIL_USE_TLS", "true").lower() in ("1", "true", "yes"),
    MAIL_USE_SSL=os.getenv("MAIL_USE_SSL", "false").lower() in ("1", "true", "yes"),
    MAIL_USERNAME=os.getenv("MAIL_USERNAME", ""),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD", ""),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER", os.getenv("MAIL_USERNAME", "noreply@example.com")),
)

bcrypt = Bcrypt(app)
mail = Mail(app)

ADMIN_NOTIFICATION_RECIPIENTS = [
    email.strip()
    for email in os.getenv(
        "ADMIN_NOTIFICATION_RECIPIENTS",
        "yahyalababidi@gmail.com,abdullahlababidi70@gmail.com",
    ).split(",")
    if email.strip()
]

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin1")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "mp4", "webm"}
NOTIFICATION_WEBHOOK_URL = os.getenv("NOTIFICATION_WEBHOOK_URL", "").strip()
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER", "").strip()
SMS_TO_PHONE = os.getenv("SMS_TO_PHONE", "").strip()


# ============================================================
# DATABASE — single sqlite3 file, managed per-request via flask.g
# ============================================================

DB_LOCAL_PATH = os.getenv("DB_LOCAL_PATH", "yard.db")
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            DB_LOCAL_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


_db_dirty = False


def mark_db_dirty():
    global _db_dirty
    _db_dirty = True


# In-memory startup cache for quick access to users/services/requests
_startup_cache = {
    "users": [],
    "services": [],
    "requests": [],
}


def load_db_cache():
    """Load key tables into an in-memory cache (called at startup)."""
    try:
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT id, email, phone, created_at FROM users ORDER BY id")
        _startup_cache["users"] = [dict(row) for row in cursor.fetchall()]

        cursor.execute("SELECT id, name, price, description, image_url FROM services ORDER BY id")
        _startup_cache["services"] = [dict(row) for row in cursor.fetchall()]

        cursor.execute(
            "SELECT id, user_id, service_id, address, phone, email, date, time, created_at FROM requests ORDER BY id"
        )
        _startup_cache["requests"] = [dict(row) for row in cursor.fetchall()]
    except Exception as exc:
        print(f"Warning: failed to load DB cache: {exc}")


def sync_db_to_b2():
    return


def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr


def is_ip_blocked(ip):
    if not ip:
        return False
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM blocked_ips WHERE ip_address = ?", (ip,))
        return cursor.fetchone() is not None
    except Exception:
        return False


def is_day_blocked(date_str):
    if not date_str:
        return False
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM blocked_days WHERE date = ?", (date_str,))
        return cursor.fetchone() is not None
    except Exception:
        return False


def is_time_blocked(date_str, time_str):
    if not date_str or not time_str:
        return False
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT 1 FROM blocked_time_slots
            WHERE date = ? AND start_time <= ? AND end_time > ?
            """,
            (date_str, time_str, time_str),
        )
        return cursor.fetchone() is not None
    except Exception:
        return False


def log_user_ip(user_id, ip):
    if not ip:
        return
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_ips (user_id, ip_address)
            SELECT ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM user_ips WHERE user_id = ? AND ip_address = ?
            )
        """, (user_id, ip, user_id, ip))
        conn.commit()
        mark_db_dirty()
    except Exception:
        pass


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            phone TEXT,
            popup_seen INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            description TEXT,
            image_url TEXT
        );

        INSERT OR IGNORE INTO services (name, price, description, image_url) VALUES
            ('Lawn Mowing', 30.00, 'Professional lawn mowing services for small to medium yards.', '/static/uploads/services/lawn-mowing.svg'),
            ('Snow Shoveling', 30.00, 'Reliable snow removal and pathway clearing for winter weather.', '/static/uploads/services/snow-shoveling.svg');

        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            service_id INTEGER REFERENCES services(id),
            address TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT NOT NULL,
            payment TEXT NOT NULL,
            note TEXT,
            date TEXT NOT NULL,
            time TEXT NOT NULL,
            token TEXT,
            discount INTEGER DEFAULT 0,
            final_price REAL,
            verification_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        INSERT OR IGNORE INTO settings (key, value) VALUES ('theme', 'none');

        CREATE TABLE IF NOT EXISTS blocked_days (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT UNIQUE NOT NULL,
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS blocked_time_slots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(date, start_time, end_time)
        );
        INSERT OR IGNORE INTO settings (key, value) VALUES ('background_image', '');
        INSERT OR IGNORE INTO settings (key, value) VALUES ('background_position', 'center center');
        INSERT OR IGNORE INTO settings (key, value) VALUES ('background_size', 'cover');
        INSERT OR IGNORE INTO settings (key, value) VALUES ('background_repeat', 'no-repeat');
        INSERT OR IGNORE INTO settings (key, value) VALUES ('background_attachment', 'fixed');
        INSERT OR IGNORE INTO settings (key, value) VALUES ('homepage_popup_active', '1');
        INSERT OR IGNORE INTO settings (key, value) VALUES ('homepage_popup_title', 'Important account notice');
        INSERT OR IGNORE INTO settings (key, value) VALUES ('homepage_popup_message', 'An error occurred and some accounts were deleted. We are sorry for that issue. Please sign up again to restore access.');

        CREATE TABLE IF NOT EXISTS ratings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            rating INTEGER NOT NULL,
            comment TEXT,
            likes INTEGER DEFAULT 0,
            featured INTEGER DEFAULT 0,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS rating_likes (
            user_id INTEGER NOT NULL REFERENCES users(id),
            rating_id INTEGER NOT NULL REFERENCES ratings(id),
            PRIMARY KEY (user_id, rating_id)
        );

        CREATE TABLE IF NOT EXISTS promotions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            discount_percent INTEGER NOT NULL,
            active INTEGER DEFAULT 1,
            expires_at TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS popups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            media_url TEXT,
            media_type TEXT,
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS user_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            ip_address TEXT NOT NULL,
            seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()

    # ------------------------------------------------------------
    # MIGRATION — backfill columns on tables that already existed
    # (e.g. a yard.db pulled down from B2 that predates a column
    # being added here). CREATE TABLE IF NOT EXISTS is a no-op on
    # pre-existing tables, so without this, older DBs would be
    # missing newer columns and later statements (like the indexes
    # below) would fail with "no such column".
    # ------------------------------------------------------------
    _required_columns = {
        "users": [
            ("phone", "TEXT"),
            ("popup_seen", "INTEGER DEFAULT 0"),
            ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ],
        "requests": [
            ("token", "TEXT"),
            ("discount", "INTEGER DEFAULT 0"),
            ("final_price", "REAL"),
            ("verification_code", "TEXT"),
            ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ],
        "ratings": [
            ("likes", "INTEGER DEFAULT 0"),
            ("featured", "INTEGER DEFAULT 0"),
            ("submitted_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ],
        "promotions": [
            ("active", "INTEGER DEFAULT 1"),
            ("expires_at", "TEXT"),
            ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ],
        "popups": [
            ("active", "INTEGER DEFAULT 1"),
            ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ],
    }
    for table, columns in _required_columns.items():
        cursor.execute(f"PRAGMA table_info({table})")
        existing_cols = {row[1] for row in cursor.fetchall()}
        for col_name, col_def in columns:
            if col_name not in existing_cols:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
                print(f"Migrated: added column {table}.{col_name}")
    conn.commit()

    cursor.executescript("""
        CREATE INDEX IF NOT EXISTS idx_requests_user_id    ON requests(user_id);
        CREATE INDEX IF NOT EXISTS idx_requests_service_id ON requests(service_id);
        CREATE INDEX IF NOT EXISTS idx_requests_created_at ON requests(created_at);
        CREATE INDEX IF NOT EXISTS idx_ratings_user_id     ON ratings(user_id);
        CREATE INDEX IF NOT EXISTS idx_ratings_featured    ON ratings(featured);
        CREATE INDEX IF NOT EXISTS idx_promotions_active   ON promotions(active);
        CREATE INDEX IF NOT EXISTS idx_promotions_token    ON promotions(token);
        CREATE INDEX IF NOT EXISTS idx_blocked_days_date   ON blocked_days(date);
        CREATE INDEX IF NOT EXISTS idx_blocked_time_slots_date ON blocked_time_slots(date);
    """)

    conn.commit()
    mark_db_dirty()


# ============================================================
# LOCAL FILE UPLOADS
# ============================================================

def _ensure_upload_folder(folder):
    upload_dir = os.path.join("static", "uploads", folder)
    os.makedirs(upload_dir, exist_ok=True)
    return upload_dir


def save_upload_to_b2(upload_file, upload_folder):
    if not upload_file or not getattr(upload_file, "filename", None):
        return None

    filename = secure_filename(upload_file.filename)
    if not filename:
        raise ValueError("Invalid filename.")

    upload_dir = _ensure_upload_folder(upload_folder)
    base, ext = os.path.splitext(filename)
    ext = ext.lower()
    destination = os.path.join(upload_dir, filename)
    counter = 1
    while os.path.exists(destination):
        destination = os.path.join(upload_dir, f"{base}_{counter}{ext}")
        counter += 1

    upload_file.save(destination)
    file_url = f"/static/uploads/{upload_folder}/{os.path.basename(destination)}"
    return file_url, ext.lstrip('.')


# ============================================================
# BOOTSTRAP — init local database and cache
# ============================================================

with app.app_context():
    init_db()
    # load a lightweight cache of users/services/requests for quick access
    load_db_cache()


# ============================================================
# HELPERS
# ============================================================

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def send_webhook_notification(message):
    webhook_url = os.getenv("NOTIFICATION_WEBHOOK_URL", "").strip() or NOTIFICATION_WEBHOOK_URL
    if not webhook_url:
        print("NOTIFICATION_WEBHOOK_URL not configured, skipping webhook notification.")
        return

    payload = {"text": message}
    try:
        req = urllib_request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=10) as response:
            if getattr(response, "status", 200) >= 400:
                raise RuntimeError(f"Webhook returned HTTP {response.status}")
    except Exception as exc:
        print(f"Failed to send webhook notification: {exc}")


def send_sms_notification(message):
    account_sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip() or TWILIO_ACCOUNT_SID
    auth_token = os.getenv("TWILIO_AUTH_TOKEN", "").strip() or TWILIO_AUTH_TOKEN
    from_number = os.getenv("TWILIO_PHONE_NUMBER", "").strip() or TWILIO_PHONE_NUMBER
    to_number = os.getenv("SMS_TO_PHONE", "").strip() or SMS_TO_PHONE

    if not all([account_sid, auth_token, from_number, to_number]):
        print("Twilio SMS settings not configured, skipping SMS notification.")
        return
    if requests is None:
        print("Requests library not available, skipping SMS notification.")
        return

    try:
        response = requests.post(
            f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
            data={
                "To": to_number,
                "From": from_number,
                "Body": message,
            },
            auth=(account_sid, auth_token),
            timeout=10,
        )
        response.raise_for_status()
    except Exception as exc:
        print(f"Failed to send SMS notification: {exc}")


def send_admin_notification(subject, body, html=None):
    teams_message = f"{subject}\n\n{body}"

    if app.config.get("MAIL_SERVER") and ADMIN_NOTIFICATION_RECIPIENTS:
        try:
            msg = Message(
                subject,
                recipients=ADMIN_NOTIFICATION_RECIPIENTS,
                body=body,
                html=html,
            )
            mail.send(msg)
        except Exception as e:
            print(f"Failed to send notification email: {e}")
    else:
        print("MAIL_SERVER not configured, skipping admin email.")

    send_webhook_notification(teams_message)
    send_sms_notification(f"{subject}\n\n{body}")


def get_settings():
    if "settings_cache" in g:
        return g.settings_cache

    defaults = {
        "theme": "none",
        "background_image": "",
        "background_position": "center center",
        "background_size": "cover",
        "background_repeat": "no-repeat",
        "background_attachment": "fixed",
        "homepage_popup_active": "1",
        "homepage_popup_title": "Important account notice",
        "homepage_popup_message": "An error occurred and some accounts were deleted. We are sorry for that issue. Please sign up again to restore access.",
    }
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM settings")
        rows = cursor.fetchall()
        result = {row["key"]: row["value"] for row in rows}
        for k, v in defaults.items():
            result.setdefault(k, v)
        g.settings_cache = result
        return result
    except Exception:
        g.settings_cache = defaults
        return defaults


def get_background_settings():
    s = get_settings()
    return (
        s.get("background_image") or None,
        s.get("background_position", "center center"),
        s.get("background_size", "cover"),
        s.get("background_repeat", "no-repeat"),
        s.get("background_attachment", "fixed"),
    )


def get_active_theme():
    s = get_settings()
    return s.get("theme", "none")


_last_promo_deactivation: datetime.datetime | None = None


def deactivate_expired_promotions():
    global _last_promo_deactivation
    now = datetime.datetime.utcnow()
    if _last_promo_deactivation and (now - _last_promo_deactivation).seconds < 3600:
        return
    _last_promo_deactivation = now

    today = datetime.date.today().isoformat()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE promotions SET active = 0 WHERE active = 1 AND expires_at IS NOT NULL AND expires_at < ?",
        (today,),
    )
    conn.commit()
    mark_db_dirty()


# ============================================================
# ADMIN AUTH
# ============================================================

def admin_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_authenticated"):
            flash("Admin login required.", "danger")
            return redirect(url_for("admin_dashboard"))
        return f(*args, **kwargs)
    return decorated


# ============================================================
# LOGIN MANAGER
# ============================================================

login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin):
    def __init__(self, id, email, password_hash, phone, popup_seen):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.phone = phone
        self.popup_seen = popup_seen


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, email, password_hash, phone, popup_seen FROM users WHERE id = ?",
        (user_id,),
    )
    row = cursor.fetchone()
    if row:
        return User(row["id"], row["email"], row["password_hash"], row["phone"], row["popup_seen"])
    return None


# ============================================================
# GLOBAL TEMPLATE CONTEXT
# ============================================================

@app.before_request
def block_banned_ips():
    if request.path.startswith("/static"):
        return
    ip = get_client_ip()
    if is_ip_blocked(ip):
        return "403 Forbidden: Your IP has been banned.", 403


@app.context_processor
def inject_globals():
    s = get_settings()
    return dict(
        active_theme=s.get("theme", "none"),
        bg_image=s.get("background_image") or None,
        bg_position=s.get("background_position", "center center"),
        bg_size=s.get("background_size", "cover"),
        bg_repeat=s.get("background_repeat", "no-repeat"),
        bg_attachment=s.get("background_attachment", "fixed"),
    )


@app.after_request
def sync_db_after_request(response):
    global _db_dirty
    if _db_dirty:
        _db_dirty = False
    return response


# ============================================================
# PUBLIC ROUTES
# ============================================================

@app.route("/")
def home():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.rating, r.comment, r.submitted_at, u.email
        FROM ratings r
        LEFT JOIN users u ON r.user_id = u.id
        WHERE r.featured = 1
        ORDER BY r.submitted_at DESC
        LIMIT 5
    """)
    rows = cursor.fetchall()
    featured_ratings = [
        {"rating": row["rating"], "comment": row["comment"],
         "timestamp": row["submitted_at"], "email": row["email"]}
        for row in rows
    ]
    popup = None
    settings = get_settings()
    if not session.get("homepage_popup_shown") and settings.get("homepage_popup_active") == "1":
        popup = {
            "title": settings.get("homepage_popup_title"),
            "message": settings.get("homepage_popup_message"),
            "media_url": None,
            "media_type": None,
        }
        session["homepage_popup_shown"] = True

    return render_template("home.html", featured_ratings=featured_ratings, popup=popup)


@app.route("/google9b6f02740691266a.html")
def google_verify():
    return "google-site-verification: google9b6f02740691266a.html"


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/contact_support")
@login_required
def contact_support():
    return render_template("contact_support.html")


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        phone = request.form.get("phone", "").strip()
        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (email, password_hash, phone) VALUES (?, ?, ?)",
                (email, password_hash, phone),
            )
            conn.commit()
            mark_db_dirty()
            sync_db_to_b2()
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            new_user = cursor.fetchone()
            if new_user:
                log_user_ip(new_user["id"], get_client_ip())
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("An account with that email already exists.", "danger")

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, password_hash, phone, popup_seen FROM users WHERE email = ?",
            (email,),
        )
        row = cursor.fetchone()

        if row and bcrypt.check_password_hash(row["password_hash"], password):
            user = User(row["id"], row["email"], row["password_hash"], row["phone"], row["popup_seen"])
            login_user(user)
            session["popup_seen"] = row["popup_seen"]
            log_user_ip(row["id"], get_client_ip())

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.pop("popup_seen", None)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ============================================================
# USER DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():
    deactivate_expired_promotions()

    popup = None
    if not session.get("popup_seen") and not current_user.popup_seen:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, title, message, media_url, media_type
            FROM popups WHERE active = 1
            ORDER BY created_at DESC LIMIT 1
        """)
        popup = cursor.fetchone()
        if popup:
            cursor.execute(
                "UPDATE users SET popup_seen = 1 WHERE id = ?",
                (current_user.id,)
            )
            conn.commit()
            mark_db_dirty()
            session["popup_seen"] = True

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.rating, r.comment, r.submitted_at, u.email
        FROM ratings r
        LEFT JOIN users u ON r.user_id = u.id
        ORDER BY r.submitted_at DESC LIMIT 5
    """)
    ratings = [
        {"rating": row["rating"], "comment": row["comment"],
         "timestamp": row["submitted_at"], "email": row["email"]}
        for row in cursor.fetchall()
    ]
    cursor.execute("""
        SELECT token, discount_percent, expires_at
        FROM promotions WHERE active = 1
        ORDER BY created_at DESC LIMIT 1
    """)
    promo = cursor.fetchone()

    return render_template("dashboard.html", ratings=ratings, promo=promo, popup=popup)


# ============================================================
# MANAGE ACCOUNT
# ============================================================

@app.route("/manage_account", methods=["GET", "POST"])
@login_required
def manage_account():
    if request.method == "POST":
        new_email = request.form.get("email", "").strip().lower()
        new_phone = request.form.get("phone", "").strip()
        new_password = request.form.get("password", "").strip()

        if not new_email:
            flash("Email address cannot be blank.", "danger")
            return render_template("manage_account.html")

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE users SET email = ?, phone = ? WHERE id = ?",
                (new_email, new_phone, current_user.id),
            )
            if new_password:
                hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
                cursor.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (hashed_pw, current_user.id),
                )
            conn.commit()
            mark_db_dirty()
            flash("Account updated successfully!", "success")
        except sqlite3.IntegrityError:
            conn.rollback()
            flash("That email address is already in use by another account.", "danger")
        except Exception:
            conn.rollback()
            flash("An unexpected error occurred. Please try again.", "danger")

        return redirect(url_for("manage_account"))

    return render_template("manage_account.html")


# ============================================================
# SERVICE ROUTES
# ============================================================

@app.route("/pricing")
def pricing():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM services ORDER BY name")
    services = cursor.fetchall()
    return render_template("pricing.html", services=services)


@app.route("/pricing/<int:service_id>")
def pricing_detail(service_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM services WHERE id = ?", (service_id,))
    service = cursor.fetchone()
    if not service:
        return redirect(url_for("pricing"))
    return render_template("pricing_detail.html", service=service)


@app.route("/guest_request")
@login_required
def guest_request():
    session["non_member_fee"] = True
    return redirect(url_for("request_service"))


@app.route("/search_service")
@login_required
def search_service():
    query = request.args.get("q", "").strip()
    conn = get_db()
    cursor = conn.cursor()
    if query:
        cursor.execute("""
            SELECT * FROM services
            WHERE LOWER(name) LIKE LOWER(?) OR LOWER(description) LIKE LOWER(?)
        """, (f"%{query}%", f"%{query}%"))
    else:
        cursor.execute("SELECT * FROM services")
    services = cursor.fetchall()
    return render_template("search_service.html", services=services, query=query)


@app.route("/service/<int:service_id>")
@login_required
def service_details(service_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM services WHERE id = ?", (service_id,))
    service = cursor.fetchone()
    if not service:
        flash("Service not found.", "danger")
        return redirect(url_for("search_service"))
    return render_template("service_details.html", service=service)


NON_MEMBER_FEE = 7.99


@app.route("/request_service", methods=["GET", "POST"])
@login_required
def request_service():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, price FROM services ORDER BY name")
    services = cursor.fetchall()

    cursor.execute("SELECT date, reason FROM blocked_days ORDER BY date")
    blocked_days = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT date, start_time, end_time, reason FROM blocked_time_slots ORDER BY date, start_time")
    blocked_time_slots = [dict(row) for row in cursor.fetchall()]

    is_non_member = session.get("non_member_fee", False)

    if request.method == "POST":
        service_id = request.form.get("service", "").strip()
        address = request.form.get("address", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        payment = request.form.get("payment", "").strip()
        note = request.form.get("note", "").strip()
        date = request.form.get("date", "").strip()
        time_value = request.form.get("time", "").strip()
        token = request.form.get("discount_token", "").strip().upper()
        apply_non_member_fee = request.form.get("non_member_fee") == "1"

        if not all([service_id, address, phone, email, payment, date, time_value]):
            flash("Please fill in all required request fields.", "danger")
            return redirect(url_for("request_service"))

        cursor.execute("SELECT name, price FROM services WHERE id = ?", (service_id,))
        service_data = cursor.fetchone()
        if not service_data:
            flash("Selected service not found.", "danger")
            return redirect(url_for("request_service"))

        if is_day_blocked(date):
            flash("That day is blocked for service requests. Please choose another day.", "danger")
            return redirect(url_for("request_service"))

        if is_time_blocked(date, time_value):
            flash("The selected time is blocked. Please choose another time.", "danger")
            return redirect(url_for("request_service"))

        service_name, base_price = service_data["name"], service_data["price"]
        discount = 0

        if token:
            cursor.execute(
                "SELECT discount_percent, expires_at, active FROM promotions WHERE token = ?",
                (token,),
            )
            promo = cursor.fetchone()
            if promo and promo["active"] == 1 and promo["expires_at"]:
                try:
                    expires_date = datetime.datetime.strptime(promo["expires_at"], "%Y-%m-%d").date()
                    if expires_date >= datetime.date.today():
                        discount = promo["discount_percent"]
                    else:
                        flash("That promo code has expired.", "warning")
                except ValueError:
                    pass
            elif promo is None:
                flash("Invalid promo code.", "warning")

        final_price = float(base_price) * (1 - discount / 100.0)
        if apply_non_member_fee:
            final_price += NON_MEMBER_FEE
        session.pop("non_member_fee", None)
        verification_code = str(random.randint(100000, 999999))

        cursor.execute("""
            INSERT INTO requests
                (user_id, service_id, address, phone, email, payment,
                 note, date, time, token, discount, final_price, verification_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            current_user.id, service_id, address, phone, email, payment,
            note, date, time_value, token or None, discount, final_price, verification_code,
        ))
        conn.commit()
        mark_db_dirty()

        send_admin_notification(
            subject=f"New service request from {current_user.email}",
            body=(
                f"A new service request was submitted:\n\n"
                f"User: {current_user.email}\n"
                f"Service: {service_name}\n"
                f"Address: {address}\n"
                f"Phone: {phone}\n"
                f"Email: {email}\n"
                f"Payment method: {payment}\n"
                f"Date: {date}\n"
                f"Time: {time_value}\n"
                f"Discount token: {token or 'N/A'}\n"
                f"Discount: {discount}%\n"
                f"Final price: ${final_price:.2f}\n"
                f"Note: {note or 'None'}\n"
            ),
            html=(
                f"<p>A new service request was submitted.</p>"
                f"<ul>"
                f"<li><strong>User:</strong> {current_user.email}</li>"
                f"<li><strong>Service:</strong> {service_name}</li>"
                f"<li><strong>Address:</strong> {address}</li>"
                f"<li><strong>Phone:</strong> {phone}</li>"
                f"<li><strong>Email:</strong> {email}</li>"
                f"<li><strong>Payment method:</strong> {payment}</li>"
                f"<li><strong>Date:</strong> {date}</li>"
                f"<li><strong>Time:</strong> {time_value}</li>"
                f"<li><strong>Discount token:</strong> {token or 'N/A'}</li>"
                f"<li><strong>Discount:</strong> {discount}%</li>"
                f"<li><strong>Final price:</strong> ${final_price:.2f}</li>"
                f"<li><strong>Note:</strong> {note or 'None'}</li>"
                f"</ul>"
            ),
        )

        return render_template(
            "confirmation.html",
            verification_code=verification_code,
            service_name=service_name,
            base_price=base_price,
            discount=discount,
            final_price=final_price,
            non_member_fee=apply_non_member_fee,
        )

    return render_template(
        "request_service.html",
        services=services,
        is_non_member=is_non_member,
        non_member_fee=NON_MEMBER_FEE,
        blocked_days=blocked_days,
        blocked_time_slots=blocked_time_slots,
    )


# ============================================================
# HISTORY
# ============================================================

@app.route("/history")
@login_required
def history():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT req.id, s.name, req.date, req.time,
               req.final_price, req.verification_code, req.created_at
        FROM requests req
        LEFT JOIN services s ON req.service_id = s.id
        WHERE req.user_id = ?
        ORDER BY req.created_at DESC
    """, (current_user.id,))
    history_rows = cursor.fetchall()
    return render_template("history.html", history=history_rows)


# ============================================================
# RATINGS
# ============================================================

@app.route("/rate_us", methods=["GET", "POST"])
@login_required
def rate_us():
    if request.method == "POST":
        rating = request.form.get("rating")
        comment = request.form.get("comment", "").strip()

        if not rating or not rating.isdigit() or not (1 <= int(rating) <= 5):
            flash("Please provide a valid rating (1-5).", "danger")
            return redirect(url_for("rate_us"))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO ratings (user_id, rating, comment) VALUES (?, ?, ?)",
            (current_user.id, int(rating), comment),
        )
        conn.commit()
        mark_db_dirty()
        flash("Thanks for your feedback!", "success")
        return redirect(url_for("rate_us"))

    sort = request.args.get("sort", "recent")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT r.id, r.rating, r.comment, r.submitted_at, r.likes, u.email
        FROM ratings r
        LEFT JOIN users u ON r.user_id = u.id
        ORDER BY r.submitted_at DESC
    """)
    ratings = [
        {"id": row["id"], "rating": row["rating"], "comment": row["comment"],
         "timestamp": row["submitted_at"], "email": row["email"], "likes": row["likes"]}
        for row in cursor.fetchall()
    ]

    total_ratings = len(ratings)
    avg_rating = round(sum(r["rating"] for r in ratings) / total_ratings, 1) if total_ratings else 0
    distribution = {n: 0 for n in range(5, 0, -1)}
    for r in ratings:
        distribution[r["rating"]] = distribution.get(r["rating"], 0) + 1
    distribution_pct = {
        n: round((count / total_ratings) * 100) if total_ratings else 0
        for n, count in distribution.items()
    }

    if sort == "top":
        ratings.sort(key=lambda r: r["likes"], reverse=True)
    elif sort == "highest":
        ratings.sort(key=lambda r: r["rating"], reverse=True)
    elif sort == "lowest":
        ratings.sort(key=lambda r: r["rating"])

    return render_template(
        "rate_us.html",
        ratings=ratings,
        total_ratings=total_ratings,
        avg_rating=avg_rating,
        distribution=distribution,
        distribution_pct=distribution_pct,
        current_sort=sort,
    )


@app.route("/like_rating/<int:rating_id>", methods=["POST"])
@login_required
def like_rating(rating_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO rating_likes (user_id, rating_id) VALUES (?, ?)",
            (current_user.id, rating_id),
        )
        cursor.execute("UPDATE ratings SET likes = likes + 1 WHERE id = ?", (rating_id,))
        conn.commit()
        mark_db_dirty()
    except sqlite3.IntegrityError:
        conn.rollback()
    return redirect(url_for("rate_us"))


# ============================================================
# ADMIN — Login / Logout
# ============================================================

@app.route("/admin", methods=["GET", "POST"])
def admin_dashboard():
    if request.method == "POST":
        password = request.form.get("password", "")
        if password == ADMIN_PASSWORD:
            session["admin_authenticated"] = True
        else:
            flash("Invalid admin password.", "danger")
            return render_template("admin_dashboard.html", password_ok=False)

    if not session.get("admin_authenticated"):
        return render_template("admin_dashboard.html", password_ok=False)

    deactivate_expired_promotions()

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, email, phone, created_at FROM users ORDER BY id DESC")
    users = cursor.fetchall()

    cursor.execute("""
        SELECT req.id, req.user_id, s.name, s.price,
               req.address, req.phone, req.email, req.payment,
               req.note, req.date, req.time, req.token,
               req.discount, req.final_price, req.verification_code, req.created_at
        FROM requests req
        LEFT JOIN services s ON req.service_id = s.id
        ORDER BY req.created_at DESC
    """)
    requests_data = cursor.fetchall()

    cursor.execute("SELECT id, name, price, description, image_url FROM services ORDER BY id DESC")
    services = cursor.fetchall()

    cursor.execute("""
        SELECT r.id, u.email, r.rating, r.comment, r.submitted_at, r.featured
        FROM ratings r
        LEFT JOIN users u ON r.user_id = u.id
        ORDER BY r.submitted_at DESC
    """)
    ratings = cursor.fetchall()

    cursor.execute("""
        SELECT r.rating, r.comment, r.submitted_at, u.email
        FROM ratings r
        LEFT JOIN users u ON r.user_id = u.id
        WHERE r.featured = 1 ORDER BY r.submitted_at DESC LIMIT 5
    """)
    featured_ratings = cursor.fetchall()

    cursor.execute(
        "SELECT id, name, token, discount_percent, active, expires_at, created_at FROM promotions ORDER BY created_at DESC"
    )
    promotions = cursor.fetchall()

    cursor.execute("SELECT id, title, message, media_url, media_type, active, created_at FROM popups ORDER BY created_at DESC")
    popups = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT id, date, reason, created_at FROM blocked_days ORDER BY date DESC")
    blocked_days = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT id, date, start_time, end_time, reason, created_at FROM blocked_time_slots ORDER BY date DESC, start_time")
    blocked_time_slots = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT id, ip_address, reason, blocked_at FROM blocked_ips ORDER BY blocked_at DESC")
    blocked_ips = [dict(row) for row in cursor.fetchall()]

    cursor.execute("""
        SELECT ui.ip_address, u.email, u.id as user_id, MAX(ui.seen_at) as last_seen
        FROM user_ips ui
        JOIN users u ON ui.user_id = u.id
        GROUP BY ui.ip_address, u.email, u.id
        ORDER BY last_seen DESC
    """)
    user_ips = [dict(row) for row in cursor.fetchall()]

    calendar_requests = [
        {
            "date": row[9],
            "time": row[10],
            "service": row[2] or "Unknown",
            "note": row[8] or "",
        }
        for row in requests_data
    ]

    return render_template(
        "admin_dashboard.html",
        password_ok=True,
        users=users,
        requests=requests_data,
        services=services,
        ratings=ratings,
        promotions=promotions,
        featured_ratings=featured_ratings,
        popups=popups,
        blocked_days=blocked_days,
        blocked_time_slots=blocked_time_slots,
        blocked_ips=blocked_ips,
        user_ips=user_ips,
        calendar_requests=calendar_requests,
    )


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_authenticated", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("admin_dashboard"))


# ============================================================
# ADMIN — Services
# ============================================================

@app.route("/admin/add_service", methods=["GET", "POST"])
@admin_login_required
def admin_add_service():
    if request.method == "GET":
        return render_template("admin_add_service.html")

    name = request.form.get("name", "").strip()
    price = request.form.get("price", "").strip()
    description = request.form.get("description", "").strip()
    image_url = request.form.get("image_url", "").strip()
    image_file = request.files.get("image_file")

    if not name or not price:
        flash("Service name and price are required.", "danger")
        return render_template("admin_add_service.html")

    if image_file and image_file.filename:
        if not allowed_file(image_file.filename):
            flash("Invalid file type. Allowed: png, jpg, jpeg, gif, mp4, webm", "danger")
            return render_template("admin_add_service.html")
        try:
            uploaded = save_upload_to_b2(image_file, "services")
            if uploaded:
                image_url, _ = uploaded
        except Exception as exc:
                flash(f"Unable to upload service image: {exc}", "danger")
        "INSERT INTO services (name, price, description, image_url) VALUES (?, ?, ?, ?)",
        (name, price, description, image_url),
    )
    conn.commit()
    mark_db_dirty()
    sync_db_to_b2()
    flash("Service added!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/edit_service/<int:service_id>", methods=["GET", "POST"])
@admin_login_required
def admin_edit_service(service_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":
        name = request.form["name"].strip()
        price = request.form["price"].strip()
        description = request.form.get("description", "").strip()
        image_url = request.form.get("image_url", "").strip()
        image_file = request.files.get("image_file")

        if image_file and image_file.filename:
            if not allowed_file(image_file.filename):
                flash("Invalid file type. Allowed: png, jpg, jpeg, gif, mp4, webm", "danger")
                return redirect(url_for("admin_edit_service", service_id=service_id))
            try:
                uploaded = save_upload_to_b2(image_file, "services")
                if uploaded:
                    image_url, _ = uploaded
            except Exception as exc:
                flash(f"Unable to upload service image: {exc}", "danger")
                return redirect(url_for("admin_edit_service", service_id=service_id))

        cursor.execute(
            "UPDATE services SET name=?, price=?, description=?, image_url=? WHERE id=?",
            (name, price, description, image_url, service_id),
        )
        conn.commit()
        mark_db_dirty()
        sync_db_to_b2()
        flash("Service updated!", "success")
        return redirect(url_for("admin_dashboard"))

    cursor.execute("SELECT * FROM services WHERE id=?", (service_id,))
    service = cursor.fetchone()
    if not service:
        flash("Service not found.", "danger")
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_edit_service.html", service=service)


@app.route("/admin/delete_service/<int:service_id>", methods=["POST"])
@admin_login_required
def admin_delete_service(service_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM services WHERE id=?", (service_id,))
    conn.commit()
    mark_db_dirty()
    flash("Service deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/search_services")
@admin_login_required
def admin_search_services():
    query = request.args.get("q", "").strip()
    conn = get_db()
    cursor = conn.cursor()
    if query:
        cursor.execute("""
            SELECT * FROM services
            WHERE LOWER(name) LIKE LOWER(?) OR LOWER(description) LIKE LOWER(?)
        """, (f"%{query}%", f"%{query}%"))
    else:
        cursor.execute("SELECT * FROM services")
    services = cursor.fetchall()
    return render_template("manage_services.html", services=services, query=query)


# ============================================================
# ADMIN — Ratings
# ============================================================

@app.route("/admin/delete_rating/<int:rating_id>", methods=["POST"])
@admin_login_required
def delete_rating(rating_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rating_likes WHERE rating_id = ?", (rating_id,))
    cursor.execute("DELETE FROM ratings WHERE id = ?", (rating_id,))
    conn.commit()
    mark_db_dirty()
    flash("Rating deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_all_ratings", methods=["POST"])
@admin_login_required
def delete_all_ratings():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rating_likes")
    cursor.execute("DELETE FROM ratings")
    conn.commit()
    mark_db_dirty()
    flash("All ratings deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/toggle_featured/<int:rating_id>", methods=["POST"])
@admin_login_required
def toggle_featured_rating(rating_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT featured FROM ratings WHERE id = ?", (rating_id,))
    row = cursor.fetchone()
    if row:
        cursor.execute(
            "UPDATE ratings SET featured = ? WHERE id = ?",
            (0 if row["featured"] else 1, rating_id),
        )
        conn.commit()
        mark_db_dirty()
    flash("Rating updated.", "success")
    return redirect(url_for("admin_dashboard"))


# ============================================================
# ADMIN — Promotions
# ============================================================

@app.route("/admin/add_promotion", methods=["POST"])
@admin_login_required
def add_promotion():
    name = request.form.get("name", "").strip()
    token = request.form.get("token", "").strip().upper()
    discount = request.form.get("discount", "").strip()
    expires_at = request.form.get("expires_at", "").strip()

    if not all([name, token, discount, expires_at]):
        flash("All promotion fields are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO promotions (name, token, discount_percent, active, expires_at) VALUES (?, ?, ?, 1, ?)",
            (name, token, discount, expires_at),
        )
        conn.commit()
        mark_db_dirty()
        flash("Promotion added!", "success")
    except sqlite3.IntegrityError:
        conn.rollback()
        flash("A promotion with that token already exists.", "danger")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/add_blocked_day", methods=["POST"])
@admin_login_required
def add_blocked_day():
    date_value = request.form.get("date", "").strip()
    reason = request.form.get("reason", "").strip()
    if not date_value:
        flash("A date is required to block the day.", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO blocked_days (date, reason) VALUES (?, ?)",
            (date_value, reason or None),
        )
        conn.commit()
        mark_db_dirty()
        flash("Blocked day added.", "success")
    except sqlite3.IntegrityError:
        flash("That day is already blocked.", "warning")
    except Exception:
        conn.rollback()
        flash("Failed to block the day.", "danger")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_blocked_day/<int:block_id>", methods=["POST"])
@admin_login_required
def delete_blocked_day(block_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_days WHERE id = ?", (block_id,))
    conn.commit()
    mark_db_dirty()
    flash("Blocked day removed.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/add_blocked_time", methods=["POST"])
@admin_login_required
def add_blocked_time():
    date_value = request.form.get("date", "").strip()
    start_time = request.form.get("start_time", "").strip()
    end_time = request.form.get("end_time", "").strip()
    reason = request.form.get("reason", "").strip()

    if not date_value or not start_time or not end_time:
        flash("Date and time range are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    if start_time >= end_time:
        flash("Start time must be before end time.", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO blocked_time_slots (date, start_time, end_time, reason) VALUES (?, ?, ?, ?)",
            (date_value, start_time, end_time, reason or None),
        )
        conn.commit()
        mark_db_dirty()
        flash("Blocked time slot added.", "success")
    except sqlite3.IntegrityError:
        flash("That time slot is already blocked.", "warning")
    except Exception:
        conn.rollback()
        flash("Failed to block the time slot.", "danger")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_blocked_time/<int:block_id>", methods=["POST"])
@admin_login_required
def delete_blocked_time(block_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_time_slots WHERE id = ?", (block_id,))
    conn.commit()
    mark_db_dirty()
    flash("Blocked time slot removed.", "info")
    return redirect(url_for("admin_dashboard"))


# ============================================================
# ADMIN — Requests
# ============================================================

@app.route("/admin/delete_request/<int:request_id>", methods=["POST"])
@admin_login_required
def delete_request(request_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM requests WHERE id = ?", (request_id,))
    conn.commit()
    mark_db_dirty()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/download_requests")
@admin_login_required
def download_requests():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM requests ORDER BY created_at DESC")
    rows = cursor.fetchall()
    col_names = [desc[0] for desc in cursor.description]

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(col_names)
    for row in rows:
        writer.writerow(list(row))
    output.seek(0)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=requests.csv"},
    )


# ============================================================
# ADMIN — Popups
# ============================================================

@app.route("/admin/add_popup", methods=["POST"])
@admin_login_required
def add_popup():
    title = request.form.get("title", "").strip()
    message = request.form.get("message", "").strip()
    file = request.files.get("file")

    if not title or not message:
        flash("Popup title and message are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    media_url = None
    media_type = None

    if file and file.filename:
        if not allowed_file(file.filename):
            flash("Invalid file type. Allowed: png, jpg, jpeg, gif, mp4, webm", "danger")
            return redirect(url_for("admin_dashboard"))

        try:
            uploaded = save_upload_to_b2(file, "popups")
            if uploaded:
                media_url, ext = uploaded
                media_type = "video" if ext in {"mp4", "webm"} else "image"
        except Exception as exc:
            flash(f"Unable to upload popup media: {exc}", "danger")
            return redirect(url_for("admin_dashboard"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO popups (title, message, media_url, media_type, active) VALUES (?, ?, ?, ?, 1)",
        (title, message, media_url, media_type),
    )
    cursor.execute("UPDATE users SET popup_seen = 0")
    conn.commit()
    mark_db_dirty()

    flash("Popup created and users will see it on next login.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_popups", methods=["POST"])
@admin_login_required
def delete_popups():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM popups")
    conn.commit()
    mark_db_dirty()
    flash("All popups deleted.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/send_test_email", methods=["POST"])
@admin_login_required
def send_test_email():
    send_admin_notification(
        subject="Test email from Yard Services",
        body="This is a test email to confirm the notification system is working.",
        html="<p>This is a <strong>test</strong> email to confirm the notification system is working.</p>",
    )
    flash("Test email sent (or attempted). Check logs if delivery failed.", "success")
    return redirect(url_for("admin_dashboard"))


# ============================================================
# ADMIN — Theme & Background
# ============================================================

@app.route("/admin/set_theme", methods=["POST"])
@admin_login_required
def set_theme():
    theme = request.form.get("theme", "none")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET value = ? WHERE key = 'theme'", (theme,))
    conn.commit()
    mark_db_dirty()
    flash("Theme updated!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/upload_background", methods=["POST"])
@admin_login_required
def upload_background():
    if "file" not in request.files or request.files["file"].filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("admin_dashboard"))

    file = request.files["file"]
    if not allowed_file(file.filename):
        flash("Invalid file type. Allowed: png, jpg, jpeg, gif", "danger")
        return redirect(url_for("admin_dashboard"))

    try:
        upload_result = save_upload_to_b2(file, "backgrounds")
        if not upload_result:
            raise RuntimeError("Background upload did not produce a file URL.")
        file_url, _ = upload_result
    except Exception as exc:
        flash(f"Unable to upload background: {exc}", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE settings SET value = ? WHERE key = 'background_image'", (file_url,))
    conn.commit()
    mark_db_dirty()

    flash("Background image updated!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/update_background_settings", methods=["POST"])
@admin_login_required
def update_background_settings():
    updates = {
        "background_position": request.form.get("position", "center center"),
        "background_size": request.form.get("size", "cover"),
        "background_repeat": request.form.get("repeat", "no-repeat"),
        "background_attachment": request.form.get("attachment", "fixed"),
    }
    conn = get_db()
    cursor = conn.cursor()
    for key, value in updates.items():
        cursor.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
    conn.commit()
    mark_db_dirty()
    flash("Background settings updated!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/clear_background", methods=["POST"])
@admin_login_required
def clear_background():
    defaults = {
        "background_image": "",
        "background_position": "center center",
        "background_size": "cover",
        "background_repeat": "no-repeat",
        "background_attachment": "fixed",
    }
    conn = get_db()
    cursor = conn.cursor()
    for key, value in defaults.items():
        cursor.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
    conn.commit()
    mark_db_dirty()
    flash("Background removed.", "info")
    return redirect(url_for("admin_dashboard"))


# ============================================================
# ADMIN — IP Blocking
# ============================================================

def is_private_ip(ip):
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_unspecified
        )
    except ValueError:
        return False


@app.route("/admin/block_ip", methods=["POST"])
@admin_login_required
def block_ip():
    ip = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "").strip()
    if not ip:
        flash("IP address is required.", "danger")
        return redirect(url_for("admin_dashboard"))

    if is_private_ip(ip):
        flash(f"Cannot block private/internal IP address: {ip}", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT OR IGNORE INTO blocked_ips (ip_address, reason) VALUES (?, ?)",
            (ip, reason or None),
        )
        conn.commit()
        mark_db_dirty()
        flash(f"IP {ip} has been blocked.", "success")
    except Exception:
        conn.rollback()
        flash("Failed to block IP.", "danger")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/unblock_ip/<int:block_id>", methods=["POST"])
@admin_login_required
def unblock_ip(block_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE id = ?", (block_id,))
    conn.commit()
    mark_db_dirty()
    flash("IP unblocked.", "success")
    return redirect(url_for("admin_dashboard"))


# ============================================================
# ADMIN — Delete User
# ============================================================

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@admin_login_required
def delete_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM rating_likes WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM ratings WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM requests WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM user_ips WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        mark_db_dirty()
    except Exception as e:
        conn.rollback()
        flash("Failed to delete user.", "danger")
    return redirect(url_for("admin_dashboard"))


# ============================================================
# APP RUNNER
# ============================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
