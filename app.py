import os
import csv
import random
import datetime
import calendar
import json
import sqlite3
import tempfile
import base64
import hashlib
import atexit
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

# "Remember me" cookie so returning users are auto-signed-in on this browser.
app.config["REMEMBER_COOKIE_DURATION"] = datetime.timedelta(days=30)
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
# Only send the cookie over HTTPS in production (set FLASK_ENV=production there).
app.config["REMEMBER_COOKIE_SECURE"] = os.getenv("FLASK_ENV") == "production"

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
# BACKBLAZE B2 CONFIG
# ============================================================
B2_KEY_ID = os.getenv("B2_KEY_ID", "").strip()
B2_APPLICATION_KEY = os.getenv("B2_APPLICATION_KEY", "").strip()
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME", "yardservices-storage-2").strip()
B2_BUCKET_ID = os.getenv("B2_BUCKET_ID", "6cb12b4a501892429bfe0716").strip()
B2_ENDPOINT = os.getenv("B2_ENDPOINT", "https://api.backblazeb2.com").strip()
_b2_auth_token = None
_b2_api_url = None
_b2_download_url = None


def b2_is_configured():
    if requests is None:
        return False
    return bool(B2_KEY_ID and B2_APPLICATION_KEY)


def b2_authorize():
    global _b2_auth_token, _b2_api_url, _b2_download_url
    if _b2_auth_token:
        return _b2_auth_token
    if not b2_is_configured():
        raise RuntimeError("B2 not configured")
    auth_str = f"{B2_KEY_ID}:{B2_APPLICATION_KEY}"
    auth_header = base64.b64encode(auth_str.encode()).decode()
    try:
        resp = requests.get(
            f"{B2_ENDPOINT}/b2api/v3/b2_authorize_account",
            headers={"Authorization": f"Basic {auth_header}"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        _b2_auth_token = data["authorizationToken"]
        # B2 v3 nests apiUrl/downloadUrl inside apiInfo.storageApi
        api_info = data.get("apiInfo", {})
        storage_api = api_info.get("storageApi", api_info)
        _b2_api_url = storage_api.get("apiUrl", api_info.get("apiUrl", ""))
        if _b2_api_url:
            _b2_api_url = _b2_api_url.rstrip("/") + "/b2api/v3"
        _b2_download_url = storage_api.get("downloadUrl", api_info.get("downloadUrl", ""))
        if not _b2_api_url or not _b2_download_url:
            print(f"B2 authorize missing apiUrl/downloadUrl. apiInfo keys: {list(api_info.keys())}")
        return _b2_auth_token
    except Exception as exc:
        print(f"B2 authorize failed: {exc}")
        _b2_auth_token = None
        raise


def b2_get_upload_url():
    auth = b2_authorize()
    resp = requests.post(
        f"{_b2_api_url}/b2_get_upload_url",
        headers={"Authorization": auth},
        json={"bucketId": B2_BUCKET_ID},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["uploadUrl"], data["authorizationToken"]


def b2_upload_bytes(file_data, b2_filename, content_type="application/octet-stream"):
    upload_url, upload_auth = b2_get_upload_url()
    sha1 = hashlib.sha1(file_data).hexdigest()
    resp = requests.post(
        upload_url,
        headers={
            "Authorization": upload_auth,
            "X-Bz-File-Name": b2_filename,
            "Content-Type": content_type,
            "X-Bz-Content-Sha1": sha1,
        },
        data=file_data,
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()


def b2_upload_file(local_path, b2_filename, content_type="application/octet-stream"):
    with open(local_path, "rb") as f:
        file_data = f.read()
    return b2_upload_bytes(file_data, b2_filename, content_type)


def b2_download_file(b2_filename, local_path):
    auth = b2_authorize()
    url = f"{_b2_download_url}/file/{B2_BUCKET_NAME}/{b2_filename}"
    resp = requests.get(url, headers={"Authorization": auth}, timeout=120)
    resp.raise_for_status()
    os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
    with open(local_path, "wb") as f:
        f.write(resp.content)


def b2_get_file_url(b2_filename):
    if _b2_download_url:
        return f"{_b2_download_url}/file/{B2_BUCKET_NAME}/{b2_filename}"
    return f"https://{B2_BUCKET_NAME}.s3.us-east-005.backblazeb2.com/{b2_filename}"


# ============================================================
# DATABASE — single sqlite3 file, managed per-request via flask.g
# ============================================================

DB_LOCAL_PATH = os.getenv("DB_LOCAL_PATH", "yard.db")
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


_last_b2_sync = 0.0
_b2_download_ok = False
_b2_backup_exists = False


def sync_db_to_b2():
    global _last_b2_sync, _b2_download_ok, _b2_backup_exists
    if not b2_is_configured():
        return
    now = datetime.datetime.utcnow().timestamp()
    if now - _last_b2_sync < 5:
        return
    _last_b2_sync = now
    try:
        # Read local user count and emails before any B2 operations
        conn = sqlite3.connect(DB_LOCAL_PATH)
        local_user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        local_users = [dict(r) for r in conn.execute(
            "SELECT email, password_hash, phone, popup_seen FROM users"
        ).fetchall()]
        conn.close()

        # ── Boot download failed reconciliation ──
        # If we never got the B2 backup at boot, a local user may have just been
        # added.  Don't overwrite a richer B2 backup with a sparse local DB.
        # Instead, download the backup, restore it, then re-insert any local-only
        # users.
        if not _b2_download_ok and local_user_count > 0:
            temp_bak = DB_LOCAL_PATH + ".b2bak"
            try:
                b2_download_file(DB_LOCAL_PATH, temp_bak)
                bak_conn = sqlite3.connect(temp_bak)
                bak_user_count = bak_conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                bak_emails = set(
                    r[0] for r in bak_conn.execute("SELECT email FROM users").fetchall()
                )
                bak_conn.close()

                if bak_user_count > local_user_count or bak_user_count > 0:
                    # B2 has more or equal users — restore it, then merge local users in
                    local_new = [u for u in local_users if u["email"] not in bak_emails]
                    os.remove(DB_LOCAL_PATH)
                    os.rename(temp_bak, DB_LOCAL_PATH)

                    if local_new:
                        merge_conn = sqlite3.connect(DB_LOCAL_PATH)
                        for u in local_new:
                            merge_conn.execute(
                                "INSERT OR IGNORE INTO users (email, password_hash, phone, popup_seen) VALUES (?, ?, ?, ?)",
                                (u["email"], u["password_hash"], u["phone"], u["popup_seen"]),
                            )
                        merge_conn.commit()
                        merge_conn.close()
                        print(f"Merged {len(local_new)} local user(s) into B2 backup ({bak_user_count} existing).")
                    else:
                        print(f"No new local users to merge — restored B2 backup ({bak_user_count} users).")

                    _b2_download_ok = True
                    _b2_backup_exists = True
                else:
                    os.remove(temp_bak)
            except Exception as bak_exc:
                print(f"B2 backup reconciliation failed: {bak_exc}")
                if os.path.exists(DB_LOCAL_PATH + ".b2bak"):
                    try:
                        os.remove(DB_LOCAL_PATH + ".b2bak")
                    except Exception:
                        pass

        # ── Final safety check ──
        conn = sqlite3.connect(DB_LOCAL_PATH)
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        conn.close()
        if user_count == 0 and _b2_backup_exists:
            print("sync_db_to_b2 skipped: local DB has no users but B2 backup exists — not overwriting.")
            return

        b2_upload_file(DB_LOCAL_PATH, DB_LOCAL_PATH, "application/x-sqlite3")
        _b2_download_ok = True
        _b2_backup_exists = True
        print(f"DB synced to B2: {DB_LOCAL_PATH}")
    except Exception as exc:
        print(f"Failed to sync DB to B2: {exc}")


def download_db_from_b2():
    global _b2_download_ok, _b2_backup_exists
    if not b2_is_configured():
        return
    if os.path.exists(DB_LOCAL_PATH):
        _b2_download_ok = True
        _b2_backup_exists = True
        return
    try:
        b2_download_file(DB_LOCAL_PATH, DB_LOCAL_PATH)
        print(f"DB downloaded from B2: {DB_LOCAL_PATH}")
        _b2_download_ok = True
        _b2_backup_exists = True
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            print("No existing DB in B2, starting fresh.")
            _b2_download_ok = True
            _b2_backup_exists = False
        else:
            print(f"Failed to download DB from B2: {exc}")
            _b2_download_ok = False
    except Exception as exc:
        print(f"Failed to download DB from B2: {exc}")
        _b2_download_ok = False


def _final_b2_sync():
    if b2_is_configured() and os.path.exists(DB_LOCAL_PATH):
        try:
            conn = sqlite3.connect(DB_LOCAL_PATH)
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            conn.commit()
            conn.close()
            if user_count == 0 and (not _b2_download_ok or _b2_backup_exists):
                print("Final DB sync skipped: local DB has no users but B2 may have a backup — not overwriting.")
                return
            b2_upload_file(DB_LOCAL_PATH, DB_LOCAL_PATH, "application/x-sqlite3")
            print(f"Final DB sync to B2 complete.")
        except Exception as exc:
            print(f"Final DB sync to B2 failed: {exc}")


atexit.register(_final_b2_sync)


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


def get_user_by_ip(ip):
    """
    Look up a single user by their last-seen public IP, for auto-login
    fallback when there's no 'remember me' cookie (e.g. new browser).

    Only returns a user if that IP is uniquely tied to exactly one
    account. IPs are frequently shared by many people (home routers,
    offices, phone carriers via CGNAT, coffee shops), so if more than
    one account has ever logged in from this IP, we refuse to guess
    and the visitor just sees the normal login page instead.
    """
    if not ip:
        return None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT DISTINCT user_id FROM user_ips WHERE ip_address = ?",
            (ip,),
        )
        rows = cursor.fetchall()
        if len(rows) != 1:
            return None

        user_id = rows[0]["user_id"]
        cursor.execute(
            "SELECT id, email, password_hash, phone, popup_seen FROM users WHERE id = ?",
            (user_id,),
        )
        row = cursor.fetchone()
        if row:
            return User(row["id"], row["email"], row["password_hash"], row["phone"], row["popup_seen"])
    except Exception:
        return None
    return None


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

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Lawn Mowing', 30.00, 'Full lawn care including precision mowing, edging along walkways and flower beds, trimming around trees and fences, and blowing clippings off driveways and patios. We leave your yard looking crisp, clean, and professionally maintained. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1558618666-fcd25c85f82e?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Lawn Mowing');

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Snow Shoveling', 30.00, 'Complete snow removal from driveways, front and back walkways, porch steps, and entry paths. We also spread salt or ice melt on slippery surfaces to keep your family safe. Service includes same-day response after any storm. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1585670149963-60c0ce1b1a42?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Snow Shoveling');

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Leaf Raking', 35.00, 'Thorough leaf removal from your entire yard including hard-to-reach corners, under bushes, and along fence lines. We rake, pile, bag, and haul away all leaves and debris so your lawn can breathe and stay healthy through the season. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1598902178163-cc89e5cbb801?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Leaf Raking');

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Hedge Trimming', 40.00, 'Precision trimming and shaping of hedges, bushes, and shrubs to keep them neat, healthy, and well-defined. We prune overgrown branches, shape formal hedges, and clean up clippings so your landscape looks polished and well-cared-for. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1589923188900-85dae523342b?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Hedge Trimming');

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Yard Cleanup', 45.00, 'Comprehensive yard cleaning covering debris pickup, fallen branch removal, trash and litter collection, and light hauling of unwanted items. We sweep patios, tidy up garden borders, and leave your outdoor space spotless and ready to enjoy. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1621255111168-c8d19a6e8d88?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Yard Cleanup');

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Garden Weeding', 35.00, 'Careful hand weeding of garden beds, flower borders, and vegetable patches. We remove weeds by the root to prevent regrowth, loosen compacted soil, and tidy up the area so your plants have room to thrive. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1585320806297-9794b3e4eeae?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Garden Weeding');

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Driveway Sweeping', 25.00, 'Complete driveway and sidewalk sweeping to remove dirt, leaves, gravel, and debris. We edge along the driveway for a clean line and blow everything off hard surfaces so your home looks well-maintained from the street. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1612865542449-7c2c3c7e4843?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Driveway Sweeping');

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Gutter Cleaning', 45.00, 'Safe and thorough cleaning of your home gutters and downspouts. We remove leaves, twigs, dirt, and blockages to prevent water damage and clogs. We also check that downspouts are clear and flowing properly before we finish. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1603105037880-880cd4edfb0d?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Gutter Cleaning');

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Garden Planting', 40.00, 'Professional planting of flowers, shrubs, vegetables, and decorative plants in your garden beds or containers. We prepare the soil, dig proper holes, plant with care, and water everything in. Perfect for refreshing your garden for spring or fall. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1558428915-31fb7d7b61a5?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Garden Planting');

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Wood Pickup', 40.00, 'We haul away fallen branches, cut tree limbs, scrap lumber, and piled brush from your property. Our team loads, cleans up, and disposes of everything so your yard stays safe and tidy. Perfect after a storm or landscaping project. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1599220148469-d0a06c9339e7?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Wood Pickup');

        INSERT INTO services (name, price, description, image_url)
        SELECT 'Hardscape Weed Control', 40.00, 'Targeted weed removal from patios, walkways, driveways, retaining walls, and stone pathways. We pull weeds from cracks and joints, sweep away debris, and apply treatment to keep hard surfaces clean and weed-free for longer. Responsible neighbor teens will be doing the work.', 'https://images.unsplash.com/photo-1621255111168-c8d19a6e8d88?w=600&q=80'
        WHERE NOT EXISTS (SELECT 1 FROM services WHERE name = 'Hardscape Weed Control');

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

        CREATE TABLE IF NOT EXISTS request_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
            service_id INTEGER REFERENCES services(id),
            service_name TEXT NOT NULL,
            price REAL NOT NULL
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
        INSERT OR IGNORE INTO settings (key, value) VALUES ('homepage_popup_media_url', '');
        INSERT OR IGNORE INTO settings (key, value) VALUES ('homepage_popup_media_type', '');

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

        CREATE TABLE IF NOT EXISTS finances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            label TEXT NOT NULL,
            value REAL NOT NULL DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        INSERT OR IGNORE INTO finances (key, label, value) VALUES ('customers_served', 'Customers Served', 0);
        INSERT OR IGNORE INTO finances (key, label, value) VALUES ('money_earned', 'Money Earned ($)', 0.00);
        INSERT OR IGNORE INTO finances (key, label, value) VALUES ('abdullah_savings', 'Abdullah Savings ($)', 0.00);
        INSERT OR IGNORE INTO finances (key, label, value) VALUES ('abdulrahaman_savings', 'Abdulrahaman Savings ($)', 0.00);
        INSERT OR IGNORE INTO finances (key, label, value) VALUES ('business_savings', 'Business Savings ($)', 0.00);

        CREATE TABLE IF NOT EXISTS admin_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            message TEXT NOT NULL,
            sender TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    # ------------------------------------------------------------
    # MIGRATION — backfill request_services for older requests that
    # were created before multi-service requests existed (they only
    # have a single requests.service_id). Safe to re-run: skips any
    # request that already has rows in request_services.
    # ------------------------------------------------------------
    cursor.execute("""
        INSERT INTO request_services (request_id, service_id, service_name, price)
        SELECT r.id, r.service_id, s.name, s.price
        FROM requests r
        JOIN services s ON r.service_id = s.id
        WHERE r.service_id IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM request_services rs WHERE rs.request_id = r.id)
    """)
    conn.commit()

    cursor.executescript("""
        CREATE INDEX IF NOT EXISTS idx_requests_user_id    ON requests(user_id);
        CREATE INDEX IF NOT EXISTS idx_requests_service_id ON requests(service_id);
        CREATE INDEX IF NOT EXISTS idx_requests_created_at ON requests(created_at);
        CREATE INDEX IF NOT EXISTS idx_request_services_request_id ON request_services(request_id);
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
    ext_clean = ext.lstrip('.')

    # Upload to B2 if configured
    if b2_is_configured():
        content_type = {
            "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
            "gif": "image/gif", "mp4": "video/mp4", "webm": "video/webm",
        }.get(ext_clean, "application/octet-stream")
        b2_path = f"{upload_folder}/{os.path.basename(destination)}"
        try:
            with open(destination, "rb") as f:
                file_data = f.read()
            b2_upload_bytes(file_data, b2_path, content_type)
            file_url = b2_get_file_url(b2_path)
            return file_url, ext_clean
        except Exception as exc:
            print(f"B2 upload failed for {b2_path}: {exc}, using local fallback.")

    file_url = f"/static/uploads/{upload_folder}/{os.path.basename(destination)}"
    return file_url, ext_clean


# ============================================================
# BOOTSTRAP — init local database and cache
# ============================================================

with app.app_context():
    if b2_is_configured():
        print(f"B2 storage configured (bucket: {B2_BUCKET_NAME})")
    else:
        print("*** WARNING: B2 not configured — user accounts will NOT persist across restarts! ***")
        print("*** Set B2_KEY_ID and B2_APPLICATION_KEY in Render dashboard Environment. ***")

    download_db_from_b2()
    init_db()
    # Only sync to B2 at boot if download succeeded (got real DB or first run).
    # If download failed, DO NOT upload — we'd overwrite the B2 backup with an empty DB.
    if _b2_download_ok:
        sync_db_to_b2()
    else:
        print("B2 download failed — skipping boot sync to protect existing backup.")


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
        "homepage_popup_media_url": "",
        "homepage_popup_media_type": "",
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
# GLOBAL TEMPLATE CONTEXT & BEFORE-REQUEST HOOKS
# ============================================================

@app.before_request
def block_banned_ips():
    if request.path.startswith("/static"):
        return
    ip = get_client_ip()
    if is_ip_blocked(ip):
        return "403 Forbidden: Your IP has been banned.", 403


@app.before_request
def auto_login_returning_user():
    """
    If the user is not already authenticated and we have no session cookie,
    try to identify them by their IP address. This enables "automatic login"
    when they come back from the same IP (e.g. home network, mobile data)
    without needing to type credentials again.
    """
    # Skip static assets and admin routes to avoid interfering
    if request.path.startswith("/static") or request.path.startswith("/admin"):
        return
    if current_user.is_authenticated:
        return

    ip = get_client_ip()
    user = get_user_by_ip(ip)
    if user:
        login_user(user, remember=True)
        session["popup_seen"] = user.popup_seen


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
        sync_db_to_b2()
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
    if settings.get("homepage_popup_active") == "1":
        popup = {
            "title": settings.get("homepage_popup_title"),
            "message": settings.get("homepage_popup_message"),
            "media_url": settings.get("homepage_popup_media_url"),
            "media_type": settings.get("homepage_popup_media_type"),
        }

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

            # Fetch the newly created user and log them in immediately
            cursor.execute(
                "SELECT id, email, password_hash, phone, popup_seen FROM users WHERE email = ?",
                (email,),
            )
            new_user = cursor.fetchone()
            if new_user:
                # Record the IP for this user
                log_user_ip(new_user["id"], get_client_ip())
                # Create User object and log in with "remember me"
                user = User(
                    new_user["id"],
                    new_user["email"],
                    new_user["password_hash"],
                    new_user["phone"],
                    new_user["popup_seen"],
                )
                login_user(user, remember=True)
                session["popup_seen"] = user.popup_seen
                flash("Account created! You are now logged in.", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Account created but could not log you in automatically. Please log in.", "warning")
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
            remember = request.form.get("remember") == "on"
            login_user(user, remember=remember)
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
# WEATHER, AI CHAT, ADMIN CHAT pages
# ============================================================

@app.route("/weather")
@login_required
def weather_page():
    return render_template("weather.html")


@app.route("/ai-chat")
@login_required
def ai_chat_page():
    return render_template("ai_chat.html")


@app.route("/admin-chat")
@login_required
def admin_chat_page():
    return render_template("admin_chat.html")


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
        service_ids = [s.strip() for s in request.form.getlist("services") if s.strip()]
        address = request.form.get("address", "").strip()
        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        payment = request.form.get("payment", "").strip()
        note = request.form.get("note", "").strip()
        date = request.form.get("date", "").strip()
        time_value = request.form.get("time", "").strip()
        token = request.form.get("discount_token", "").strip().upper()
        apply_non_member_fee = request.form.get("non_member_fee") == "1"

        if not all([service_ids, address, phone, email, payment, date, time_value]):
            flash("Please select at least one service and fill in all required fields.", "danger")
            return redirect(url_for("request_service"))

        placeholders = ",".join("?" for _ in service_ids)
        cursor.execute(
            f"SELECT id, name, price FROM services WHERE id IN ({placeholders})",
            service_ids,
        )
        selected_services = cursor.fetchall()
        if not selected_services or len(selected_services) != len(set(service_ids)):
            flash("One or more selected services could not be found.", "danger")
            return redirect(url_for("request_service"))

        if is_day_blocked(date):
            flash("That day is blocked for service requests. Please choose another day.", "danger")
            return redirect(url_for("request_service"))

        if is_time_blocked(date, time_value):
            flash("The selected time is blocked. Please choose another time.", "danger")
            return redirect(url_for("request_service"))

        service_name = ", ".join(s["name"] for s in selected_services)
        base_price = sum(float(s["price"]) for s in selected_services)
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
            current_user.id, selected_services[0]["id"], address, phone, email, payment,
            note, date, time_value, token or None, discount, final_price, verification_code,
        ))
        new_request_id = cursor.lastrowid

        cursor.executemany(
            """
            INSERT INTO request_services (request_id, service_id, service_name, price)
            VALUES (?, ?, ?, ?)
            """,
            [
                (new_request_id, s["id"], s["name"], float(s["price"]))
                for s in selected_services
            ],
        )
        conn.commit()
        mark_db_dirty()

        services_list_text = "\n".join(
            f"  - {s['name']} (${float(s['price']):.2f})" for s in selected_services
        )
        services_list_html = "".join(
            f"<li>{s['name']} — ${float(s['price']):.2f}</li>" for s in selected_services
        )

        send_admin_notification(
            subject=f"New service request from {current_user.email}",
            body=(
                f"A new service request was submitted:\n\n"
                f"User: {current_user.email}\n"
                f"Services:\n{services_list_text}\n"
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
                f"<li><strong>Services:</strong><ul>{services_list_html}</ul></li>"
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
            services=[{"name": s["name"], "price": float(s["price"])} for s in selected_services],
            base_price=base_price,
            discount=discount,
            final_price=final_price,
            non_member_fee=apply_non_member_fee,
            token=token or None,
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
        SELECT req.id, GROUP_CONCAT(rs.service_name, ', ') AS name, req.date, req.time,
               req.final_price, req.verification_code, req.created_at
        FROM requests req
        LEFT JOIN request_services rs ON rs.request_id = req.id
        WHERE req.user_id = ?
        GROUP BY req.id
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
# VIORA AI CHAT
# ============================================================

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "").strip()
_NVIDIA_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"


@app.route("/api/ai/chat", methods=["POST"])
@login_required
def ai_chat():
    data = request.get_json(silent=True)
    if not data:
        return {"error": "Missing data"}, 400
    if not NVIDIA_API_KEY:
        return {"error": "AI not configured"}, 503

    conn = get_db()
    services_list = conn.execute(
        "SELECT id, name, price, description FROM services ORDER BY name"
    ).fetchall()
    services_str = "\n".join(
        f"- \"{s['name']}\" (${s['price']}): {s['description'] or 'No description'}"
        for s in services_list
    )

    system_prompt = (
        "You are Viora AI, a friendly lawn & yard care assistant for Yard Services.\n\n"
        "WRITING STYLE:\n"
        "- Keep responses short, punchy, and confident.\n"
        "- Use emojis naturally: 🌿 for nature, 🧹 for mowing, 💰 for pricing, ✅ for confirmations.\n"
        "- Bold key info with **asterisks**.\n"
        "- Use bullet points for lists.\n"
        "- Start replies with a quick emoji that matches the topic.\n"
        "- Sound like a cool lawn expert who loves what they do.\n\n"
        "SERVICE PREVIEW FORMAT — When discussing a specific service, show it like this:\n"
        "🧹 **Service Name** — $XX.XX\n"
        "> Brief description of the service.\n\n"
        "When listing multiple services, use a compact bullet list:\n"
        "• **Service Name** — $XX.XX — Short description\n\n"
        "BOOKING PREVIEW — When the user wants to book, collect details (service, address, phone, date, time) "
        "conversationally, then show a booking summary like this:\n"
        "═══════════════════════\n"
        "📋 **Booking Summary**\n"
        "🧹 Service: Lawn Mowing\n"
        "📍 Address: 123 Main St\n"
        "📅 Date: 2025-07-24 at 2:00 PM\n"
        "💰 Total: $24.99\n"
        "═══════════════════════\n"
        "Then tell them to use the **Request a Service** button to confirm. "
        "Do NOT create bookings yourself.\n\n"
        "AVAILABLE SERVICES:\n" + services_str
    )

    messages = data.get("messages", [])
    if not isinstance(messages, list) or len(messages) == 0:
        return {"error": "Missing messages"}, 400

    # Check for explicit /search command
    last_user_msg = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            last_user_msg = m.get("content", "").strip()
            break

    if last_user_msg.lower().startswith("/search "):
        query = last_user_msg[8:].strip()
        if query:
            results = _web_search(query)
            if results:
                return {"reply": f"🔍 **Web search results for:** {query}\n\n{results}"}
            return {"reply": f"❌ Couldn't find results for \"{query}\"."}
        return {"reply": "Usage: /search your query"}

    if messages[0].get("role") == "system":
        messages[0]["content"] = system_prompt
    else:
        messages.insert(0, {"role": "system", "content": system_prompt})

    try:
        resp = requests.post(
            _NVIDIA_ENDPOINT,
            headers={
                "Authorization": f"Bearer {NVIDIA_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "meta/llama-3.1-8b-instruct",
                "messages": messages,
                "temperature": 0.5,
                "max_tokens": 300,
            },
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        reply = result["choices"][0]["message"]["content"] or "Got it! How can I help?"
        return {"reply": reply}
    except Exception as exc:
        print(f"AI chat error: {exc}")
        return {"error": "AI service unavailable"}, 502


def _web_search(query):
    try:
        import re
        resp = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        results = re.findall(
            r'<a[^>]+class="result__a"[^>]*>([^<]+)</a>',
            resp.text,
        )
        snippets = re.findall(
            r'<a[^>]+class="result__snippet"[^>]*>([^<]+)</a>',
            resp.text,
        )
        if results:
            lines = []
            for i, title in enumerate(results[:8]):
                desc = snippets[i] if i < len(snippets) else ""
                lines.append(f"• **{title}**" + (f" — {desc}" if desc else ""))
            return "\n".join(lines)
        return None
    except Exception as e:
        print(f"Web search error: {e}")
        return None


# ============================================================
# ADMIN CHAT (user → admin messaging)
# ============================================================

@app.route("/api/admin_chat/send", methods=["POST"])
@login_required
def admin_chat_send():
    data = request.get_json(silent=True)
    if not data or not data.get("message", "").strip():
        return {"error": "Missing message"}, 400
    conn = get_db()
    conn.execute(
        "INSERT INTO admin_chats (user_id, message, sender) VALUES (?, ?, 'user')",
        (current_user.id, data["message"].strip()),
    )
    conn.commit()
    mark_db_dirty()
    return {"ok": True}


@app.route("/api/admin_chat/messages")
@login_required
def admin_chat_messages():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, message, sender, created_at FROM admin_chats WHERE user_id = ? ORDER BY created_at ASC",
        (current_user.id,),
    ).fetchall()
    msgs = []
    for r in rows:
        m = dict(r)
        if isinstance(m.get("created_at"), datetime.datetime):
            m["created_at"] = m["created_at"].isoformat()
        msgs.append(m)
    return {"messages": msgs}


@app.route("/api/admin/chat/poll")
@admin_login_required
def admin_chat_poll():
    last_id = request.args.get("last_id", 0, type=int)
    conn = get_db()
    rows = conn.execute("""
        SELECT ac.id, ac.user_id, ac.message, ac.sender, u.email
        FROM admin_chats ac
        JOIN users u ON ac.user_id = u.id
        WHERE ac.id > ?
        ORDER BY ac.id ASC
    """, (last_id,)).fetchall()
    messages = []
    max_id = last_id
    for r in rows:
        messages.append({"id": r["id"], "user_id": r["user_id"], "email": r["email"], "message": r["message"], "sender": r["sender"]})
        if r["id"] > max_id:
            max_id = r["id"]
    return {"messages": messages, "max_id": max_id}


@app.route("/admin/chat/reply", methods=["POST"])
@admin_login_required
def admin_chat_reply():
    user_id = request.form.get("user_id", "").strip()
    message = request.form.get("message", "").strip()
    if not user_id or not message:
        flash("Missing user or message.", "danger")
        return redirect(url_for("admin_dashboard"))
    conn = get_db()
    conn.execute(
        "INSERT INTO admin_chats (user_id, message, sender) VALUES (?, ?, 'admin')",
        (int(user_id), message),
    )
    conn.commit()
    mark_db_dirty()
    sync_db_to_b2()
    flash("Reply sent.", "success")
    return redirect(url_for("admin_dashboard"))


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
        SELECT req.id, req.user_id, GROUP_CONCAT(rs.service_name, ', ') AS service_names,
               SUM(rs.price) AS services_total,
               req.address, req.phone, req.email, req.payment,
               req.note, req.date, req.time, req.token,
               req.discount, req.final_price, req.verification_code, req.created_at
        FROM requests req
        LEFT JOIN request_services rs ON rs.request_id = req.id
        GROUP BY req.id
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

    cursor.execute("SELECT key, label, value FROM finances ORDER BY id")
    finances = {row[0]: {"label": row[1], "value": row[2]} for row in cursor.fetchall()}

    cursor.execute("""
        SELECT ac.id, ac.user_id, ac.message, ac.sender, ac.created_at, u.email
        FROM admin_chats ac
        JOIN users u ON ac.user_id = u.id
        ORDER BY ac.user_id, ac.created_at ASC
    """)
    admin_chat_raw = cursor.fetchall()
    admin_chat_convos = {}
    for row in admin_chat_raw:
        uid = row["user_id"]
        if uid not in admin_chat_convos:
            admin_chat_convos[uid] = {"email": row["email"], "messages": []}
        admin_chat_convos[uid]["messages"].append({
            "id": row["id"],
            "message": row["message"],
            "sender": row["sender"],
            "created_at": row["created_at"],
        })

    calendar_requests = [
        {
            "date": row[9],
            "time": row[10],
            "service": row[2] or "Unknown",
            "note": row[8] or "",
        }
        for row in requests_data
    ]

    admin_chat_max_id = 0
    for uid, convo in admin_chat_convos.items():
        for m in convo["messages"]:
            if m["id"] > admin_chat_max_id:
                admin_chat_max_id = m["id"]

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
        finances=finances,
        admin_chat_convos=admin_chat_convos,
        admin_chat_max_id=admin_chat_max_id,
        b2_configured=b2_is_configured(),
    )


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_authenticated", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/test_b2", methods=["POST"])
@admin_login_required
def admin_test_b2():
    if not b2_is_configured():
        flash("B2 is NOT configured. Set B2_KEY_ID and B2_APPLICATION_KEY in Render environment.", "danger")
        return redirect(url_for("admin_dashboard"))
    try:
        b2_authorize()
        flash("B2 authorization succeeded! ✅", "success")
    except Exception as exc:
        flash(f"B2 authorization FAILED: {exc}", "danger")
        return redirect(url_for("admin_dashboard"))
    try:
        upload_url, upload_auth = b2_get_upload_url()
        flash(f"Got upload URL from B2 ✅ ({upload_url[:60]}...)", "success")
    except Exception as exc:
        flash(f"B2 get_upload_url FAILED: {exc}", "danger")
        return redirect(url_for("admin_dashboard"))
    flash("B2 is fully working! Accounts will persist across restarts. 🎉", "success")
    return redirect(url_for("admin_dashboard"))


# ============================================================
# ADMIN — Finances
# ============================================================

@app.route("/admin/update_finance", methods=["POST"])
@admin_login_required
def admin_update_finance():
    key = request.form.get("key", "").strip()
    action = request.form.get("action", "set")
    try:
        amount = float(request.form.get("amount", 0))
    except ValueError:
        flash("Invalid amount.", "danger")
        return redirect(url_for("admin_dashboard"))

    valid_keys = {"customers_served", "money_earned", "abdullah_savings", "abdulrahaman_savings", "business_savings"}
    if key not in valid_keys:
        flash("Invalid finance key.", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = get_db()
    if action == "add":
        conn.execute("UPDATE finances SET value = value + ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?", (amount, key))
    elif action == "subtract":
        conn.execute("UPDATE finances SET value = value - ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?", (amount, key))
    else:
        conn.execute("UPDATE finances SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?", (amount, key))

    conn.commit()
    mark_db_dirty()
    conn.close()
    flash("Finance updated.", "success")
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
            return render_template("admin_add_service.html")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
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


@app.route("/admin/delete_services", methods=["POST"])
@admin_login_required
def admin_delete_services():
    ids = request.form.getlist("service_ids")
    if not ids:
        flash("No services selected.", "warning")
        return redirect(url_for("admin_dashboard"))
    conn = get_db()
    cursor = conn.cursor()
    placeholders = ",".join("?" for _ in ids)
    cursor.execute(f"DELETE FROM services WHERE id IN ({placeholders})", ids)
    conn.commit()
    mark_db_dirty()
    flash(f"Deleted {len(ids)} service(s).", "info")
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
