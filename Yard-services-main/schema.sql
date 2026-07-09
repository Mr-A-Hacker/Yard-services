-- USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    phone TEXT,
    popup_seen BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- SERVICES TABLE
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT,
    image_url TEXT
);

-- REQUESTS TABLE
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
    discount INTEGER DEFAULT 0,
    final_price REAL,
    verification_code TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(service_id) REFERENCES services(id)
);

-- REQUEST SERVICES TABLE (supports selecting multiple services per request)
CREATE TABLE IF NOT EXISTS request_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    service_id INTEGER REFERENCES services(id),
    service_name TEXT NOT NULL,
    price REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_request_services_request_id ON request_services(request_id);

-- SETTINGS TABLE
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- DEFAULT SETTINGS
INSERT OR IGNORE INTO settings (key, value) VALUES ('theme', 'none');
INSERT OR IGNORE INTO settings (key, value) VALUES ('background_image', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('background_position', 'center center');
INSERT OR IGNORE INTO settings (key, value) VALUES ('background_size', 'cover');
INSERT OR IGNORE INTO settings (key, value) VALUES ('background_repeat', 'no-repeat');
INSERT OR IGNORE INTO settings (key, value) VALUES ('background_attachment', 'fixed');

-- RATINGS TABLE
CREATE TABLE IF NOT EXISTS ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    rating INTEGER NOT NULL,
    comment TEXT,
    likes INTEGER DEFAULT 0,
    featured BOOLEAN DEFAULT FALSE,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- RATING LIKES TABLE
CREATE TABLE IF NOT EXISTS rating_likes (
    user_id INTEGER NOT NULL,
    rating_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, rating_id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(rating_id) REFERENCES ratings(id)
);

-- PROMOTIONS TABLE
CREATE TABLE IF NOT EXISTS promotions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    discount_percent INTEGER NOT NULL,
    active BOOLEAN DEFAULT 1,
    expires_at TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- POPUPS TABLE
CREATE TABLE IF NOT EXISTS popups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    media_url TEXT,
    media_type TEXT,
    active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- PERFORMANCE INDEXES (FIX 4)
-- Speeds up JOIN and WHERE queries on frequently filtered columns.
-- IF NOT EXISTS makes these safe to run on existing databases.
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_requests_user_id    ON requests(user_id);
CREATE INDEX IF NOT EXISTS idx_requests_service_id ON requests(service_id);
CREATE INDEX IF NOT EXISTS idx_requests_created_at ON requests(created_at);
CREATE INDEX IF NOT EXISTS idx_ratings_user_id     ON ratings(user_id);
CREATE INDEX IF NOT EXISTS idx_ratings_featured    ON ratings(featured);
CREATE INDEX IF NOT EXISTS idx_promotions_active   ON promotions(active);
CREATE INDEX IF NOT EXISTS idx_promotions_token    ON promotions(token);
