CREATE TABLE IF NOT EXISTS slack_browser_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    encrypted_xoxc_token TEXT NOT NULL,
    encrypted_xoxd_cookie TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
