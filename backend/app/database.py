import sqlite3
import os

def get_db_path() -> str:
    return os.getenv("CODEREVIEW_DB_PATH", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "codereview.db")))

def get_db_connection(db_path: str = None):
    target_path = db_path or get_db_path()
    is_uri = target_path.startswith("file:") or "mode=memory" in target_path
    if is_uri or target_path == ":memory:":
        conn = sqlite3.connect(target_path, check_same_thread=False, uri=is_uri)
    else:
        conn = sqlite3.connect(target_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(db_path: str = None):
    conn = get_db_connection(db_path)
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS reviews (
                id TEXT PRIMARY KEY,
                repo_name TEXT DEFAULT 'local-repo',
                filename TEXT NOT NULL,
                language TEXT DEFAULT 'python',
                raw_code TEXT NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                total_issues INTEGER NOT NULL,
                critical_issues INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS review_issues (
                id TEXT PRIMARY KEY,
                review_id TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                suggested_fix TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (review_id) REFERENCES reviews (id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_issues_review ON review_issues(review_id);
            CREATE INDEX IF NOT EXISTS idx_reviews_created ON reviews(created_at);
        """)
    return conn
