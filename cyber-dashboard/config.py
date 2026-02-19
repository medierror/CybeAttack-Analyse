import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "cyber-dashboard-secret-key-2026")

    # ── Database ─────────────────────────────────────────────
    # Default: SQLite (no extra setup needed)
    # To use MySQL, set the DATABASE_URL environment variable:
    #   export DATABASE_URL="mysql+pymysql://root:password@localhost/cyber_dashboard"
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'cyber_dashboard.db')}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── File Uploads ─────────────────────────────────────────
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max
    ALLOWED_EXTENSIONS = {"txt", "log", "csv"}
