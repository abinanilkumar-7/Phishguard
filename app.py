"""PhishGuard AI - Phase 2 Flask web dashboard."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from analyzer import analyze_email

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = BASE_DIR / "database.db"
ALLOWED_EXTENSIONS = {".eml"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-local-development-key")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                created_at TEXT NOT NULL,
                reasons_json TEXT NOT NULL
            )
            """
        )


def allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def save_history(result: dict) -> None:
    email_info = result.get("email", {})
    risk = result.get("risk", {})
    with get_db() as connection:
        connection.execute(
            """
            INSERT INTO analyses
            (filename, sender, subject, score, classification, created_at, reasons_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.get("file_name", "unknown.eml"),
                email_info.get("from", ""),
                email_info.get("subject", ""),
                int(risk.get("score", 0)),
                risk.get("classification", "Unknown"),
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                json.dumps(risk.get("reasons", [])),
            ),
        )


@app.errorhandler(413)
def too_large(_error):
    flash("File is too large. Please upload an email smaller than 5 MB.", "error")
    return redirect(url_for("index"))


@app.get("/")
def index():
    with get_db() as connection:
        rows = connection.execute(
            "SELECT * FROM analyses ORDER BY id DESC LIMIT 8"
        ).fetchall()
        stats = connection.execute(
            """
            SELECT COUNT(*) AS total,
                SUM(CASE WHEN classification = 'Likely Phishing' THEN 1 ELSE 0 END) AS phishing,
                SUM(CASE WHEN classification = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN classification = 'Low Risk' THEN 1 ELSE 0 END) AS low_risk
            FROM analyses
            """
        ).fetchone()

    return render_template("index.html", history=rows, stats=stats)


@app.post("/analyze")
def analyze():
    uploaded = request.files.get("email_file")
    if uploaded is None or not uploaded.filename:
        flash("Choose an .eml file before starting the analysis.", "error")
        return redirect(url_for("index"))

    original_name = secure_filename(uploaded.filename)
    if not original_name or not allowed_file(original_name):
        flash("Unsupported file type. Please upload an .eml email file.", "error")
        return redirect(url_for("index"))

    # A random server-side name prevents path traversal and filename collisions.
    stored_path = UPLOAD_DIR / f"{uuid.uuid4().hex}.eml"
    uploaded.save(stored_path)

    try:
        check_reputation = request.form.get("check_reputation") == "on"
        result = analyze_email(stored_path, check_reputation=check_reputation)
        result["file_name"] = original_name
        save_history(result)
        return render_template("result.html", result=result)
    except Exception as exc:
        app.logger.exception("Email analysis failed")
        flash(f"Could not analyze this email: {exc}", "error")
        return redirect(url_for("index"))
    finally:
        try:
            stored_path.unlink(missing_ok=True)
        except OSError:
            app.logger.warning("Could not remove temporary upload: %s", stored_path)


@app.get("/history")
def history():
    with get_db() as connection:
        rows = connection.execute(
            "SELECT * FROM analyses ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return render_template("history.html", history=rows)


@app.get("/health")
def health():
    return {"status": "ok", "application": "PhishGuard AI"}


init_db()

if __name__ == "__main__":
    # Local development only. Do not expose Flask's development server publicly.
    app.run(host="127.0.0.1", port=5000, debug=True)
