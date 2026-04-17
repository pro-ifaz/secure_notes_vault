import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import bleach
import psycopg2
import psycopg2.extras
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, HiddenField
from wtforms.validators import DataRequired, Email, Length
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["WTF_CSRF_TIME_LIMIT"] = 3600

csrf = CSRFProtect(app)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

MAX_FAILED_ATTEMPTS = 3
LOCK_MINUTES = 5
OTP_VALID_MINUTES = 3
RESET_TOKEN_MAX_AGE_SECONDS = 900


# Forms

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=30)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=128)])


class OTPForm(FlaskForm):
    otp = StringField("OTP", validators=[DataRequired(), Length(min=6, max=6)])


class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=120)])


class ResetPasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired(), Length(min=8, max=128)])


class NoteForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(min=1, max=100)])
    body = TextAreaField("Body", validators=[DataRequired(), Length(min=1, max=2000)])


class DeleteForm(FlaskForm):
    note_id = HiddenField("Note ID", validators=[DataRequired()])


# PostgreSQL helpers

def database_url():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL environment variable is missing. Add your Supabase/Neon PostgreSQL connection string.")
    return url


def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(
            database_url(),
            cursor_factory=psycopg2.extras.RealDictCursor,
            sslmode="require"
        )
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = psycopg2.connect(database_url(), sslmode="require")
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lock_until TIMESTAMPTZ,
            last_device_fingerprint TEXT,
            created_at TIMESTAMPTZ NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            event TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMPTZ NOT NULL
        )
    """)

    conn.commit()
    cur.close()
    conn.close()


def fetchone(query, params=()):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchone()


def fetchall(query, params=()):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchall()


def execute(query, params=(), commit=True):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(query, params)
    if commit:
        conn.commit()


# Utility and security helpers

def now_utc():
    return datetime.now(timezone.utc)


def now_iso():
    return now_utc()


def log_activity(user_id, event):
    execute(
        "INSERT INTO activity_logs (user_id, event, ip_address, user_agent, created_at) VALUES (%s, %s, %s, %s, %s)",
        (
            user_id,
            event,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            request.headers.get("User-Agent", "unknown")[:255],
            now_iso()
        )
    )


def get_device_fingerprint():
    raw = f"{request.headers.get('User-Agent', '')}|{request.remote_addr}"
    return secrets.token_hex(8) + ":" + str(abs(hash(raw)))


def is_strong_password(password):
    checks = [
        len(password) >= 8,
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ]
    return all(checks)


def password_policy_message():
    return "Password must be at least 8 characters and include uppercase, lowercase, number, and special character."


def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def sanitize_text(text):
    return bleach.clean(text.strip(), tags=[], attributes={}, strip=True)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def otp_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("pending_2fa_user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# Routes

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = sanitize_text(form.username.data)
        email = sanitize_text(form.email.data.lower())
        password = form.password.data

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash("Username may contain only letters, numbers, and underscores.", "danger")
            return render_template("register.html", form=form)

        if not is_strong_password(password):
            flash(password_policy_message(), "danger")
            return render_template("register.html", form=form)

        existing = fetchone(
            "SELECT id FROM users WHERE username = %s OR email = %s",
            (username, email)
        )

        if existing:
            flash("Username or email already exists.", "danger")
            return render_template("register.html", form=form)

        execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (%s, %s, %s, %s)",
            (username, email, hash_password(password), now_iso())
        )

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = sanitize_text(form.username.data)
        password = form.password.data

        user = fetchone(
            "SELECT * FROM users WHERE username = %s",
            (username,)
        )

        if not user:
            flash("Invalid username or password.", "danger")
            return render_template("login.html", form=form)

        lock_until = user["lock_until"]
        if lock_until and lock_until > now_utc():
            remaining = int((lock_until - now_utc()).total_seconds() // 60) + 1
            flash(f"Account temporarily locked. Try again in about {remaining} minute(s).", "danger")
            return render_template("login.html", form=form)

        if not verify_password(password, user["password_hash"]):
            failed_attempts = user["failed_attempts"] + 1

            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                locked_until = now_utc() + timedelta(minutes=LOCK_MINUTES)
                execute(
                    "UPDATE users SET failed_attempts = %s, lock_until = %s WHERE id = %s",
                    (failed_attempts, locked_until, user["id"])
                )
                log_activity(user["id"], "Account locked after multiple failed login attempts")
                flash(f"Too many failed attempts. Account locked for {LOCK_MINUTES} minutes.", "danger")
            else:
                execute(
                    "UPDATE users SET failed_attempts = %s WHERE id = %s",
                    (failed_attempts, user["id"])
                )
                flash(f"Invalid password. Failed attempts: {failed_attempts}/{MAX_FAILED_ATTEMPTS}.", "danger")

            return render_template("login.html", form=form)

        execute(
            "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE id = %s",
            (user["id"],)
        )

        otp = f"{secrets.randbelow(1000000):06d}"
        session.clear()
        session["pending_2fa_user_id"] = user["id"]
        session["otp"] = otp
        session["otp_expires_at"] = (now_utc() + timedelta(minutes=OTP_VALID_MINUTES)).isoformat()

        print("\n" + "=" * 60, flush=True)
        print(f"SECURE NOTES VAULT OTP for {user['username']}: {otp}", flush=True)
        print(f"OTP expires in {OTP_VALID_MINUTES} minutes.", flush=True)
        print("=" * 60 + "\n", flush=True)

        log_activity(user["id"], "Password verified. OTP generated")
        flash("Password verified. Enter the OTP shown in the server logs.", "info")
        return redirect(url_for("verify_otp"))

    return render_template("login.html", form=form)


@app.route("/verify-otp", methods=["GET", "POST"])
@otp_required
def verify_otp():
    form = OTPForm()

    if form.validate_on_submit():
        entered_otp = sanitize_text(form.otp.data)
        expires_at = datetime.fromisoformat(session.get("otp_expires_at"))

        if not expires_at or expires_at < now_utc():
            session.clear()
            flash("OTP expired. Please log in again.", "danger")
            return redirect(url_for("login"))

        if entered_otp != session.get("otp"):
            flash("Invalid OTP.", "danger")
            return render_template("verify_otp.html", form=form)

        user_id = session.get("pending_2fa_user_id")
        user = fetchone("SELECT * FROM users WHERE id = %s", (user_id,))

        new_fingerprint = get_device_fingerprint()
        old_fingerprint = user["last_device_fingerprint"]

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=30)

        if old_fingerprint != new_fingerprint:
            execute(
                "UPDATE users SET last_device_fingerprint = %s WHERE id = %s",
                (new_fingerprint, user["id"])
            )

            print("\n" + "=" * 60, flush=True)
            print(f"NEW DEVICE LOGIN NOTIFICATION for {user['email']}", flush=True)
            print(f"Username: {user['username']}", flush=True)
            print(f"IP: {request.remote_addr}", flush=True)
            print(f"Browser: {request.headers.get('User-Agent', 'unknown')[:120]}", flush=True)
            print(f"Time UTC: {now_utc().isoformat()}", flush=True)
            print("In real deployment, this would be sent by email or SMS.", flush=True)
            print("=" * 60 + "\n", flush=True)

            log_activity(user["id"], "New device login notification generated")
            flash("New device login detected. Notification simulated in logs.", "warning")

        log_activity(user["id"], "Login successful with 2FA")
        return redirect(url_for("dashboard"))

    return render_template("verify_otp.html", form=form)


@app.route("/dashboard")
@login_required
def dashboard():
    query = sanitize_text(request.args.get("q", ""))

    if query:
        pattern = f"%{query}%"
        notes = fetchall(
            "SELECT * FROM notes WHERE user_id = %s AND (title ILIKE %s OR body ILIKE %s) ORDER BY updated_at DESC",
            (session["user_id"], pattern, pattern)
        )
    else:
        notes = fetchall(
            "SELECT * FROM notes WHERE user_id = %s ORDER BY updated_at DESC",
            (session["user_id"],)
        )

    logs = fetchall(
        "SELECT * FROM activity_logs WHERE user_id = %s ORDER BY created_at DESC LIMIT 8",
        (session["user_id"],)
    )

    delete_form = DeleteForm()
    return render_template("dashboard.html", notes=notes, logs=logs, query=query, delete_form=delete_form)


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def new_note():
    form = NoteForm()

    if form.validate_on_submit():
        title = sanitize_text(form.title.data)
        body = sanitize_text(form.body.data)

        execute(
            "INSERT INTO notes (user_id, title, body, created_at, updated_at) VALUES (%s, %s, %s, %s, %s)",
            (session["user_id"], title, body, now_iso(), now_iso())
        )
        log_activity(session["user_id"], "Created a secure note")
        flash("Note created.", "success")
        return redirect(url_for("dashboard"))

    return render_template("note_form.html", form=form, mode="Create")


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id):
    note = fetchone(
        "SELECT * FROM notes WHERE id = %s AND user_id = %s",
        (note_id, session["user_id"])
    )

    if not note:
        flash("Note not found or access denied.", "danger")
        return redirect(url_for("dashboard"))

    form = NoteForm()

    if request.method == "GET":
        form.title.data = note["title"]
        form.body.data = note["body"]

    if form.validate_on_submit():
        title = sanitize_text(form.title.data)
        body = sanitize_text(form.body.data)

        execute(
            "UPDATE notes SET title = %s, body = %s, updated_at = %s WHERE id = %s AND user_id = %s",
            (title, body, now_iso(), note_id, session["user_id"])
        )
        log_activity(session["user_id"], "Edited a secure note")
        flash("Note updated.", "success")
        return redirect(url_for("dashboard"))

    return render_template("note_form.html", form=form, mode="Edit")


@app.route("/notes/delete", methods=["POST"])
@login_required
def delete_note():
    form = DeleteForm()

    if form.validate_on_submit():
        note_id = int(form.note_id.data)

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM notes WHERE id = %s AND user_id = %s",
                (note_id, session["user_id"])
            )
            deleted_rows = cur.rowcount
        conn.commit()

        if deleted_rows > 0:
            log_activity(session["user_id"], "Deleted a secure note")
            flash("Note deleted.", "success")
        else:
            flash("No note was deleted.", "danger")
    else:
        flash(f"Delete request failed validation: {form.errors}", "danger")

    return redirect(url_for("dashboard"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = sanitize_text(form.email.data.lower())
        user = fetchone("SELECT * FROM users WHERE email = %s", (email,))

        if user:
            token = serializer.dumps(email, salt="password-reset")
            reset_link = url_for("reset_password", token=token, _external=True)

            print("\n" + "=" * 60, flush=True)
            print(f"PASSWORD RESET LINK for {email}", flush=True)
            print(reset_link, flush=True)
            print("In real deployment, this would be sent by email.", flush=True)
            print("=" * 60 + "\n", flush=True)

            log_activity(user["id"], "Password reset link generated")

        flash("If the email exists, a password reset link has been generated in the server logs.", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password.html", form=form)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = serializer.loads(
            token,
            salt="password-reset",
            max_age=RESET_TOKEN_MAX_AGE_SECONDS
        )
    except SignatureExpired:
        flash("Reset link expired.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Invalid reset link.", "danger")
        return redirect(url_for("forgot_password"))

    form = ResetPasswordForm()

    if form.validate_on_submit():
        password = form.password.data

        if not is_strong_password(password):
            flash(password_policy_message(), "danger")
            return render_template("reset_password.html", form=form)

        user = fetchone("SELECT * FROM users WHERE email = %s", (email,))

        if user:
            execute(
                "UPDATE users SET password_hash = %s, failed_attempts = 0, lock_until = NULL WHERE id = %s",
                (hash_password(password), user["id"])
            )
            log_activity(user["id"], "Password reset completed")

        flash("Password changed successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", form=form)


@app.route("/logout")
@login_required
def logout():
    user_id = session["user_id"]
    log_activity(user_id, "Logged out")
    session.clear()
    flash("Logged out securely.", "success")
    return redirect(url_for("login"))


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


# Gunicorn imports app:app, so database initialization must run at import time.
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
