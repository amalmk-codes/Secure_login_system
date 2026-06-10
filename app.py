import json
from datetime import datetime, timedelta

import pyotp
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, inspect, text
from sqlalchemy.exc import IntegrityError

from config import Config
from extensions import db, login_manager
from models.login_log import LoginLog
from models.user import User
from utils.qr_generator import generate_qr_data_uri
from utils.security import (
    consume_backup_code,
    generate_backup_codes,
    hash_password,
    verify_password,
)
from utils.validators import validate_password

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"


def verify_totp_code(secret, otp_code, valid_window=3):
    if not secret or not otp_code:
        return False

    cleaned_code = otp_code.strip().replace(" ", "")
    if not cleaned_code.isdigit():
        return False

    totp = pyotp.TOTP(secret)
    return totp.verify(cleaned_code, valid_window=valid_window)


def ensure_schema():
    db.create_all()
    inspector = inspect(db.engine)
    table_names = set(inspector.get_table_names())

    if "users" in table_names:
        user_columns = {column["name"] for column in inspector.get_columns("users")}
        with db.engine.begin() as connection:
            if "locked_until" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN locked_until DATETIME"))
            if "last_login" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN last_login DATETIME"))
            if "backup_codes" not in user_columns:
                connection.execute(text("ALTER TABLE users ADD COLUMN backup_codes TEXT"))

    if "login_logs" in table_names:
        log_columns = {column["name"] for column in inspector.get_columns("login_logs")}
        with db.engine.begin() as connection:
            if "username" not in log_columns:
                connection.execute(text("ALTER TABLE login_logs ADD COLUMN username VARCHAR(100)"))
            if "timestamp" not in log_columns:
                connection.execute(text("ALTER TABLE login_logs ADD COLUMN timestamp DATETIME"))


def record_login(user, status):
    db.session.add(
        LoginLog(
            user_id=user.id if user else 0,
            username=user.username if user else None,
            ip_address=request.remote_addr,
            status=status,
        )
    )


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        normalized_username = username.lower()
        user = User.query.filter(func.lower(User.username) == normalized_username).first()

        if user and user.locked_until and user.locked_until > datetime.utcnow():
            flash(f"Account locked until {user.locked_until.strftime('%Y-%m-%d %H:%M')}.", "danger")
            record_login(user, "Failed")
            db.session.commit()
            return render_template("login.html")

        if user and user.locked_until and user.locked_until <= datetime.utcnow():
            user.locked_until = None
            user.failed_attempts = 0

        if user and verify_password(user.password_hash, password):
            user.failed_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            db.session.add(user)
            if user.is_2fa_enabled and user.otp_secret:
                session["pending_2fa_user_id"] = user.id
                record_login(user, "Pending 2FA")
                db.session.commit()
                flash("Please enter your 2FA code.", "info")
                return redirect(url_for("verify_otp"))

            record_login(user, "Success")
            db.session.commit()
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                flash("Account locked for 15 minutes due to too many failed attempts.", "danger")
            else:
                flash("Invalid username or password.", "danger")
            record_login(user, "Failed")
            db.session.commit()
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        normalized_username = username.lower()
        normalized_email = email.lower()

        if not username or not email or not password:
            flash("All fields are required.", "danger")
        elif not validate_password(password):
            flash(
                "Password must be at least 8 characters and include uppercase, lowercase, a number, and a special character.",
                "danger",
            )
        elif User.query.filter(func.lower(User.username) == normalized_username).first():
            flash("That username is already taken.", "danger")
        elif User.query.filter(func.lower(User.email) == normalized_email).first():
            flash("That email is already registered.", "danger")
        else:
            user = User(
                username=username,
                email=normalized_email,
                password_hash=hash_password(password),
            )
            try:
                db.session.add(user)
                db.session.commit()
            except IntegrityError:
                db.session.rollback()
                flash("That email or username is already registered.", "danger")
            else:
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/dashboard")
@login_required
def dashboard():
    last_login = current_user.last_login.strftime("%Y-%m-%d %H:%M") if current_user.last_login else "Not recorded"
    return render_template(
        "dashboard.html",
        user=current_user,
        last_login=last_login,
        failed_attempts=current_user.failed_attempts or 0,
    )


@app.route("/logs")
@login_required
def logs():
    log_entries = (
        LoginLog.query.filter_by(user_id=current_user.id)
        .order_by(LoginLog.login_time.desc())
        .all()
    )
    return render_template("logs.html", logs=log_entries)


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    if request.method == "POST":
        otp_code = request.form.get("otp", "").strip()
        if not current_user.otp_secret:
            current_user.otp_secret = pyotp.random_base32()
            db.session.commit()

        if verify_totp_code(current_user.otp_secret, otp_code, valid_window=3):
            current_user.is_2fa_enabled = True
            if not current_user.backup_codes:
                backup_codes = generate_backup_codes()
                current_user.backup_codes = json.dumps([hash_password(code) for code in backup_codes])
                db.session.commit()
                return render_template(
                    "setup_2fa.html",
                    qr_code=generate_qr_data_uri(
                        pyotp.totp.TOTP(current_user.otp_secret).provisioning_uri(
                            current_user.email,
                            issuer_name="Secure Login System",
                        )
                    ),
                    otp_secret=current_user.otp_secret,
                    backup_codes=backup_codes,
                )

            db.session.commit()
            flash("Two-factor authentication enabled successfully.", "success")
            return redirect(url_for("dashboard"))

        flash(
            "Invalid verification code. If your phone clock is slightly off, wait 30 seconds and try again.",
            "danger",
        )

    if not current_user.otp_secret:
        current_user.otp_secret = pyotp.random_base32()
        db.session.commit()

    provisioning_uri = pyotp.totp.TOTP(current_user.otp_secret).provisioning_uri(
        current_user.email,
        issuer_name="Secure Login System",
    )
    qr_code = generate_qr_data_uri(provisioning_uri)
    return render_template(
        "setup_2fa.html",
        qr_code=qr_code,
        otp_secret=current_user.otp_secret,
        backup_codes=None,
    )


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        flash("Please log in first.", "danger")
        return redirect(url_for("login"))

    user = User.query.get(user_id)
    if not user or not user.otp_secret:
        session.pop("pending_2fa_user_id", None)
        flash("2FA setup is incomplete.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_code = request.form.get("otp", "").strip()
        otp_valid = verify_totp_code(user.otp_secret, otp_code, valid_window=3)
        backup_codes = user.backup_codes
        backup_valid = False

        if not otp_valid and backup_codes:
            backup_codes, backup_valid = consume_backup_code(backup_codes, otp_code)
            if backup_valid:
                user.backup_codes = backup_codes

        if otp_valid or backup_valid:
            session.pop("pending_2fa_user_id", None)
            user.failed_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            db.session.add(user)
            record_login(user, "Success")
            db.session.commit()
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        flash(
            "Invalid 2FA code. If your phone clock is slightly off, wait 30 seconds and try again.",
            "danger",
        )

    return render_template("verify_otp.html")


@app.route("/logout")
@login_required
def logout():
    session.pop("pending_2fa_user_id", None)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


with app.app_context():
    ensure_schema()


if __name__ == "__main__":
    app.run(debug=True)
