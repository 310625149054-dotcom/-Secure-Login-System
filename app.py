"""
app.py - Production-ready, cybersecurity-focused Flask Authentication Application.

Implements:
- Argon2id password hashing
- CSRF protection via Flask-WTF
- Granular rate limiting via Flask-Limiter
- Session fixation protection & secure cookie attributes (HttpOnly, SameSite, Secure)
- Parameterized SQLite queries against SQL injection
- Timing-attack-resistant authentication flow
- Defense-in-depth HTTP security response headers
"""

import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Tuple, Dict, Any

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    g
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from email_validator import validate_email, EmailNotValidError
from dotenv import load_dotenv

import database

# Load environment configuration
load_dotenv()

# Initialize Argon2 Password Hasher (Argon2id default params)
# 64MB memory cost, 2 iterations, 1 parallelism, 32 bytes hash length
hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16
)

# Pre-computed dummy hash to mitigate timing-based user enumeration attacks
DUMMY_HASH = hasher.hash("Secur3LoginDummyToken#2026")

# Module-level extensions to maintain reference integrity
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["300 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)


def create_app(test_config: Optional[Dict[str, Any]] = None) -> Flask:
    """Application factory for secure Flask app instance."""
    app = Flask(__name__)

    # Default security configuration
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
        DATABASE_PATH=os.environ.get("DATABASE_PATH", "secure_login.db"),
        PERMANENT_SESSION_LIFETIME=timedelta(
            minutes=int(os.environ.get("PERMANENT_SESSION_LIFETIME_MINUTES", "30"))
        ),
        # Session cookie hardening
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1"),
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_TIME_LIMIT=3600,
        RATELIMIT_STORAGE_URI="memory://",
        RATELIMIT_STRATEGY="fixed-window",
    )

    if test_config:
        app.config.update(test_config)

    # Initialize extensions
    csrf.init_app(app)
    limiter.init_app(app)
    app.limiter = limiter

    # Initialize database
    with app.app_context():
        database.init_db(app.config["DATABASE_PATH"])

    # --- Security Headers Middleware ---
    @app.after_request
    def set_security_headers(response):
        """Inject robust HTTP security headers into every response."""
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:;"
        )
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    # --- Template Context Processors ---
    @app.context_processor
    def inject_auth_state():
        """Expose current user status and app metadata to templates."""
        return {
            "current_user": session.get("username"),
            "user_email": session.get("email"),
            "is_authenticated": bool(session.get("user_id")),
            "now_year": datetime.now(timezone.utc).year,
        }

    # --- Authentication Decorator ---
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("user_id"):
                flash("Authentication required. Please sign in to access this page.", "warning")
                return redirect(url_for("login", next=request.path))
            return f(*args, **kwargs)
        return decorated_function

    # --- Validation Utilities ---
    def validate_registration_input(
        username: str,
        email: str,
        password: str,
        confirm_password: str
    ) -> Tuple[bool, Optional[str]]:
        """Strict server-side validation for account registration."""
        # 1. Username checks: 3-30 chars, alphanumeric + underscore/hyphen
        if not username or len(username.strip()) < 3 or len(username.strip()) > 30:
            return False, "Username must be between 3 and 30 characters in length."
        if not re.match(r"^[a-zA-Z0-9_-]+$", username.strip()):
            return False, "Username can only contain alphanumeric characters, hyphens, and underscores."

        # 2. Email checks: RFC-compliant syntax
        if not email:
            return False, "Email address is required."
        try:
            validate_email(email.strip(), check_deliverability=False)
        except EmailNotValidError as e:
            return False, f"Invalid email format: {str(e)}"

        # 3. Password match
        if password != confirm_password:
            return False, "Password and confirmation password do not match."

        # 4. Password complexity policy
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        if len(password) > 128:
            return False, "Password exceeds maximum allowable length of 128 characters."
        if not re.search(r"[A-Z]", password):
            return False, "Password must include at least one uppercase letter (A-Z)."
        if not re.search(r"[a-z]", password):
            return False, "Password must include at least one lowercase letter (a-z)."
        if not re.search(r"[0-9]", password):
            return False, "Password must include at least one numerical digit (0-9)."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_+=\[\]\\/`~]", password):
            return False, "Password must include at least one special character (e.g. !@#$%^&*)."

        return True, None

    # --- Routes ---

    @app.route("/")
    def index():
        """Public homepage with security dashboard overview."""
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def register():
        """User registration endpoint with Argon2 hashing and duplicate prevention."""
        if session.get("user_id"):
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            # Server-side validation
            is_valid, error_message = validate_registration_input(
                username, email, password, confirm_password
            )
            if not is_valid:
                flash(error_message, "danger")
                return render_template("register.html", username=username, email=email)

            # Hash password using Argon2id
            try:
                hashed_password = hasher.hash(password)
            except Exception:
                flash("An error occurred during secure credential processing.", "danger")
                return render_template("register.html", username=username, email=email)

            # Insert user into database with parameterized query
            success, db_error, user_id = database.create_user(
                username=username,
                email=email,
                password_hash=hashed_password,
                db_path=app.config["DATABASE_PATH"]
            )

            if not success:
                flash(db_error or "Registration failed. Please try again.", "danger")
                return render_template("register.html", username=username, email=email)

            flash("Account successfully created! You may now sign in with your credentials.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("8 per minute", methods=["POST"])
    def login():
        """
        User login endpoint.
        - Supports login by username or email
        - Uses timing-safe Argon2 verification
        - Generic error messages to prevent enumeration
        - Account lockout integration
        - Session fixation protection
        """
        if session.get("user_id"):
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            identifier = request.form.get("identifier", "").strip()
            password = request.form.get("password", "")

            if not identifier or not password:
                flash("Please provide both your username/email and password.", "danger")
                return render_template("login.html", identifier=identifier)

            user = database.get_user_by_identifier(
                identifier,
                db_path=app.config["DATABASE_PATH"]
            )

            # Account Lockout Check
            if user:
                is_locked, remaining_str = database.is_account_locked(user)
                if is_locked:
                    flash(
                        f"Account is temporarily locked due to excessive failed attempts. Try again in {remaining_str}.",
                        "danger"
                    )
                    return render_template("login.html", identifier=identifier)

            # Verification with timing attack mitigation
            password_matches = False
            if user:
                try:
                    password_matches = hasher.verify(user["password_hash"], password)
                    # Check if hash needs rehash with updated cost parameters
                    if hasher.check_needs_rehash(user["password_hash"]):
                        # Could silently rehash here in future migrations
                        pass
                except (VerifyMismatchError, VerificationError, InvalidHashError):
                    password_matches = False
            else:
                # Perform dummy verification so response time does not reveal whether user exists
                try:
                    hasher.verify(DUMMY_HASH, password)
                except Exception:
                    pass
                password_matches = False

            if not password_matches:
                if user:
                    # Increment failed attempt counter
                    new_count, is_now_locked = database.record_failed_login(
                        user["id"],
                        max_attempts=5,
                        lockout_duration_minutes=15,
                        db_path=app.config["DATABASE_PATH"]
                    )
                    if is_now_locked:
                        flash(
                            "Account has been temporarily locked for 15 minutes due to 5 consecutive failed attempts.",
                            "danger"
                        )
                        return render_template("login.html", identifier=identifier)

                # Return generic error message to prevent user enumeration
                flash("Invalid credentials. Please verify your login details and try again.", "danger")
                return render_template("login.html", identifier=identifier)

            # Authentication succeeded: reset failed attempts
            database.record_successful_login(user["id"], db_path=app.config["DATABASE_PATH"])

            # Prevent Session Fixation: clear existing session and rebuild fresh
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["email"] = user["email"]
            session["auth_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            flash(f"Welcome back, {user['username']}! Authentication successful.", "success")

            next_url = request.args.get("next")
            # Ensure next_url is relative to prevent open-redirect vulnerabilities
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        """Protected dashboard: accessible strictly to authenticated users."""
        user = database.get_user_by_id(session["user_id"], db_path=app.config["DATABASE_PATH"])
        if not user:
            session.clear()
            flash("User session invalid. Please log in again.", "danger")
            return redirect(url_for("login"))

        return render_template("dashboard.html", user=user)

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        """Secure logout: clears session, invalidates cookies."""
        session.clear()
        flash("You have been securely logged out.", "info")
        return redirect(url_for("login"))

    # --- Error Handlers ---

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        """Custom handler for Cross-Site Request Forgery violations."""
        return render_template(
            "index.html",
            csrf_error="CSRF Token validation failed or session expired. Request rejected for security.",
            status_code=400
        ), 400

    @app.errorhandler(429)
    def ratelimit_handler(e):
        """Custom handler for rate limit violations."""
        flash("Rate limit exceeded! Please pause and try again in a moment.", "danger")
        return render_template("index.html", rate_limit_error=str(e.description)), 429

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("index.html", not_found_error="The requested resource was not found."), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("index.html", server_error="An unexpected server error occurred."), 500

    return app


# Default entry point
app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
