"""
test_auth.py - Comprehensive Automated Security & Functional Test Suite.

Covers:
1. User registration & Argon2id password hashing
2. Duplicate username & email prevention
3. Input validation & password complexity policies
4. Authentication by username & email
5. Generic error messages (enumeration defense)
6. Protected dashboard route authorization
7. Secure logout & session invalidation
8. SQL Injection resistance in authentication queries
9. CSRF token validation and missing token rejection (HTTP 400)
10. Account lockout defense after excessive failed attempts
11. Defense-in-depth HTTP security response headers
"""

import os
import re
import sqlite3
import tempfile
import pytest
from argon2 import PasswordHasher

from app import create_app, hasher
import database


@pytest.fixture
def app_instance():
    """Create a pristine temporary SQLite database and test app instance."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    app = create_app({
        "TESTING": True,
        "DATABASE_PATH": db_path,
        "WTF_CSRF_ENABLED": True,
        "SECRET_KEY": "test-cybersecurity-secret-key-32chars",
        "RATELIMIT_ENABLED": False,  # Disable global rate-limiting during fast unit test execution
    })

    with app.app_context():
        database.init_db(db_path)

    yield app

    # Cleanup temporary test database
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


@pytest.fixture
def client(app_instance):
    """Test client with cookie and session support."""
    return app_instance.test_client()


def get_csrf_token(client, endpoint="/login") -> str:
    """Helper to fetch an endpoint and extract the CSRF token from the HTML form."""
    resp = client.get(endpoint)
    html = resp.get_data(as_text=True)
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if not match:
        raise ValueError(f"Could not locate CSRF token in response from {endpoint}")
    return match.group(1)


# ==============================================================================
# 1. Registration & Password Hashing Tests
# ==============================================================================

def test_user_registration_success(client, app_instance):
    """Verify that a user with strong credentials registers successfully."""
    csrf_token = get_csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "csrf_token": csrf_token,
            "username": "cyber_cadet",
            "email": "cadet@cybersec.edu",
            "password": "SecurePassword#2026",
            "confirm_password": "SecurePassword#2026",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Account successfully created" in html


def test_password_hashing_in_database(client, app_instance):
    """Verify password is stored as an Argon2id hash and never as plaintext."""
    raw_password = "SuperHardPassword@99"
    csrf_token = get_csrf_token(client, "/register")
    client.post(
        "/register",
        data={
            "csrf_token": csrf_token,
            "username": "hash_tester",
            "email": "hash@defense.gov",
            "password": raw_password,
            "confirm_password": raw_password,
        },
    )

    db_path = app_instance.config["DATABASE_PATH"]
    conn = database.get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = 'hash_tester'")
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    stored_hash = row["password_hash"]

    # 1. Plaintext password MUST NOT appear anywhere in the database
    assert raw_password not in stored_hash

    # 2. Must be an Argon2id format ($argon2id$v=...)
    assert stored_hash.startswith("$argon2id$")

    # 3. Must successfully verify via Argon2 PasswordHasher
    assert hasher.verify(stored_hash, raw_password) is True


def test_duplicate_username_prevention(client, app_instance):
    """Verify duplicate username registration is prevented with a clean error."""
    csrf = get_csrf_token(client, "/register")
    client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "unique_user",
            "email": "first@test.com",
            "password": "ValidPassword!123",
            "confirm_password": "ValidPassword!123",
        },
    )

    # Attempt to register the exact same username with a different email
    csrf2 = get_csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "csrf_token": csrf2,
            "username": "unique_user",
            "email": "second@test.com",
            "password": "ValidPassword!123",
            "confirm_password": "ValidPassword!123",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Username is already registered." in response.get_data(as_text=True)


def test_duplicate_email_prevention(client, app_instance):
    """Verify duplicate email registration is prevented with a clean error."""
    csrf = get_csrf_token(client, "/register")
    client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "first_user",
            "email": "duplicate@test.com",
            "password": "ValidPassword!123",
            "confirm_password": "ValidPassword!123",
        },
    )

    # Attempt to register different username with the exact same email
    csrf2 = get_csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "csrf_token": csrf2,
            "username": "second_user",
            "email": "duplicate@test.com",
            "password": "ValidPassword!123",
            "confirm_password": "ValidPassword!123",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Email address is already registered." in response.get_data(as_text=True)


# ==============================================================================
# 2. Input Validation & Complexity Tests
# ==============================================================================

@pytest.mark.parametrize("invalid_password, expected_error", [
    ("Short1!", "at least 8 characters"),
    ("alllowercase123!", "uppercase letter"),
    ("ALLUPPERCASE123!", "lowercase letter"),
    ("NoNumbersSpecial!", "numerical digit"),
    ("NoSpecialChar123", "special character"),
])
def test_password_complexity_enforcement(client, invalid_password, expected_error):
    """Ensure weak passwords violating policy are strictly rejected."""
    csrf = get_csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "policy_tester",
            "email": "policy@test.com",
            "password": invalid_password,
            "confirm_password": invalid_password,
        },
        follow_redirects=True,
    )
    html = response.get_data(as_text=True)
    assert expected_error in html


def test_password_mismatch(client):
    """Ensure mismatched confirmation password is rejected."""
    csrf = get_csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "mismatch_user",
            "email": "mismatch@test.com",
            "password": "StrongPassword!1",
            "confirm_password": "DifferentPassword!1",
        },
        follow_redirects=True,
    )
    assert "Password and confirmation password do not match." in response.get_data(as_text=True)


def test_invalid_email_format(client):
    """Ensure invalid email format fails server-side validation."""
    csrf = get_csrf_token(client, "/register")
    response = client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "bademail_user",
            "email": "not-an-email-at-all",
            "password": "StrongPassword!1",
            "confirm_password": "StrongPassword!1",
        },
        follow_redirects=True,
    )
    assert "Invalid email format" in response.get_data(as_text=True)


# ==============================================================================
# 3. Authentication & Login Tests
# ==============================================================================

def test_login_with_username(client):
    """Ensure a user can sign in using their username."""
    # Register user
    csrf = get_csrf_token(client, "/register")
    client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "alice_sec",
            "email": "alice@university.edu",
            "password": "AliceSecretPassword$1",
            "confirm_password": "AliceSecretPassword$1",
        },
    )

    # Login with username
    login_csrf = get_csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": login_csrf,
            "identifier": "alice_sec",
            "password": "AliceSecretPassword$1",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Welcome" in html
    assert "alice_sec" in html


def test_login_with_email(client):
    """Ensure a user can sign in using their email address."""
    # Register user
    csrf = get_csrf_token(client, "/register")
    client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "bob_sec",
            "email": "bob@defense.edu",
            "password": "BobSecretPassword$2",
            "confirm_password": "BobSecretPassword$2",
        },
    )

    # Login with email
    login_csrf = get_csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": login_csrf,
            "identifier": "bob@defense.edu",
            "password": "BobSecretPassword$2",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Welcome" in html
    assert "bob_sec" in html


def test_login_with_incorrect_password(client):
    """Verify incorrect password yields a generic error message (anti-enumeration)."""
    csrf = get_csrf_token(client, "/register")
    client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "charlie_sec",
            "email": "charlie@test.com",
            "password": "CharlieCorrectPassword!1",
            "confirm_password": "CharlieCorrectPassword!1",
        },
    )

    login_csrf = get_csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": login_csrf,
            "identifier": "charlie_sec",
            "password": "WrongPasswordAttempt#9",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Invalid credentials." in html


def test_login_with_nonexistent_user(client):
    """Verify non-existent user also receives generic error message without enumerating account existence."""
    login_csrf = get_csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": login_csrf,
            "identifier": "ghost_user_not_exist",
            "password": "SomePassword123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Invalid credentials." in html


# ==============================================================================
# 4. Protected Routes & Session Handling
# ==============================================================================

def test_unauthenticated_dashboard_redirect(client):
    """Accessing /dashboard while unauthenticated redirects to /login."""
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_dashboard_accessible_when_authenticated(client):
    """Dashboard is rendered when authenticated session exists."""
    csrf = get_csrf_token(client, "/register")
    client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "diana_sec",
            "email": "diana@test.org",
            "password": "DianaPassword!1",
            "confirm_password": "DianaPassword!1",
        },
    )
    login_csrf = get_csrf_token(client, "/login")
    client.post(
        "/login",
        data={
            "csrf_token": login_csrf,
            "identifier": "diana_sec",
            "password": "DianaPassword!1",
        },
    )

    response = client.get("/dashboard")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "diana_sec" in html
    assert "diana@test.org" in html
    assert "Active Defense Parameters" in html


def test_secure_logout(client):
    """Logout clears session and prevents subsequent dashboard access."""
    csrf = get_csrf_token(client, "/register")
    client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "evan_sec",
            "email": "evan@test.org",
            "password": "EvanPassword!1",
            "confirm_password": "EvanPassword!1",
        },
    )
    login_csrf = get_csrf_token(client, "/login")
    client.post(
        "/login",
        data={
            "csrf_token": login_csrf,
            "identifier": "evan_sec",
            "password": "EvanPassword!1",
        },
    )

    # Perform logout
    logout_csrf = get_csrf_token(client, "/dashboard")
    logout_resp = client.post(
        "/logout",
        data={"csrf_token": logout_csrf},
        follow_redirects=True,
    )
    assert logout_resp.status_code == 200
    assert "securely logged out" in logout_resp.get_data(as_text=True)

    # Attempt to access protected dashboard after logout
    dashboard_resp = client.get("/dashboard", follow_redirects=False)
    assert dashboard_resp.status_code == 302
    assert "/login" in dashboard_resp.headers["Location"]


# ==============================================================================
# 5. Security Attacks: SQL Injection & CSRF Defense
# ==============================================================================

def test_sql_injection_login_attempt(client):
    """
    Test classical SQL injection payload in identifier field:
    ' OR '1'='1' --
    Parameterized queries must evaluate this as a literal string.
    """
    login_csrf = get_csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": login_csrf,
            "identifier": "' OR '1'='1' --",
            "password": "' OR '1'='1' --",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Invalid credentials." in html
    assert "Session Active" not in html


def test_csrf_protection_missing_token(client):
    """POST request without CSRF token must be rejected with HTTP 400 Bad Request."""
    response = client.post(
        "/login",
        data={
            "identifier": "admin",
            "password": "SomePassword123!",
        },
    )
    assert response.status_code == 400
    assert "CSRF" in response.get_data(as_text=True)


def test_csrf_protection_invalid_token(client):
    """POST request with forged/tampered CSRF token must be rejected with HTTP 400 Bad Request."""
    response = client.post(
        "/login",
        data={
            "csrf_token": "forged_malicious_csrf_token_value_xyz",
            "identifier": "admin",
            "password": "SomePassword123!",
        },
    )
    assert response.status_code == 400
    assert "CSRF" in response.get_data(as_text=True)


# ==============================================================================
# 6. Account Lockout & Security Headers
# ==============================================================================

def test_account_lockout_after_failed_attempts(client):
    """Account is temporarily locked after 5 consecutive failed login attempts."""
    csrf = get_csrf_token(client, "/register")
    client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "username": "lockout_target",
            "email": "lockout@target.com",
            "password": "TargetPassword!1",
            "confirm_password": "TargetPassword!1",
        },
    )

    # Perform 5 failed attempts
    for _ in range(5):
        l_csrf = get_csrf_token(client, "/login")
        client.post(
            "/login",
            data={
                "csrf_token": l_csrf,
                "identifier": "lockout_target",
                "password": "IncorrectPassword!0",
            },
        )

    # 6th attempt: should indicate account is locked
    l_csrf = get_csrf_token(client, "/login")
    response = client.post(
        "/login",
        data={
            "csrf_token": l_csrf,
            "identifier": "lockout_target",
            "password": "TargetPassword!1",  # Even with correct password, account is locked!
        },
        follow_redirects=True,
    )
    html = response.get_data(as_text=True)
    assert "temporarily locked" in html


def test_http_security_headers(client):
    """Ensure HTTP responses contain OWASP-recommended security defense headers."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"
    assert "Content-Security-Policy" in response.headers
