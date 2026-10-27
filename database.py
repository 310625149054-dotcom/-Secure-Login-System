"""
database.py - Database access layer for Secure Login System.

Implements SQLite storage with parameterized queries to prevent SQL injection,
schema initialization, and helper functions for user management and account lockout.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple

DEFAULT_DB_PATH = os.environ.get("DATABASE_PATH", "secure_login.db")


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Establish and return a connection to the SQLite database.
    Configures row_factory to sqlite3.Row for dict-like column access.
    Enforces foreign keys.
    """
    target_path = db_path or os.environ.get("DATABASE_PATH", DEFAULT_DB_PATH)
    conn = sqlite3.connect(target_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initialize the database schema if tables do not already exist.
    Creates the users table with strict constraints:
      - Unique username (case-insensitive)
      - Unique email (case-insensitive)
      - Argon2 password hash
      - Failed attempt counter and lockout timestamp for brute-force protection
      - Timestamp tracking (created_at, last_login)
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until TIMESTAMP,
                    last_login TIMESTAMP,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            # Create indexes for fast, case-insensitive lookups
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_users_username_lower
                ON users(username COLLATE NOCASE);
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_users_email_lower
                ON users(email COLLATE NOCASE);
                """
            )
    finally:
        conn.close()


def create_user(
    username: str,
    email: str,
    password_hash: str,
    db_path: Optional[str] = None
) -> Tuple[bool, Optional[str], Optional[int]]:
    """
    Insert a new user using parameterized queries to prevent SQL injection.
    Returns:
        (success: bool, error_message: Optional[str], user_id: Optional[int])
    """
    cleaned_username = username.strip()
    cleaned_email = email.strip().lower()

    conn = get_db_connection(db_path)
    try:
        with conn:
            # Check explicitly for duplicate username or email to return clear feedback
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, email FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
                (cleaned_username, cleaned_email),
            )
            existing = cursor.fetchall()
            for row in existing:
                if row["username"].lower() == cleaned_username.lower():
                    return False, "Username is already registered.", None
                if row["email"].lower() == cleaned_email.lower():
                    return False, "Email address is already registered.", None

            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (cleaned_username, cleaned_email, password_hash),
            )
            user_id = cursor.lastrowid
            return True, None, user_id
    except sqlite3.IntegrityError as e:
        err_msg = str(e).lower()
        if "username" in err_msg:
            return False, "Username is already registered.", None
        if "email" in err_msg:
            return False, "Email address is already registered.", None
        return False, "A database integrity error occurred.", None
    finally:
        conn.close()


def get_user_by_identifier(
    identifier: str,
    db_path: Optional[str] = None
) -> Optional[sqlite3.Row]:
    """
    Fetch a user record by either username or email.
    Uses parameterized query to prevent SQL injection vulnerabilities.
    """
    cleaned_id = identifier.strip()
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM users
            WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
            LIMIT 1
            """,
            (cleaned_id, cleaned_id),
        )
        return cursor.fetchone()
    finally:
        conn.close()


def get_user_by_id(
    user_id: int,
    db_path: Optional[str] = None
) -> Optional[sqlite3.Row]:
    """
    Fetch a user record by primary key ID.
    """
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ? LIMIT 1", (user_id,))
        return cursor.fetchone()
    finally:
        conn.close()


def record_failed_login(
    user_id: int,
    max_attempts: int = 5,
    lockout_duration_minutes: int = 15,
    db_path: Optional[str] = None
) -> Tuple[int, bool]:
    """
    Increment failed login count for a user.
    If attempts reach max_attempts, locks account until now + lockout_duration_minutes.
    Returns:
        (new_failed_count: int, is_now_locked: bool)
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT failed_login_attempts FROM users WHERE id = ?",
                (user_id,)
            )
            row = cursor.fetchone()
            if not row:
                return 0, False

            new_count = row["failed_login_attempts"] + 1
            locked_until = None
            is_locked = False

            if new_count >= max_attempts:
                locked_until = (datetime.now(timezone.utc) + timedelta(minutes=lockout_duration_minutes)).strftime("%Y-%m-%d %H:%M:%S")
                is_locked = True

            cursor.execute(
                """
                UPDATE users
                SET failed_login_attempts = ?,
                    locked_until = COALESCE(?, locked_until)
                WHERE id = ?
                """,
                (new_count, locked_until, user_id),
            )
            return new_count, is_locked
    finally:
        conn.close()


def record_successful_login(
    user_id: int,
    db_path: Optional[str] = None
) -> None:
    """
    Reset failed login attempts and update last_login timestamp.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            conn.execute(
                """
                UPDATE users
                SET failed_login_attempts = 0,
                    locked_until = NULL,
                    last_login = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (user_id,),
            )
    finally:
        conn.close()


def is_account_locked(user_row: sqlite3.Row) -> Tuple[bool, Optional[str]]:
    """
    Check if a user account is currently locked out.
    Returns:
        (is_locked: bool, unlock_time_str: Optional[str])
    """
    locked_until = user_row["locked_until"]
    if not locked_until:
        return False, None

    # Handle string or datetime if parsed
    if isinstance(locked_until, str):
        try:
            lock_time = datetime.fromisoformat(locked_until.replace("Z", "+00:00"))
        except ValueError:
            try:
                lock_time = datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return False, None
    elif isinstance(locked_until, datetime):
        lock_time = locked_until
    else:
        return False, None

    # Make tz-aware if naive
    if lock_time.tzinfo is None:
        lock_time = lock_time.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    if now < lock_time:
        remaining = int((lock_time - now).total_seconds() / 60) + 1
        return True, f"{remaining} minute(s)"
    return False, None
