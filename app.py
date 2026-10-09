import os
from datetime import datetime, timedelta
import sqlite3
import hmac
import hashlib
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session, flash
)
import secrets
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv


load_dotenv()

app = Flask(__name__)
@app.template_filter("nice_datetime")
def nice_datetime(value):
    if not value:
        return "—"

    from datetime import datetime

    try:
        dt = datetime.fromisoformat(str(value))
        return dt.strftime("%d %b %Y, %I:%M %p")
    except (ValueError, TypeError):
        return str(value)


app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "FLASK_SECRET_KEY is missing. Check your .env file."
    )

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["WTF_CSRF_TIME_LIMIT"] = 3600

csrf = CSRFProtect(app)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response

DATABASE = "investment.db"

ADMIN_EMAIL = os.environ.get(
    "ADMIN_EMAIL",
    "admin@novavest.local"
)

ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD"
)

if not ADMIN_PASSWORD:
    raise RuntimeError(
        "ADMIN_PASSWORD is missing. Check your .env file."
    )
def audit_log(conn, actor_type, actor_id, action, entity_type=None, entity_id=None, details=None):
    conn.execute("""
        INSERT INTO audit_logs
        (actor_type, actor_id, action, entity_type, entity_id, details)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        actor_type,
        actor_id,
        action,
        entity_type,
        entity_id,
        details
    ))


def hash_reset_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_reset_token():
    return secrets.token_urlsafe(32)


def get_db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_notification(conn, user_id, title, message):
    conn.execute(
        """
        INSERT INTO notifications (user_id, title, message)
        VALUES (?, ?, ?)
        """,
        (user_id, title, message)
    )


def init_db():
    conn = get_db()

    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'Active'
            );

            CREATE TABLE IF NOT EXISTS investment_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL,
                minimum_amount REAL NOT NULL,
                term_days INTEGER NOT NULL,
                management_fee_percent REAL NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                return_percent REAL NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS deposits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                reference TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS withdrawals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                method TEXT NOT NULL,
                account_details TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS investments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                started_at TEXT NOT NULL,
                maturity_at TEXT NOT NULL,
                completed_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (plan_id) REFERENCES investment_plans(id)
            );

            CREATE TABLE IF NOT EXISTS investment_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                request_token TEXT NOT NULL UNIQUE,
                investment_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_type TEXT NOT NULL,
                actor_id INTEGER,
                action TEXT NOT NULL,
                entity_type TEXT,
                entity_id INTEGER,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS balance_adjustments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                adjustment_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS daily_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plan_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                reward REAL NOT NULL DEFAULT 0,
                task_type TEXT NOT NULL DEFAULT 'daily_checkin',
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (plan_id) REFERENCES investment_plans(id)
            );

            CREATE TABLE IF NOT EXISTS daily_task_completions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                task_date TEXT NOT NULL,
                reward REAL NOT NULL,
                completed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (task_id) REFERENCES daily_tasks(id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(task_id, user_id, task_date)
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TIMESTAMP NOT NULL,
                used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_created
                ON audit_logs(actor_type, actor_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_created
                ON audit_logs(created_at);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_entity
                ON audit_logs(entity_type, entity_id);
            CREATE INDEX IF NOT EXISTS idx_balance_adjustments_user_id
                ON balance_adjustments(user_id);
            CREATE INDEX IF NOT EXISTS idx_daily_task_completions_user_date
                ON daily_task_completions(user_id, task_date);
            CREATE INDEX IF NOT EXISTS idx_daily_tasks_plan
                ON daily_tasks(plan_id);
            CREATE INDEX IF NOT EXISTS idx_deposits_user_created
                ON deposits(user_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_investment_requests_user
                ON investment_requests(user_id);
            CREATE INDEX IF NOT EXISTS idx_investments_status
                ON investments(status);
            CREATE INDEX IF NOT EXISTS idx_investments_user
                ON investments(user_id);
            CREATE INDEX IF NOT EXISTS idx_notifications_user_created
                ON notifications(user_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires
                ON password_reset_tokens(expires_at);
            CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user
                ON password_reset_tokens(user_id);
            CREATE INDEX IF NOT EXISTS idx_transactions_user_created
                ON transactions(user_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_withdrawals_user_created
                ON withdrawals(user_id, created_at);
        """)

        migrations = {
            "users": {
                "status": "TEXT NOT NULL DEFAULT 'Active'"
            },
            "investment_plans": {
                "return_percent": "REAL NOT NULL DEFAULT 0"
            }
        }

        for table, columns in migrations.items():
            existing = {
                row["name"]
                for row in conn.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            for column, definition in columns.items():
                if column not in existing:
                    conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN "
                        f"{column} {definition}"
                    )

        conn.commit()

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def current_user():

    if "user_id" not in session:
        return None

    conn = get_db()

    user = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    conn.close()

    if not user:
        session.pop("user_id", None)
        return None

    if user["status"] != "Active":
        session.pop("user_id", None)
        return None

    return user


def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("admin"):
            return redirect(url_for("admin_login"))

        return function(*args, **kwargs)

    return wrapper


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if not name or not email or not password:
            return "All fields are required.", 400

        if len(password) < 8:
            return "Password must contain at least 8 characters.", 400

        password_hash = generate_password_hash(password)

        conn = get_db()

        try:

            conn.execute(
                """
                INSERT INTO users
                (name, email, password)
                VALUES (?, ?, ?)
                """,
                (name, email, password_hash)
            )

            conn.commit()

        except sqlite3.IntegrityError:

            conn.rollback()
            conn.close()

            return "An account with this email already exists.", 400

        conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


USER_LOGIN_ATTEMPTS = {}
USER_LOGIN_MAX_ATTEMPTS = 5
USER_LOGIN_BLOCK_SECONDS = 300


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            return render_template(
                "forgot_password.html",
                error="Please enter your email address."
            )

        conn = get_db()

        user = conn.execute(
            """
            SELECT id, email
            FROM users
            WHERE LOWER(email) = ?
            """,
            (email,)
        ).fetchone()

        if user:
            raw_token = generate_reset_token()
            token_hash = hash_reset_token(raw_token)

            expires_at = datetime.utcnow() + timedelta(minutes=30)

            conn.execute(
                """
                INSERT INTO password_reset_tokens
                (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)
                """,
                (user["id"], token_hash, expires_at.isoformat())
            )

            conn.commit()

            print(
                "PASSWORD RESET TOKEN:",
                raw_token
            )

        conn.close()

        return render_template(
            "forgot_password.html",
            message="If an account with that email exists, a password reset link has been generated."
        )

    return render_template("forgot_password.html")



@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hash_reset_token(token)

    conn = get_db()

    reset_token = conn.execute(
        """
        SELECT id, user_id, expires_at, used_at
        FROM password_reset_tokens
        WHERE token_hash = ?
        """,
        (token_hash,)
    ).fetchone()

    if not reset_token:
        conn.close()
        return render_template(
            "reset_password.html",
            error="Invalid or expired password reset link."
        )

    if reset_token["used_at"] is not None:
        conn.close()
        return render_template(
            "reset_password.html",
            error="This password reset link has already been used."
        )

    try:
        expires_at = datetime.fromisoformat(reset_token["expires_at"])
    except (TypeError, ValueError):
        conn.close()
        return render_template(
            "reset_password.html",
            error="Invalid password reset link."
        )

    if datetime.utcnow() > expires_at:
        conn.close()
        return render_template(
            "reset_password.html",
            error="This password reset link has expired."
        )

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            conn.close()
            return render_template(
                "reset_password.html",
                error="Password must be at least 8 characters long."
            )

        if password != confirm_password:
            conn.close()
            return render_template(
                "reset_password.html",
                error="Passwords do not match."
            )

        password_hash = generate_password_hash(password)

        conn.execute(
            """
            UPDATE users
            SET password = ?
            WHERE id = ?
            """,
            (password_hash, reset_token["user_id"])
        )

        conn.execute(
            """
            UPDATE password_reset_tokens
            SET used_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (reset_token["id"],)
        )

        conn.commit()
        conn.close()

        return redirect(url_for("login"))

    conn.close()

    return render_template("reset_password.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        now = datetime.now().timestamp()
        attempt = USER_LOGIN_ATTEMPTS.get(email)

        if attempt:
            failures, blocked_until = attempt

            if blocked_until and now < blocked_until:
                return "Too many failed login attempts. Please try again later.", 429

            if blocked_until and now >= blocked_until:
                USER_LOGIN_ATTEMPTS.pop(email, None)

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            USER_LOGIN_ATTEMPTS.pop(email, None)

            if user["status"] != "Active":
                return "Your account is currently suspended. Please contact support.", 403

            session.clear()
            session["user_id"] = user["id"]

            return redirect(url_for("dashboard"))

        failures, blocked_until = USER_LOGIN_ATTEMPTS.get(
            email, (0, None)
        )

        failures += 1

        if failures >= USER_LOGIN_MAX_ATTEMPTS:
            blocked_until = now + USER_LOGIN_BLOCK_SECONDS
        else:
            blocked_until = None

        USER_LOGIN_ATTEMPTS[email] = (failures, blocked_until)

        return "Invalid email or password.", 401

    return render_template("login.html")



@app.route("/forgot-credentials", methods=["GET", "POST"])
def forgot_credentials():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()

        if not email:
            return render_template(
                "forgot_credentials.html",
                message="If an account exists for that email, recovery instructions will be sent."
            )

        conn = get_db()

        user = conn.execute(
            "SELECT id FROM users WHERE email = ? AND status = 'Active'",
            (email,)
        ).fetchone()

        if user:

            token = generate_reset_token()
            token_hash = hash_reset_token(token)

            conn.execute(
                """
                UPDATE password_reset_tokens
                SET used_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
                  AND used_at IS NULL
                """,
                (user["id"],)
            )

            conn.execute(
                """
                INSERT INTO password_reset_tokens
                (user_id, token_hash, expires_at)
                VALUES (
                    ?,
                    ?,
                    datetime('now', '+30 minutes')
                )
                """,
                (user["id"], token_hash)
            )

            conn.commit()

        conn.close()

        return render_template(
            "forgot_credentials.html",
            message="If an account exists for that email, recovery instructions will be sent."
        )

    return render_template("forgot_credentials.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile")
def profile():
    if not current_user():
        return redirect(url_for("login"))

    user = current_user()

    return render_template(
        "profile.html",
        user=user
    )

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if not current_user():
        return redirect(url_for("login"))

    user = current_user()

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not check_password_hash(user["password"], current_password):
            return render_template(
                "change_password.html",
                message="Current password is incorrect."
            )

        if len(new_password) < 8:
            return render_template(
                "change_password.html",
                message="New password must contain at least 8 characters."
            )

        if new_password != confirm_password:
            return render_template(
                "change_password.html",
                message="New passwords do not match."
            )

        password_hash = generate_password_hash(new_password)

        conn = get_db()
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (password_hash, user["id"])
        )
        conn.commit()
        conn.close()

        session.pop("user_id", None)

        return redirect(url_for("login"))

    return render_template("change_password.html")


@app.route("/dashboard")
def dashboard():

    user = current_user()

    if not user:
        return redirect(url_for("login"))

    conn = get_db()

    total_deposits = conn.execute(
        """
        SELECT COALESCE(SUM(amount), 0)
        FROM deposits
        WHERE user_id = ?
        AND status = 'Approved'
        """,
        (user["id"],)
    ).fetchone()[0]

    pending_deposits = conn.execute(
        """
        SELECT COALESCE(SUM(amount), 0)
        FROM deposits
        WHERE user_id = ?
        AND status = 'Pending'
        """,
        (user["id"],)
    ).fetchone()[0]

    total_withdrawals = conn.execute(
        """
        SELECT COALESCE(SUM(amount), 0)
        FROM withdrawals
        WHERE user_id = ?
        AND status = 'Approved'
        """,
        (user["id"],)
    ).fetchone()[0]

    active_investment_total = conn.execute(
        """
        SELECT COALESCE(SUM(amount), 0)
        FROM investments
        WHERE user_id = ?
        AND status = 'ACTIVE'
        """,
        (user["id"],)
    ).fetchone()[0]

    expected_investment_profit = conn.execute(
        """
        SELECT COALESCE(
            SUM(
                investments.amount * investment_plans.return_percent / 100
            ),
            0
        )
        FROM investments
        JOIN investment_plans
            ON investment_plans.id = investments.plan_id
        WHERE investments.user_id = ?
        AND investments.status = 'ACTIVE'
        """,
        (user["id"],)
    ).fetchone()[0]

    active_investment_count = conn.execute(
        """
        SELECT COUNT(*)
        FROM investments
        WHERE user_id = ?
        AND status = 'ACTIVE'
        """,
        (user["id"],)
    ).fetchone()[0]

    next_maturity = conn.execute(
        """
        SELECT MIN(maturity_at)
        FROM investments
        WHERE user_id = ?
        AND status = 'ACTIVE'
        """,
        (user["id"],)
    ).fetchone()[0]

    if next_maturity:
        try:
            from datetime import datetime
            next_maturity = datetime.fromisoformat(next_maturity).strftime("%d %B %Y, %I:%M %p")
        except (TypeError, ValueError):
            pass

    unread_notifications = conn.execute(
        """
        SELECT COUNT(*)
        FROM notifications
        WHERE user_id = ?
        AND is_read = 0
        """,
        (user["id"],)
    ).fetchone()[0]

    conn.close()

    return render_template(
        "dashboard.html",
        user=user,
        total_deposits=total_deposits,
        pending_deposits=pending_deposits,
        total_withdrawals=total_withdrawals,
        active_investment_total=active_investment_total,
        active_investment_count=active_investment_count,
        expected_investment_profit=expected_investment_profit,
        next_maturity=next_maturity,
        unread_notifications=unread_notifications
    )


@app.route("/deposit", methods=["GET", "POST"])
def deposit():

    user = current_user()

    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":

        try:
            amount = float(request.form["amount"])
        except (ValueError, TypeError):
            return "Please enter a valid amount.", 400

        reference = request.form.get(
            "reference",
            ""
        ).strip()

        if amount <= 0:
            return "Amount must be greater than zero.", 400

        if amount > 100000000:
            return "Amount exceeds the allowed test limit.", 400

        conn = get_db()

        try:

            cursor = conn.execute(
                """
                INSERT INTO deposits
                (user_id, amount, status, reference)
                VALUES (?, ?, 'Pending', ?)
                """,
                (
                    user["id"],
                    amount,
                    reference
                )
            )

            deposit_id = cursor.lastrowid

            conn.execute(
                """
                INSERT INTO transactions
                (user_id, transaction_type, amount,
                 status, description)
                VALUES (?, 'Deposit', ?, 'Pending', ?)
                """,
                (
                    user["id"],
                    amount,
                    f"Deposit request #{deposit_id}"
                )
            )

            audit_log(conn, 
                "user",
                user["id"],
                "deposit_requested",
                "deposit",
                deposit_id,
                f"Deposit request for {amount:.2f}"
            )

            conn.commit()

        except Exception:

            conn.rollback()
            conn.close()

            return "Unable to create deposit request.", 500

        conn.close()

        return redirect(url_for("history"))

    return render_template("deposit.html")


@app.route("/withdraw", methods=["GET", "POST"])
def withdraw():

    user = current_user()

    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":

        try:
            amount = float(request.form["amount"])
        except (ValueError, TypeError):
            return "Please enter a valid amount.", 400

        method = request.form.get(
            "method",
            ""
        ).strip()

        account_details = request.form.get(
            "account_details",
            ""
        ).strip()

        if amount <= 0:
            return "Amount must be greater than zero.", 400

        if not method or not account_details:
            return "Please provide withdrawal details.", 400

        conn = get_db()

        try:

            # Lock the database while checking the balance
            conn.execute("BEGIN IMMEDIATE")

            fresh_user = conn.execute(
                """
                SELECT balance
                FROM users
                WHERE id = ?
                """,
                (user["id"],)
            ).fetchone()

            if not fresh_user:
                conn.rollback()
                conn.close()
                return "User account not found.", 404

            if amount > fresh_user["balance"]:
                conn.rollback()
                conn.close()
                return "Insufficient available balance.", 400

            cursor = conn.execute(
                """
                INSERT INTO withdrawals
                (user_id, amount, method,
                 account_details, status)
                VALUES (?, ?, ?, ?, 'Pending')
                """,
                (
                    user["id"],
                    amount,
                    method,
                    account_details
                )
            )

            withdrawal_id = cursor.lastrowid

            conn.execute(
                """
                INSERT INTO transactions
                (user_id, transaction_type,
                 amount, status, description)
                VALUES (?, 'Withdrawal', ?, 'Pending', ?)
                """,
                (
                    user["id"],
                    amount,
                    f"Withdrawal request #{withdrawal_id}"
                )
            )

            audit_log(
                conn,
                "user",
                user["id"],
                "withdrawal_requested",
                "withdrawal",
                withdrawal_id,
                f"Withdrawal request for {amount:.2f}"
            )

            conn.commit()

        except Exception:

            conn.rollback()
            conn.close()

            return "Unable to create withdrawal request.", 500

        conn.close()

        return redirect(url_for("history"))

    return render_template("withdraw.html")


@app.route("/history")
def history():

    user = current_user()

    if not user:
        return redirect(url_for("login"))

    conn = get_db()

    transactions = conn.execute(
        """
        SELECT *
        FROM transactions
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (user["id"],)
    ).fetchall()

    conn.close()

    return render_template(
        "history.html",
        transactions=transactions
    )




@app.route("/notifications")
def notifications():
    user = current_user()

    if not user:
        return redirect(url_for("login"))

    db = get_db()

    notifications = db.execute(
        """
        SELECT *
        FROM notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (user["id"],)
    ).fetchall()

    db.close()

    return render_template(
        "notifications.html",
        notifications=notifications
    )


@app.route("/notifications/<int:notification_id>/read", methods=["POST"])
def mark_notification_read(notification_id):
    user = current_user()

    if not user:
        return redirect(url_for("login"))

    db = get_db()

    db.execute(
        """
        UPDATE notifications
        SET is_read = 1
        WHERE id = ?
          AND user_id = ?
        """,
        (notification_id, user["id"])
    )

    db.commit()
    db.close()

    return redirect(url_for("notifications"))


@app.route("/investments")
def investments():
    if not current_user():
        return redirect(url_for("login"))

    user = current_user()

    db = get_db()

    plans = db.execute("""
        SELECT id, name, description, minimum_amount,
               term_days, management_fee_percent, return_percent
        FROM investment_plans
        WHERE active = 1
        ORDER BY id
    """).fetchall()

    active_investments = db.execute("""
        SELECT investments.id,
               investment_plans.name,
               investments.amount,
               investments.status,
               investments.started_at,
               investment_plans.return_percent,
               investments.maturity_at
        FROM investments
        JOIN investment_plans
          ON investment_plans.id = investments.plan_id
        WHERE investments.user_id = ?
        ORDER BY investments.id DESC
    """, (user["id"],)).fetchall()

    investment_request_token = secrets.token_urlsafe(32)

    return render_template(
        "investments.html",
        user=user,
        plans=plans,
        active_investments=active_investments,
        investment_request_token=investment_request_token
    )


@app.route("/invest/<int:plan_id>", methods=["POST"])
def create_investment(plan_id):
    if not current_user():
        return redirect(url_for("login"))

    user = current_user()

    request_token = request.form.get("request_token", "").strip()

    if not request_token or len(request_token) < 20:
        flash("Invalid investment request. Please reload the investments page and try again.", "error")
        return redirect(url_for("investments"))

    amount_raw = request.form.get("amount", "").strip()

    try:
        amount = float(amount_raw)
    except (TypeError, ValueError):
        flash("Enter a valid investment amount.", "error")
        return redirect(url_for("investments"))

    if amount <= 0:
        flash("Investment amount must be greater than zero.", "error")
        return redirect(url_for("investments"))

    db = get_db()

    plan = db.execute("""
        SELECT id, name, minimum_amount, term_days
        FROM investment_plans
        WHERE id = ? AND active = 1
    """, (plan_id,)).fetchone()

    if not plan:
        flash("Investment plan not found.", "error")
        return redirect(url_for("investments"))

    if amount < plan["minimum_amount"]:
        flash(
            f"Minimum investment for {plan['name']} is "
            f"₦{plan['minimum_amount']:,.2f}.",
            "error"
        )
        return redirect(url_for("investments"))

    try:
        db.execute("BEGIN IMMEDIATE")

        existing_request = db.execute("""
            SELECT investment_id
            FROM investment_requests
            WHERE request_token = ?
        """, (request_token,)).fetchone()

        if existing_request:
            db.rollback()
            flash("This investment request has already been processed.", "error")
            return redirect(url_for("investments"))

        db.execute("""
            INSERT INTO investment_requests
            (user_id, request_token)
            VALUES (?, ?)
        """, (user["id"], request_token))

        account = db.execute("""
            SELECT balance
            FROM users
            WHERE id = ?
        """, (user["id"],)).fetchone()

        if not account:
            db.rollback()
            flash("User account not found.", "error")
            return redirect(url_for("investments"))

        balance = float(account["balance"])

        if amount > balance:
            db.rollback()
            flash(
                f"Insufficient available balance. "
                f"Available: ₦{balance:,.2f}.",
                "error"
            )
            return redirect(url_for("investments"))

        from datetime import datetime, timedelta, timezone

        started = datetime.now(timezone.utc).replace(tzinfo=None)
        maturity = started + timedelta(days=plan["term_days"])

        db.execute("""
            UPDATE users
            SET balance = balance - ?
            WHERE id = ?
        """, (amount, user["id"]))

        cursor = db.execute("""
            INSERT INTO investments
            (user_id, plan_id, amount, status,
             started_at, maturity_at)
            VALUES (?, ?, ?, 'ACTIVE', ?, ?)
        """, (
            user["id"],
            plan["id"],
            amount,
            started.isoformat(),
            maturity.isoformat()
        ))

        investment_id = cursor.lastrowid

        db.execute("""
            UPDATE investment_requests
            SET investment_id = ?
            WHERE request_token = ?
        """, (investment_id, request_token))

        audit_log(
            db,
            "user",
            user["id"],
            "investment_created",
            "investment",
            investment_id,
            f"Investment #{investment_id} created for {amount:.2f} in {plan['name']}"
        )

        db.execute("""
            INSERT INTO transactions
            (user_id, transaction_type, amount, status, description)
            VALUES (?, 'investment', ?, 'Completed', ?)
        """, (
            user["id"],
            amount,
            f"Investment #{investment_id} - {plan['name']}"
        ))

        create_notification(
            db,
            user["id"],
            "Investment Created",
            f"Your ₦{amount:,.2f} {plan['name']} investment "
            f"has been created successfully. "
            f"It will mature on {maturity.strftime('%Y-%m-%d')}."
        )

        reconciliation = calculate_reconciliation(db)
        if not reconciliation["ok"]:
            db.rollback()
            flash("Investment creation blocked by accounting reconciliation check. No changes were made.", "error")
            return redirect(url_for("investments"))

        db.commit()

    except Exception:
        db.rollback()
        flash("Investment could not be created. No funds were deducted.", "error")
        return redirect(url_for("investments"))

    flash(
        f"Investment #{investment_id} created successfully.",
        "success"
    )

    return redirect(url_for("investments"))


@app.route("/investment/<int:investment_id>")
def investment_detail(investment_id):
    if not current_user():
        return redirect(url_for("login"))

    user = current_user()

    db = get_db()

    investment = db.execute("""
        SELECT investments.id,
               investments.amount,
               investments.status,
               investments.started_at,
               investments.maturity_at,
               investments.completed_at,
               investment_plans.name,
               investment_plans.description,
               investment_plans.term_days,
               investment_plans.management_fee_percent,
               investment_plans.return_percent
        FROM investments
        JOIN investment_plans
          ON investment_plans.id = investments.plan_id
        WHERE investments.id = ?
          AND investments.user_id = ?
    """, (investment_id, user["id"])).fetchone()

    if not investment:
        flash("Investment not found.", "error")
        return redirect(url_for("investments"))

    from datetime import datetime, timezone

    maturity = datetime.fromisoformat(investment["maturity_at"])

    if maturity.tzinfo is None:
        maturity = maturity.replace(tzinfo=timezone.utc)

    is_matured = datetime.now(timezone.utc) >= maturity

    return render_template(
        "investment_detail.html",
        user=user,
        investment=investment,
        is_matured=is_matured
    )


ADMIN_LOGIN_ATTEMPTS = {}
ADMIN_LOGIN_MAX_ATTEMPTS = 5
ADMIN_LOGIN_BLOCK_SECONDS = 300

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        now = datetime.now().timestamp()
        attempt = ADMIN_LOGIN_ATTEMPTS.get(email)

        if attempt:
            failures, blocked_until = attempt

            if blocked_until and now < blocked_until:
                return "Too many failed login attempts. Please try again later.", 429

            if blocked_until and now >= blocked_until:
                ADMIN_LOGIN_ATTEMPTS.pop(email, None)

        if (
            hmac.compare_digest(email, ADMIN_EMAIL.lower())
            and check_password_hash(ADMIN_PASSWORD, password)
        ):

            ADMIN_LOGIN_ATTEMPTS.pop(email, None)

            session.clear()
            session["admin"] = True

            return redirect(url_for("admin_dashboard"))

        failures, blocked_until = ADMIN_LOGIN_ATTEMPTS.get(
            email, (0, None)
        )

        failures += 1

        if failures >= ADMIN_LOGIN_MAX_ATTEMPTS:
            blocked_until = now + ADMIN_LOGIN_BLOCK_SECONDS
        else:
            blocked_until = None

        ADMIN_LOGIN_ATTEMPTS[email] = (failures, blocked_until)

        return "Invalid administrator credentials.", 401

    return render_template("admin_login.html")


def calculate_reconciliation(conn):
    """
    Calculate the current accounting reconciliation from the database.
    Returns a dictionary suitable for both admin checks and audit logging.
    """
    approved_deposits = float(conn.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM deposits
        WHERE status = 'Approved'
    """).fetchone()[0])

    approved_withdrawals = float(conn.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM withdrawals
        WHERE status = 'Approved'
    """).fetchone()[0])

    balance_adjustments = float(conn.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM balance_adjustments
    """).fetchone()[0])

    user_balances = float(conn.execute("""
        SELECT COALESCE(SUM(balance), 0)
        FROM users
    """).fetchone()[0])

    active_investments = float(conn.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM investments
        WHERE status = 'ACTIVE'
    """).fetchone()[0])

    investment_returns = float(conn.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM transactions
        WHERE transaction_type = 'investment_return'
          AND status = 'Completed'
    """).fetchone()[0])

    task_rewards = float(conn.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM transactions
        WHERE transaction_type = 'Task Reward'
          AND status = 'Approved'
    """).fetchone()[0])

    expected = (
        approved_deposits
        - approved_withdrawals
        + balance_adjustments
        + investment_returns
        + task_rewards
    )

    actual = user_balances + active_investments
    difference = actual - expected

    return {
        "approved_deposits": approved_deposits,
        "approved_withdrawals": approved_withdrawals,
        "balance_adjustments": balance_adjustments,
        "user_balances": user_balances,
        "active_investments": active_investments,
        "investment_returns": investment_returns,
        "task_rewards": task_rewards,
        "expected": expected,
        "actual": actual,
        "difference": difference,
        "ok": abs(difference) < 0.01,
    }


@app.route("/admin/reconciliation")
@admin_required
def admin_reconciliation():
    conn = get_db()

    summary = {
        "user_balances": conn.execute(
            "SELECT COALESCE(SUM(balance), 0) FROM users"
        ).fetchone()[0],

        "active_investments": conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM investments WHERE status = 'ACTIVE'"
        ).fetchone()[0],

        "cancelled_investments": conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM investments WHERE status = 'CANCELLED'"
        ).fetchone()[0],

        "completed_investments": conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM investments WHERE status = 'COMPLETED'"
        ).fetchone()[0],

        "approved_deposits": conn.execute(
            """
            SELECT COALESCE(SUM(amount), 0)
            FROM deposits
            WHERE status = 'Approved'
            """
        ).fetchone()[0],

        "approved_withdrawals": conn.execute(
            """
            SELECT COALESCE(SUM(amount), 0)
            FROM withdrawals
            WHERE status = 'Approved'
            """
        ).fetchone()[0],

        "balance_adjustments": conn.execute(
            """
            SELECT COALESCE(SUM(amount), 0)
            FROM balance_adjustments
            """
        ).fetchone()[0],
    }

    balance_adjustments = conn.execute(
        """
        SELECT COALESCE(SUM(amount), 0)
        FROM balance_adjustments
        """
    ).fetchone()[0]

    reconciliation_expected = (
        float(summary["approved_deposits"])
        - float(summary["approved_withdrawals"])
        + float(balance_adjustments)
    )

    reconciliation_actual = (
        float(summary["user_balances"])
        + float(summary["active_investments"])
    )

    reconciliation_difference = (
        reconciliation_actual - reconciliation_expected
    )

    reconciliation_ok = abs(reconciliation_difference) < 0.01

    recent_transactions = conn.execute(
        """
        SELECT
            transactions.id,
            transactions.transaction_type,
            transactions.amount,
            transactions.status,
            transactions.description,
            transactions.created_at,
            users.email
        FROM transactions
        JOIN users ON users.id = transactions.user_id
        ORDER BY transactions.id DESC
        LIMIT 25
        """
    ).fetchall()

    conn.close()

    return render_template(
        "admin_reconciliation.html",
        summary=summary,
        recent_transactions=recent_transactions,
        reconciliation_expected=reconciliation_expected,
        reconciliation_actual=reconciliation_actual,
        reconciliation_difference=reconciliation_difference,
        reconciliation_ok=reconciliation_ok
    )

@app.route("/admin/balance-adjustments", methods=["GET", "POST"])
@admin_required
def admin_balance_adjustments():
    db = get_db()

    if request.method == "POST":
        user_id = request.form.get("user_id", type=int)
        amount = request.form.get("amount", type=float)
        adjustment_action = request.form.get("adjustment_action", "").strip().upper()
        reason = request.form.get("reason", "").strip()
        admin_password = request.form.get("admin_password", "")

        if (
            not user_id
            or amount is None
            or amount <= 0
            or adjustment_action not in ("CREDIT", "DEBIT")
            or not reason
            or not admin_password
        ):
            flash(
                "User, valid Credit/Debit type, positive amount, and reason are required.",
                "error"
            )
            return redirect(url_for("admin_balance_adjustments"))

        if not check_password_hash(ADMIN_PASSWORD, admin_password):
            flash(
                "Admin password verification failed. No changes were made.",
                "error"
            )
            return redirect(url_for("admin_balance_adjustments"))

        try:
            db.execute("BEGIN IMMEDIATE")

            user = db.execute(
                """
                SELECT id, name, email, balance
                FROM users
                WHERE id = ?
                """,
                (user_id,)
            ).fetchone()

            if not user:
                db.rollback()
                flash("User not found. No changes were made.", "error")
                return redirect(url_for("admin_balance_adjustments"))

            current_balance = float(user["balance"])

            if adjustment_action == "DEBIT" and current_balance < amount:
                db.rollback()
                flash(
                    f"Insufficient balance. Current balance is ₦{current_balance:,.2f}.",
                    "error"
                )
                return redirect(url_for("admin_balance_adjustments"))

            signed_amount = amount if adjustment_action == "CREDIT" else -amount

            cursor = db.execute(
                """
                INSERT INTO balance_adjustments
                (user_id, amount, adjustment_type, reason)
                VALUES (?, ?, 'ADMIN_ADJUSTMENT', ?)
                """,
                (user_id, signed_amount, reason)
            )

            adjustment_id = cursor.lastrowid

            db.execute(
                """
                UPDATE users
                SET balance = balance + ?
                WHERE id = ?
                """,
                (signed_amount, user_id)
            )

            transaction_type = (
                "balance_adjustment_credit"
                if adjustment_action == "CREDIT"
                else "balance_adjustment_debit"
            )

            db.execute(
                """
                INSERT INTO transactions
                (user_id, transaction_type, amount, status, description)
                VALUES (?, ?, ?, 'Completed', ?)
                """,
                (
                    user_id,
                    transaction_type,
                    amount,
                    f"Admin {adjustment_action.lower()} adjustment #{adjustment_id}"
                )
            )

            audit_log(
                db,
                "admin",
                None,
                "balance_adjustment_created",
                "balance_adjustment",
                adjustment_id,
                (
                    f"{adjustment_action} of {amount:.2f} for user {user_id}. "
                    f"Reason: {reason}"
                )
            )

            reconciliation = calculate_reconciliation(db)

            if not reconciliation["ok"]:
                db.rollback()
                flash(
                    "Balance adjustment blocked because it would create an accounting mismatch. No changes were made.",
                    "error"
                )
                return redirect(url_for("admin_balance_adjustments"))

            db.commit()

            new_balance = current_balance + signed_amount

            flash(
                f"{adjustment_action.title()} of ₦{amount:,.2f} applied to "
                f"{user['name']}. New balance: ₦{new_balance:,.2f}.",
                "success"
            )

        except Exception:
            db.rollback()
            flash(
                "Balance adjustment failed. No changes were made.",
                "error"
            )

        return redirect(url_for("admin_balance_adjustments"))

    users = db.execute(
        """
        SELECT id, name, email, balance
        FROM users
        ORDER BY id
        """
    ).fetchall()

    adjustments = db.execute(
        """
        SELECT
            balance_adjustments.*,
            users.name,
            users.email
        FROM balance_adjustments
        JOIN users ON users.id = balance_adjustments.user_id
        ORDER BY balance_adjustments.id DESC
        """
    ).fetchall()

    db.close()

    return render_template(
        "admin_balance_adjustments.html",
        users=users,
        adjustments=adjustments
    )


@app.route("/admin")
@admin_required
def admin_dashboard():

    conn = get_db()

    pending_deposits = conn.execute(
        """
        SELECT deposits.*, users.name, users.email
        FROM deposits
        JOIN users ON users.id = deposits.user_id
        WHERE deposits.status = 'Pending'
        ORDER BY deposits.created_at DESC
        """
    ).fetchall()

    pending_withdrawals = conn.execute(
        """
        SELECT withdrawals.*, users.name, users.email
        FROM withdrawals
        JOIN users ON users.id = withdrawals.user_id
        WHERE withdrawals.status = 'Pending'
        ORDER BY withdrawals.created_at DESC
        """
    ).fetchall()

    users = conn.execute(
        """
        SELECT
            users.id,
            users.name,
            users.email,
            users.balance,
            users.created_at,
            users.status,
            COALESCE(
                (
                    SELECT SUM(investments.amount)
                    FROM investments
                    WHERE investments.user_id = users.id
                    AND investments.status = 'ACTIVE'
                ),
                0
            ) AS active_investment_total
        FROM users
        ORDER BY users.created_at DESC
        """
    ).fetchall()

    financial_report = calculate_reconciliation(conn)

    financial_report["active_investment_count"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM investments
        WHERE status = 'ACTIVE'
        """
    ).fetchone()[0]

    financial_report["pending_deposit_count"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM deposits
        WHERE status = 'Pending'
        """
    ).fetchone()[0]

    financial_report["pending_deposit_total"] = conn.execute(
        """
        SELECT COALESCE(SUM(amount), 0)
        FROM deposits
        WHERE status = 'Pending'
        """
    ).fetchone()[0]

    financial_report["pending_withdrawal_count"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM withdrawals
        WHERE status = 'Pending'
        """
    ).fetchone()[0]

    financial_report["pending_withdrawal_total"] = conn.execute(
        """
        SELECT COALESCE(SUM(amount), 0)
        FROM withdrawals
        WHERE status = 'Pending'
        """
    ).fetchone()[0]

    financial_report["total_users"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM users
        """
    ).fetchone()[0]

    financial_report["active_users"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM users
        WHERE status = 'Active'
        """
    ).fetchone()[0]

    financial_report["total_task_rewards"] = conn.execute(
        """
        SELECT COALESCE(SUM(reward), 0)
        FROM daily_task_completions
        """
    ).fetchone()[0]

    financial_report["task_completion_count"] = conn.execute(
        """
        SELECT COUNT(*)
        FROM daily_task_completions
        """
    ).fetchone()[0]

    recent_activity = conn.execute(
        """
        SELECT
            transactions.created_at,
            transactions.transaction_type,
            transactions.amount,
            transactions.status,
            transactions.description,
            users.name
        FROM transactions
        LEFT JOIN users ON users.id = transactions.user_id
        ORDER BY transactions.created_at DESC
        LIMIT 10
        """
    ).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        pending_deposits=pending_deposits,
        pending_withdrawals=pending_withdrawals,
        users=users,
        financial_report=financial_report,
        recent_activity=recent_activity
    )


@app.route(
    "/admin/deposit/<int:deposit_id>/approve",
    methods=["POST"]
)
@admin_required
def approve_deposit(deposit_id):

    conn = get_db()

    try:

        conn.execute("BEGIN IMMEDIATE")

        deposit = conn.execute(
            """
            SELECT *
            FROM deposits
            WHERE id = ?
            """,
            (deposit_id,)
        ).fetchone()

        if not deposit:
            conn.rollback()
            return "Deposit not found.", 404

        if deposit["status"] != "Pending":
            conn.rollback()
            return "This deposit has already been processed.", 400

        conn.execute(
            """
            UPDATE deposits
            SET status = 'Approved'
            WHERE id = ?
            """,
            (deposit_id,)
        )

        conn.execute(
            """
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
            """,
            (
                deposit["amount"],
                deposit["user_id"]
            )
        )

        conn.execute(
            """
            UPDATE transactions
            SET status = 'Approved'
            WHERE user_id = ?
            AND transaction_type = 'Deposit'
            AND description = ?
            AND status = 'Pending'
            """,
            (
                deposit["user_id"],
                f"Deposit request #{deposit_id}"
            )
        )

        audit_log(conn, 
            "admin",
            None,
            "deposit_approved",
            "deposit",
            deposit_id,
            f"Approved deposit of {deposit['amount']:.2f} for user {deposit['user_id']}"
        )

        reconciliation = calculate_reconciliation(conn)

        if not reconciliation["ok"]:
            conn.rollback()
            return "Deposit approval blocked by accounting reconciliation check.", 409

        create_notification(
            conn,
            deposit["user_id"],
            "Deposit Approved",
            f"Your ₦{deposit['amount']:,.2f} deposit has been approved "
            f"and added to your account balance."
        )

        conn.commit()

    except Exception:

        conn.rollback()
        conn.close()

        return "Unable to approve deposit.", 500

    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route(
    "/admin/deposit/<int:deposit_id>/reject",
    methods=["POST"]
)
@admin_required
def reject_deposit(deposit_id):

    conn = get_db()

    try:

        conn.execute("BEGIN IMMEDIATE")

        deposit = conn.execute(
            """
            SELECT *
            FROM deposits
            WHERE id = ?
            """,
            (deposit_id,)
        ).fetchone()

        if not deposit:
            conn.rollback()
            return "Deposit not found.", 404

        if deposit["status"] != "Pending":
            conn.rollback()
            return "This deposit has already been processed.", 400

        conn.execute(
            """
            UPDATE deposits
            SET status = 'Rejected'
            WHERE id = ?
            """,
            (deposit_id,)
        )

        conn.execute(
            """
            UPDATE transactions
            SET status = 'Rejected'
            WHERE user_id = ?
            AND transaction_type = 'Deposit'
            AND description = ?
            AND status = 'Pending'
            """,
            (
                deposit["user_id"],
                f"Deposit request #{deposit_id}"
            )
        )

        audit_log(
            conn,
            "admin",
            None,
            "deposit_rejected",
            "deposit",
            deposit_id,
            f"Rejected deposit of {deposit['amount']:.2f} for user {deposit['user_id']}"
        )

        create_notification(
            conn,
            deposit["user_id"],
            "Deposit Rejected",
            f"Your ₦{deposit['amount']:,.2f} deposit request was rejected."
        )

        conn.commit()

    except Exception:

        conn.rollback()
        conn.close()

        return "Unable to reject deposit.", 500

    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route(
    "/admin/withdrawal/<int:withdrawal_id>/approve",
    methods=["POST"]
)
@admin_required
def approve_withdrawal(withdrawal_id):

    conn = get_db()

    try:

        conn.execute("BEGIN IMMEDIATE")

        withdrawal = conn.execute(
            """
            SELECT *
            FROM withdrawals
            WHERE id = ?
            """,
            (withdrawal_id,)
        ).fetchone()

        if not withdrawal:
            conn.rollback()
            return "Withdrawal not found.", 404

        if withdrawal["status"] != "Pending":
            conn.rollback()
            return "This withdrawal has already been processed.", 400

        user = conn.execute(
            """
            SELECT balance
            FROM users
            WHERE id = ?
            """,
            (withdrawal["user_id"],)
        ).fetchone()

        if not user:
            conn.rollback()
            return "User not found.", 404

        if user["balance"] < withdrawal["amount"]:
            conn.rollback()
            return "Insufficient balance.", 400

        conn.execute(
            """
            UPDATE withdrawals
            SET status = 'Approved'
            WHERE id = ?
            """,
            (withdrawal_id,)
        )

        conn.execute(
            """
            UPDATE users
            SET balance = balance - ?
            WHERE id = ?
            """,
            (
                withdrawal["amount"],
                withdrawal["user_id"]
            )
        )

        conn.execute(
            """
            UPDATE transactions
            SET status = 'Approved'
            WHERE user_id = ?
            AND transaction_type = 'Withdrawal'
            AND description = ?
            AND status = 'Pending'
            """,
            (
                withdrawal["user_id"],
                f"Withdrawal request #{withdrawal_id}"
            )
        )

        audit_log(
            conn,
            "admin",
            None,
            "withdrawal_approved",
            "withdrawal",
            withdrawal_id,
            f"Approved withdrawal of {withdrawal['amount']:.2f} for user {withdrawal['user_id']}"
        )

        create_notification(
            conn,
            withdrawal["user_id"],
            "Withdrawal Approved",
            f"Your ₦{withdrawal['amount']:,.2f} withdrawal request has been approved."
        )

        reconciliation = calculate_reconciliation(conn)

        if not reconciliation["ok"]:
            conn.rollback()
            return "Withdrawal approval blocked by accounting reconciliation check.", 409

        conn.commit()

    except Exception:

        conn.rollback()
        conn.close()

        return "Unable to approve withdrawal.", 500

    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route(
    "/admin/withdrawal/<int:withdrawal_id>/reject",
    methods=["POST"]
)
@admin_required
def reject_withdrawal(withdrawal_id):

    conn = get_db()

    try:

        conn.execute("BEGIN IMMEDIATE")

        withdrawal = conn.execute(
            """
            SELECT *
            FROM withdrawals
            WHERE id = ?
            """,
            (withdrawal_id,)
        ).fetchone()

        if not withdrawal:
            conn.rollback()
            return "Withdrawal not found.", 404

        if withdrawal["status"] != "Pending":
            conn.rollback()
            return "This withdrawal has already been processed.", 400

        conn.execute(
            """
            UPDATE withdrawals
            SET status = 'Rejected'
            WHERE id = ?
            """,
            (withdrawal_id,)
        )

        conn.execute(
            """
            UPDATE transactions
            SET status = 'Rejected'
            WHERE user_id = ?
            AND transaction_type = 'Withdrawal'
            AND description = ?
            AND status = 'Pending'
            """,
            (
                withdrawal["user_id"],
                f"Withdrawal request #{withdrawal_id}"
            )
        )

        audit_log(
            conn,
            "admin",
            None,
            "withdrawal_rejected",
            "withdrawal",
            withdrawal_id,
            f"Rejected withdrawal of {withdrawal['amount']:.2f} for user {withdrawal['user_id']}"
        )

        create_notification(
            conn,
            withdrawal["user_id"],
            "Withdrawal Rejected",
            f"Your ₦{withdrawal['amount']:,.2f} withdrawal request has been rejected."
        )

        conn.commit()

    except Exception:

        conn.rollback()
        conn.close()

        return "Unable to reject withdrawal.", 500

    conn.close()

    return redirect(url_for("admin_dashboard"))





def process_matured_investments(db):
    """
    Settle all ACTIVE investments that have reached maturity.
    Returns a list of successfully settled investment IDs.
    """

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)

    matured = db.execute("""
        SELECT investments.id,
               investments.user_id,
               investments.amount,
               investments.maturity_at,
               investment_plans.return_percent
        FROM investments
        JOIN investment_plans
          ON investment_plans.id = investments.plan_id
        WHERE investments.status = 'ACTIVE'
    """).fetchall()

    settled_ids = []

    for investment in matured:
        maturity = datetime.fromisoformat(investment["maturity_at"])

        if maturity.tzinfo is None:
            maturity = maturity.replace(tzinfo=timezone.utc)

        if now < maturity:
            continue

        amount = float(investment["amount"])
        return_percent = float(investment["return_percent"] or 0)
        profit = round(amount * return_percent / 100, 2)
        total_payout = round(amount + profit, 2)

        db.execute("""
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
        """, (
            total_payout,
            investment["user_id"]
        ))

        db.execute("""
            UPDATE investments
            SET status = 'COMPLETED',
                completed_at = ?
            WHERE id = ?
              AND status = 'ACTIVE'
        """, (
            now.isoformat(),
            investment["id"]
        ))

        db.execute("""
            INSERT INTO transactions
            (user_id, transaction_type, amount, status, description)
            VALUES (?, 'investment_settlement', ?, 'Completed', ?)
        """, (
            investment["user_id"],
            amount,
            f"Investment #{investment['id']} principal settlement"
        ))

        if profit > 0:
            db.execute("""
                INSERT INTO transactions
                (user_id, transaction_type, amount, status, description)
                VALUES (?, 'investment_return', ?, 'Completed', ?)
            """, (
                investment["user_id"],
                profit,
                f"Investment #{investment['id']} return at {return_percent:.2f}%"
            ))

        audit_log(
            db,
            "system",
            None,
            "investment_auto_settled",
            "investment",
            investment["id"],
            f"Automatic maturity settlement. Principal: {amount:.2f}, "
            f"Return: {profit:.2f}, Total: {total_payout:.2f}"
        )

        create_notification(
            db,
            investment["user_id"],
            "Investment Matured",
            f"Your investment #{investment['id']} has matured. "
            f"₦{total_payout:,.2f} has been added to your balance."
        )

        settled_ids.append(investment["id"])

    return settled_ids


@app.route("/investment/<int:investment_id>/settle", methods=["POST"])
def settle_investment(investment_id):
    if not current_user():
        return redirect(url_for("login"))

    user = current_user()
    db = get_db()

    try:
        db.execute("BEGIN IMMEDIATE")

        investment = db.execute("""
            SELECT investments.id,
                   investments.amount,
                   investments.status,
                   investments.maturity_at,
                   investment_plans.name AS plan_name,
                   investment_plans.return_percent
            FROM investments
            JOIN investment_plans
              ON investment_plans.id = investments.plan_id
            WHERE investments.id = ? AND investments.user_id = ?
        """, (investment_id, user["id"])).fetchone()

        if not investment:
            db.rollback()
            flash("Investment not found.", "error")
            return redirect(url_for("investments"))

        if investment["status"] != "ACTIVE":
            db.rollback()
            flash("This investment has already been settled or is not active.", "error")
            return redirect(url_for("investment_detail",
                                    investment_id=investment_id))

        from datetime import datetime, timezone

        maturity = datetime.fromisoformat(investment["maturity_at"])

        if maturity.tzinfo is None:
            maturity = maturity.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        if now < maturity:
            db.rollback()
            flash(
                f"This investment has not reached maturity yet. "
                f"Maturity date: {investment['maturity_at']}",
                "error"
            )
            return redirect(url_for("investment_detail",
                                    investment_id=investment_id))

        amount = float(investment["amount"])
        return_percent = float(investment["return_percent"] or 0)
        profit = round(amount * return_percent / 100, 2)
        total_payout = round(amount + profit, 2)

        db.execute("""
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
        """, (total_payout, user["id"]))

        db.execute("""
            UPDATE investments
            SET status = 'COMPLETED',
                completed_at = ?
            WHERE id = ?
              AND status = 'ACTIVE'
        """, (now.isoformat(), investment_id))

        db.execute("""
            INSERT INTO transactions
            (user_id, transaction_type, amount, status, description)
            VALUES (?, 'investment_settlement', ?, 'Completed', ?)
        """, (
            user["id"],
            amount,
            f"Investment #{investment_id} principal settlement"
        ))

        if profit > 0:
            db.execute("""
                INSERT INTO transactions
                (user_id, transaction_type, amount, status, description)
                VALUES (?, 'investment_return', ?, 'Completed', ?)
            """, (
                user["id"],
                profit,
                f"Investment #{investment_id} return at {return_percent:.2f}%"
            ))

        audit_log(
            db,
            "user",
            user["id"],
            "investment_settled",
            "investment",
            investment_id,
            f"Investment #{investment_id} principal settlement of {amount:.2f}"
        )

        create_notification(
            db,
            user["id"],
            "Investment Matured",
            f"Your investment #{investment_id} has matured. "
            f"₦{total_payout:,.2f} has been added to your balance."
        )

        reconciliation = calculate_reconciliation(db)

        if not reconciliation["ok"]:
            db.rollback()
            flash(
                "Investment settlement blocked by accounting reconciliation check. No changes were made.",
                "error"
            )
            return redirect(url_for("investment_detail", investment_id=investment_id))

        db.commit()

    except Exception:
        db.rollback()
        flash(
            "Investment settlement failed. No funds were changed.",
            "error"
        )
        return redirect(url_for("investment_detail",
                                investment_id=investment_id))

    flash(
        f"Investment #{investment_id} matured successfully. "
        f"Principal: ₦{amount:,.2f}. "
        f"Return: ₦{profit:,.2f}. "
        f"Total paid: ₦{total_payout:,.2f}.",
        "success"
    )

    return redirect(url_for("investment_detail",
                            investment_id=investment_id))


@app.route("/admin/process-matured", methods=["POST"])
@admin_required
def admin_process_matured():
    db = get_db()

    try:
        db.execute("BEGIN IMMEDIATE")

        settled_ids = process_matured_investments(db)

        if settled_ids:
            reconciliation = calculate_reconciliation(db)

            if not reconciliation["ok"]:
                db.rollback()
                flash(
                    "Automatic maturity processing was blocked by the accounting reconciliation check. No changes were made.",
                    "error"
                )
                return redirect(url_for("admin_investments"))

        db.commit()

    except Exception:
        db.rollback()
        flash(
            "Maturity processing failed. No investment changes were made.",
            "error"
        )
        return redirect(url_for("admin_investments"))

    if settled_ids:
        flash(
            f"Successfully processed {len(settled_ids)} matured investment(s).",
            "success"
        )
    else:
        flash(
            "No investments have reached maturity.",
            "success"
        )

    return redirect(url_for("admin_investments"))


@app.route("/admin/investment/<int:investment_id>/cancel", methods=["POST"])
@admin_required
def admin_cancel_investment(investment_id):
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        investment = db.execute("""
            SELECT id, user_id, amount, status
            FROM investments
            WHERE id = ?
        """, (investment_id,)).fetchone()

        if not investment:
            db.rollback()
            flash("Investment not found.", "error")
            return redirect(url_for("admin_investments"))

        if investment["status"] != "ACTIVE":
            db.rollback()
            flash("Only active investments can be cancelled.", "error")
            return redirect(url_for("admin_investments"))

        amount = float(investment["amount"])

        db.execute("""
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
        """, (amount, investment["user_id"]))

        db.execute("""
            UPDATE investments
            SET status = 'CANCELLED', completed_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (investment_id,))

        db.execute("""
            INSERT INTO transactions
            (user_id, transaction_type, amount, status, description)
            VALUES (?, 'investment_reversal', ?, 'Completed', ?)
        """, (
            investment["user_id"],
            amount,
            f"Reversal of cancelled investment #{investment_id}"
        ))

        audit_log(
            db,
            "admin",
            None,
            "investment_cancelled",
            "investment",
            investment_id,
            f"Cancelled investment #{investment_id} and returned {amount:.2f} to user {investment['user_id']}"
        )

        create_notification(
            db,
            investment["user_id"],
            "Investment Cancelled",
            f"Your investment #{investment_id} was cancelled by the administrator. "
            f"₦{amount:,.2f} has been returned to your balance."
        )

        reconciliation = calculate_reconciliation(db)

        if not reconciliation["ok"]:
            db.rollback()
            flash(
                "Investment cancellation blocked by accounting reconciliation check. No changes were made.",
                "error"
            )
            return redirect(url_for("admin_investments"))

        db.commit()
    except Exception:
        db.rollback()
        flash("Investment cancellation failed. No changes were made.", "error")
        return redirect(url_for("admin_investments"))

    flash(
        f"Investment #{investment_id} cancelled and ₦{amount:,.2f} returned.",
        "success"
    )
    return redirect(url_for("admin_investments"))



@app.route("/admin/investment/<int:investment_id>/restore", methods=["POST"])
@admin_required
def admin_restore_investment(investment_id):
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")

        investment = db.execute("""
            SELECT id, user_id, amount, status
            FROM investments
            WHERE id = ?
        """, (investment_id,)).fetchone()

        if not investment:
            db.rollback()
            flash("Investment not found.", "error")
            return redirect(url_for("admin_investments"))

        if investment["status"] != "CANCELLED":
            db.rollback()
            flash("Only cancelled investments can be restored.", "error")
            return redirect(url_for("admin_investments"))

        amount = float(investment["amount"])

        user = db.execute("""
            SELECT balance
            FROM users
            WHERE id = ?
        """, (investment["user_id"],)).fetchone()

        if not user or float(user["balance"]) < amount:
            db.rollback()
            flash("Insufficient user balance to restore this investment.", "error")
            return redirect(url_for("admin_investments"))

        db.execute("""
            UPDATE users
            SET balance = balance - ?
            WHERE id = ?
        """, (amount, investment["user_id"]))

        db.execute("""
            UPDATE investments
            SET status = 'ACTIVE', completed_at = NULL
            WHERE id = ?
        """, (investment_id,))

        db.execute("""
            INSERT INTO transactions
            (user_id, transaction_type, amount, status, description)
            VALUES (?, 'investment_reinstatement', ?, 'Completed', ?)
        """, (
            investment["user_id"],
            amount,
            f"Reinstatement of investment #{investment_id}"
        ))

        audit_log(
            db,
            "admin",
            None,
            "investment_reinstated",
            "investment",
            investment_id,
            f"Reinstated investment #{investment_id} and deducted {amount:.2f} from user {investment['user_id']}"
        )

        create_notification(
            db,
            investment["user_id"],
            "Investment Restored",
            f"Your investment #{investment_id} has been restored and is active again. "
            f"₦{amount:,.2f} has been deducted from your balance."
        )

        reconciliation = calculate_reconciliation(db)

        if not reconciliation["ok"]:
            db.rollback()
            flash(
                "Investment restoration blocked by accounting reconciliation check. No changes were made.",
                "error"
            )
            return redirect(url_for("admin_investments"))

        db.commit()

    except Exception:
        db.rollback()
        flash("Investment restoration failed. No changes were made.", "error")
        return redirect(url_for("admin_investments"))

    flash(
        f"Investment #{investment_id} restored to ACTIVE and ₦{amount:,.2f} deducted.",
        "success"
    )
    return redirect(url_for("admin_investments"))


@app.route("/admin/user/<int:user_id>/suspend", methods=["POST"])
@admin_required
def admin_suspend_user(user_id):
    db = get_db()

    try:
        user = db.execute(
            "SELECT id, name, status FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if not user:
            db.close()
            flash("User not found.", "error")
            return redirect(url_for("admin_dashboard"))

        if user["status"] == "Suspended":
            db.close()
            flash("User account is already suspended.", "error")
            return redirect(url_for("admin_user_details", user_id=user_id))

        db.execute(
            "UPDATE users SET status = 'Suspended' WHERE id = ?",
            (user_id,)
        )

        audit_log(
            db,
            "admin",
            None,
            "user_suspended",
            "user",
            user_id,
            f"Suspended user #{user_id} ({user['name']})"
        )

        create_notification(
            db,
            user_id,
            "Account Suspended",
            "Your NovaVest account has been suspended. Please contact support."
        )

        db.commit()

    except Exception:
        db.rollback()
        db.close()
        flash("Unable to suspend user. No changes were made.", "error")
        return redirect(url_for("admin_user_details", user_id=user_id))

    db.close()

    flash(
        f"User #{user_id} has been suspended.",
        "success"
    )

    return redirect(url_for("admin_user_details", user_id=user_id))


@app.route("/admin/user/<int:user_id>/activate", methods=["POST"])
@admin_required
def admin_activate_user(user_id):
    db = get_db()

    try:
        user = db.execute(
            "SELECT id, name, status FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if not user:
            db.close()
            flash("User not found.", "error")
            return redirect(url_for("admin_dashboard"))

        if user["status"] == "Active":
            db.close()
            flash("User account is already active.", "error")
            return redirect(url_for("admin_user_details", user_id=user_id))

        db.execute(
            "UPDATE users SET status = 'Active' WHERE id = ?",
            (user_id,)
        )

        audit_log(
            db,
            "admin",
            None,
            "user_activated",
            "user",
            user_id,
            f"Activated user #{user_id} ({user['name']})"
        )

        create_notification(
            db,
            user_id,
            "Account Activated",
            "Your NovaVest account has been activated. You can now log in."
        )

        db.commit()

    except Exception:
        db.rollback()
        db.close()
        flash("Unable to activate user. No changes were made.", "error")
        return redirect(url_for("admin_user_details", user_id=user_id))

    db.close()

    flash(
        f"User #{user_id} has been activated.",
        "success"
    )

    return redirect(url_for("admin_user_details", user_id=user_id))


@app.route("/admin/user/<int:user_id>")
@admin_required
def admin_user_details(user_id):
    db = get_db()

    user = db.execute(
        "SELECT id, name, email, balance, created_at, status FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if not user:
        db.close()
        flash("User not found.", "error")
        return redirect(url_for("admin_dashboard"))

    deposits = db.execute(
        "SELECT id, amount, status, created_at FROM deposits WHERE user_id = ? ORDER BY id DESC",
        (user_id,)
    ).fetchall()

    withdrawals = db.execute(
        "SELECT id, amount, status, created_at FROM withdrawals WHERE user_id = ? ORDER BY id DESC",
        (user_id,)
    ).fetchall()

    investments = db.execute(
        """
        SELECT investments.id, investments.amount, investments.status,
               investments.started_at, investments.maturity_at,
               investments.completed_at, investment_plans.name AS plan_name
        FROM investments
        JOIN investment_plans ON investment_plans.id = investments.plan_id
        WHERE investments.user_id = ?
        ORDER BY investments.id DESC
        """,
        (user_id,)
    ).fetchall()

    transactions = db.execute(
        """
        SELECT id, transaction_type, amount, status, description, created_at
        FROM transactions
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (user_id,)
    ).fetchall()

    audit_history = db.execute(
        """
        SELECT id, actor_type, actor_id, action,
               entity_type, entity_id, details, created_at
        FROM audit_logs
        WHERE actor_id = ?
           OR (entity_type = 'user' AND entity_id = ?)
        ORDER BY id DESC
        """,
        (user_id, user_id)
    ).fetchall()

    summary = db.execute(
        """
        SELECT
            COALESCE((SELECT SUM(amount) FROM deposits
                      WHERE user_id = ? AND status = 'Approved'), 0) AS approved_deposits,
            COALESCE((SELECT SUM(amount) FROM withdrawals
                      WHERE user_id = ? AND status = 'Approved'), 0) AS approved_withdrawals,
            COALESCE((SELECT SUM(amount) FROM investments
                      WHERE user_id = ? AND status = 'ACTIVE'), 0) AS active_investments,
            COALESCE((SELECT SUM(amount) FROM investments
                      WHERE user_id = ? AND status = 'COMPLETED'), 0) AS completed_investments,
            COALESCE((SELECT SUM(amount) FROM investments
                      WHERE user_id = ? AND status = 'CANCELLED'), 0) AS cancelled_investments
        """,
        (user_id, user_id, user_id, user_id, user_id)
    ).fetchone()

    db.close()

    return render_template(
        "admin_user_details.html",
        user=user,
        deposits=deposits,
        withdrawals=withdrawals,
        investments=investments,
        transactions=transactions,
        audit_history=audit_history,
        summary=summary
    )

@app.route("/admin/investments")
@admin_required
def admin_investments():
    db = get_db()

    investments = db.execute("""
        SELECT
            investments.id,
            investments.user_id,
            users.name AS user_name,
            users.email,
            investment_plans.name AS plan_name,
            investments.amount,
            investments.status,
            investments.started_at,
            investments.maturity_at,
            investments.completed_at
        FROM investments
        JOIN users
            ON users.id = investments.user_id
        JOIN investment_plans
            ON investment_plans.id = investments.plan_id
        ORDER BY investments.id DESC
    """).fetchall()

    total_investments = db.execute("""
        SELECT COUNT(*)
        FROM investments
    """).fetchone()[0]

    active_investments = db.execute("""
        SELECT COUNT(*)
        FROM investments
        WHERE status = 'ACTIVE'
    """).fetchone()[0]

    completed_investments = db.execute("""
        SELECT COUNT(*)
        FROM investments
        WHERE status = 'COMPLETED'
    """).fetchone()[0]

    total_invested = db.execute("""
        SELECT COALESCE(SUM(amount), 0)
        FROM investments
        WHERE status = 'ACTIVE'
    """).fetchone()[0]

    return render_template(
        "admin_investments.html",
        investments=investments,
        total_investments=total_investments,
        active_investments=active_investments,
        completed_investments=completed_investments,
        total_invested=total_invested
    )


@app.route("/admin/maturity")
@admin_required
def admin_maturity():
    db = get_db()

    investments = db.execute("""
        SELECT
            investments.id,
            users.email,
            investment_plans.name AS plan_name,
            investments.amount,
            investments.status,
            investments.started_at,
            investments.maturity_at,
            investments.completed_at
        FROM investments
        JOIN users
            ON users.id = investments.user_id
        JOIN investment_plans
            ON investment_plans.id = investments.plan_id
        ORDER BY
            CASE investments.status
                WHEN 'ACTIVE' THEN 1
                WHEN 'COMPLETED' THEN 2
                ELSE 3
            END,
            investments.maturity_at ASC
    """).fetchall()

    return render_template(
        "admin_maturity.html",
        investments=investments
    )


@app.route("/admin/audit-logs")
@admin_required
def admin_audit_logs():
    db = get_db()

    logs = db.execute("""
        SELECT
            id,
            actor_type,
            actor_id,
            action,
            entity_type,
            entity_id,
            details,
            created_at
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 500
    """).fetchall()

    return render_template(
        "admin_audit_logs.html",
        logs=logs
    )

@app.route("/admin/logout", methods=["POST"])
def admin_logout():

    session.pop("admin", None)

    return redirect(url_for("admin_login"))



@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500

# =========================================================
# DAILY TASKS - USER PAGE
# =========================================================

@app.route("/daily-tasks")
def daily_tasks():

    user = current_user()

    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    today = datetime.now().date().isoformat()

    tasks = conn.execute("""
        SELECT DISTINCT
            daily_tasks.id,
            daily_tasks.plan_id,
            daily_tasks.title,
            daily_tasks.description,
            daily_tasks.reward,
            investment_plans.name AS plan_name,
            CASE
                WHEN daily_task_completions.id IS NULL THEN 0
                ELSE 1
            END AS completed
        FROM daily_tasks
        JOIN investment_plans
            ON investment_plans.id = daily_tasks.plan_id
        LEFT JOIN daily_task_completions
            ON daily_task_completions.task_id = daily_tasks.id
            AND daily_task_completions.user_id = ?
            AND daily_task_completions.task_date = ?
        WHERE daily_tasks.active = 1
        AND investment_plans.active = 1
        AND EXISTS (
            SELECT 1
            FROM investments
            WHERE investments.user_id = ?
            AND investments.plan_id = daily_tasks.plan_id
            AND investments.status = 'ACTIVE'
        )
        ORDER BY daily_tasks.plan_id, daily_tasks.id
    """, (user["id"], today, user["id"])).fetchall()

    today_earnings = conn.execute("""
        SELECT COALESCE(SUM(reward), 0)
        FROM daily_task_completions
        WHERE user_id = ?
        AND task_date = ?
    """, (user["id"], today)).fetchone()[0]

    total_task_earnings = conn.execute("""
        SELECT COALESCE(SUM(reward), 0)
        FROM daily_task_completions
        WHERE user_id = ?
    """, (user["id"],)).fetchone()[0]

    conn.close()

    return render_template(
        "daily_tasks.html",
        user=user,
        tasks=tasks,
        today=today,
        today_earnings=today_earnings,
        total_task_earnings=total_task_earnings
    )



# =========================================================
# DAILY TASKS - COMPLETE TASK
# =========================================================

@app.route("/daily-tasks/<int:task_id>/complete", methods=["POST"])
def complete_daily_task(task_id):

    user = current_user()

    if not user:
        return redirect(url_for("login"))

    today = datetime.now().date().isoformat()

    conn = get_db()

    try:
        conn.execute("BEGIN IMMEDIATE")

        task = conn.execute("""
            SELECT
                daily_tasks.id,
                daily_tasks.plan_id,
                daily_tasks.title,
                daily_tasks.reward,
                daily_tasks.active,
                investment_plans.name AS plan_name
            FROM daily_tasks
            JOIN investment_plans
                ON investment_plans.id = daily_tasks.plan_id
            WHERE daily_tasks.id = ?
            AND daily_tasks.active = 1
            AND investment_plans.active = 1
        """, (task_id,)).fetchone()

        if not task:
            conn.rollback()
            conn.close()
            flash("This task is not available.", "error")
            return redirect(url_for("daily_tasks"))

        eligible = conn.execute("""
            SELECT 1
            FROM investments
            WHERE user_id = ?
            AND plan_id = ?
            AND status = 'ACTIVE'
            LIMIT 1
        """, (user["id"], task["plan_id"])).fetchone()

        if not eligible:
            conn.rollback()
            conn.close()
            flash("You are not eligible for this task.", "error")
            return redirect(url_for("daily_tasks"))

        existing = conn.execute("""
            SELECT id
            FROM daily_task_completions
            WHERE task_id = ?
            AND user_id = ?
            AND task_date = ?
        """, (task_id, user["id"], today)).fetchone()

        if existing:
            conn.rollback()
            conn.close()
            flash("You have already completed this task today.", "error")
            return redirect(url_for("daily_tasks"))

        reward = float(task["reward"])

        conn.execute("""
            INSERT INTO daily_task_completions
            (task_id, user_id, task_date, reward)
            VALUES (?, ?, ?, ?)
        """, (task_id, user["id"], today, reward))

        conn.execute("""
            UPDATE users
            SET balance = balance + ?
            WHERE id = ?
        """, (reward, user["id"]))

        conn.execute("""
            INSERT INTO transactions
            (user_id, transaction_type, amount, status, description)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user["id"],
            "Task Reward",
            reward,
            "Approved",
            f"Daily task reward: {task['title']}"
        ))

        create_notification(
            conn,
            user["id"],
            "Daily Task Completed",
            f"You completed '{task['title']}' and earned ₦{reward:,.2f}."
        )

        audit_log(
            conn,
            "user",
            user["id"],
            "daily_task_completed",
            "daily_task",
            task_id,
            f"Completed {task['title']} and received ₦{reward:.2f}"
        )

        conn.commit()
        conn.close()

        flash(
            f"Task completed successfully. ₦{reward:,.2f} has been added to your balance.",
            "success"
        )

    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()

        flash("This task has already been completed today.", "error")

    except Exception:
        conn.rollback()
        conn.close()

        flash("Unable to complete the task. Please try again.", "error")

    return redirect(url_for("daily_tasks"))



# =========================================================
# ADMIN - DAILY TASK MANAGEMENT
# =========================================================

@app.route("/admin/daily-tasks")
@admin_required
def admin_daily_tasks():

    conn = get_db()

    tasks = conn.execute("""
        SELECT
            daily_tasks.*,
            investment_plans.name AS plan_name,
            COUNT(daily_task_completions.id) AS completion_count
        FROM daily_tasks
        JOIN investment_plans
            ON investment_plans.id = daily_tasks.plan_id
        LEFT JOIN daily_task_completions
            ON daily_task_completions.task_id = daily_tasks.id
        GROUP BY daily_tasks.id
        ORDER BY daily_tasks.plan_id, daily_tasks.id
    """).fetchall()

    plans = conn.execute("""
        SELECT id, name, active
        FROM investment_plans
        ORDER BY id
    """).fetchall()

    conn.close()

    return render_template(
        "admin_daily_tasks.html",
        tasks=tasks,
        plans=plans
    )


@app.route("/admin/daily-tasks/create", methods=["POST"])
@admin_required
def admin_create_daily_task():

    plan_id = request.form.get("plan_id", type=int)
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    reward = request.form.get("reward", type=float)
    task_type = request.form.get("task_type", "daily_checkin").strip()

    if not plan_id or not title or reward is None or reward < 0:
        flash("Please provide valid task details.", "error")
        return redirect(url_for("admin_daily_tasks"))

    conn = get_db()

    plan = conn.execute("""
        SELECT id, name
        FROM investment_plans
        WHERE id = ?
    """, (plan_id,)).fetchone()

    if not plan:
        conn.close()
        flash("Selected investment plan was not found.", "error")
        return redirect(url_for("admin_daily_tasks"))

    conn.execute("""
        INSERT INTO daily_tasks
        (plan_id, title, description, reward, task_type, active)
        VALUES (?, ?, ?, ?, ?, 1)
    """, (
        plan_id,
        title,
        description,
        reward,
        task_type
    ))

    task_id = conn.execute(
        "SELECT last_insert_rowid()"
    ).fetchone()[0]

    audit_log(
        conn,
        "admin",
        None,
        "daily_task_created",
        "daily_task",
        task_id,
        f"Created task '{title}' for {plan['name']} with reward ₦{reward:.2f}"
    )

    conn.commit()
    conn.close()

    flash("Daily task created successfully.", "success")
    return redirect(url_for("admin_daily_tasks"))


@app.route("/admin/daily-tasks/<int:task_id>/edit", methods=["POST"])
@admin_required
def admin_edit_daily_task(task_id):

    plan_id = request.form.get("plan_id", type=int)
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    reward = request.form.get("reward", type=float)
    task_type = request.form.get("task_type", "daily_checkin").strip()

    if not plan_id or not title or reward is None or reward < 0:
        flash("Please provide valid task details.", "error")
        return redirect(url_for("admin_daily_tasks"))

    conn = get_db()

    task = conn.execute("""
        SELECT id
        FROM daily_tasks
        WHERE id = ?
    """, (task_id,)).fetchone()

    if not task:
        conn.close()
        flash("Daily task not found.", "error")
        return redirect(url_for("admin_daily_tasks"))

    conn.execute("""
        UPDATE daily_tasks
        SET plan_id = ?,
            title = ?,
            description = ?,
            reward = ?,
            task_type = ?
        WHERE id = ?
    """, (
        plan_id,
        title,
        description,
        reward,
        task_type,
        task_id
    ))

    audit_log(
        conn,
        "admin",
        None,
        "daily_task_updated",
        "daily_task",
        task_id,
        f"Updated task '{title}' with reward ₦{reward:.2f}"
    )

    conn.commit()
    conn.close()

    flash("Daily task updated successfully.", "success")
    return redirect(url_for("admin_daily_tasks"))


@app.route("/admin/daily-tasks/<int:task_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_daily_task(task_id):

    conn = get_db()

    task = conn.execute("""
        SELECT id, title, active
        FROM daily_tasks
        WHERE id = ?
    """, (task_id,)).fetchone()

    if not task:
        conn.close()
        flash("Daily task not found.", "error")
        return redirect(url_for("admin_daily_tasks"))

    new_status = 0 if task["active"] else 1

    conn.execute("""
        UPDATE daily_tasks
        SET active = ?
        WHERE id = ?
    """, (new_status, task_id))

    action = (
        "daily_task_activated"
        if new_status
        else "daily_task_deactivated"
    )

    audit_log(
        conn,
        "admin",
        None,
        action,
        "daily_task",
        task_id,
        f"Task '{task['title']}' active={new_status}"
    )

    conn.commit()
    conn.close()

    flash(
        "Daily task activated successfully."
        if new_status
        else "Daily task deactivated successfully.",
        "success"
    )

    return redirect(url_for("admin_daily_tasks"))


@app.route("/admin/daily-task-completions")
@admin_required
def admin_daily_task_completions():

    conn = get_db()

    completions = conn.execute("""
        SELECT
            daily_task_completions.*,
            daily_tasks.title AS task_title,
            investment_plans.name AS plan_name,
            users.name AS user_name,
            users.email AS user_email
        FROM daily_task_completions
        JOIN daily_tasks
            ON daily_tasks.id = daily_task_completions.task_id
        JOIN investment_plans
            ON investment_plans.id = daily_tasks.plan_id
        JOIN users
            ON users.id = daily_task_completions.user_id
        ORDER BY daily_task_completions.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "admin_daily_task_completions.html",
        completions=completions
    )


init_db()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
