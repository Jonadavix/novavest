from pathlib import Path

path = Path("app.py")
text = path.read_text()

marker = '\nif __name__ == "__main__":'

admin_code = r'''
import os
from functools import wraps


ADMIN_EMAIL = os.environ.get(
    "ADMIN_EMAIL",
    "admin@novavest.local"
)

ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "ChangeMe123!"
)


def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("admin"):
            return redirect(url_for("admin_login"))

        return function(*args, **kwargs)

    return wrapper


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":

        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:

            session["admin"] = True

            return redirect(url_for("admin_dashboard"))

        return "Invalid administrator credentials."

    return render_template("admin_login.html")


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
        SELECT id, name, email, balance, created_at
        FROM users
        ORDER BY created_at DESC
        """
    ).fetchall()

    conn.close()

    return render_template(
        "admin.html",
        pending_deposits=pending_deposits,
        pending_withdrawals=pending_withdrawals,
        users=users
    )


@app.route("/admin/deposit/<int:deposit_id>/approve", methods=["POST"])
@admin_required
def approve_deposit(deposit_id):

    conn = get_db()

    deposit = conn.execute(
        """
        SELECT *
        FROM deposits
        WHERE id = ?
        """,
        (deposit_id,)
    ).fetchone()

    if not deposit:
        conn.close()
        return "Deposit not found."

    if deposit["status"] != "Pending":
        conn.close()
        return "This deposit has already been processed."

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
        (deposit["amount"], deposit["user_id"])
    )

    conn.execute(
        """
        UPDATE transactions
        SET status = 'Approved'
        WHERE user_id = ?
        AND transaction_type = 'Deposit'
        AND description = ?
        """,
        (
            deposit["user_id"],
            f"Deposit request #{deposit_id}"
        )
    )

    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/deposit/<int:deposit_id>/reject", methods=["POST"])
@admin_required
def reject_deposit(deposit_id):

    conn = get_db()

    deposit = conn.execute(
        """
        SELECT *
        FROM deposits
        WHERE id = ?
        """,
        (deposit_id,)
    ).fetchone()

    if not deposit:
        conn.close()
        return "Deposit not found."

    if deposit["status"] != "Pending":
        conn.close()
        return "This deposit has already been processed."

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
        """,
        (
            deposit["user_id"],
            f"Deposit request #{deposit_id}"
        )
    )

    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/withdrawal/<int:withdrawal_id>/approve", methods=["POST"])
@admin_required
def approve_withdrawal(withdrawal_id):

    conn = get_db()

    withdrawal = conn.execute(
        """
        SELECT *
        FROM withdrawals
        WHERE id = ?
        """,
        (withdrawal_id,)
    ).fetchone()

    if not withdrawal:
        conn.close()
        return "Withdrawal not found."

    if withdrawal["status"] != "Pending":
        conn.close()
        return "This withdrawal has already been processed."

    user = conn.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (withdrawal["user_id"],)
    ).fetchone()

    if user["balance"] < withdrawal["amount"]:
        conn.close()
        return "Insufficient balance. Withdrawal cannot be approved."

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
        (withdrawal["amount"], withdrawal["user_id"])
    )

    conn.execute(
        """
        UPDATE transactions
        SET status = 'Approved'
        WHERE user_id = ?
        AND transaction_type = 'Withdrawal'
        AND description = ?
        """,
        (
            withdrawal["user_id"],
            f"Withdrawal request #{withdrawal_id}"
        )
    )

    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/withdrawal/<int:withdrawal_id>/reject", methods=["POST"])
@admin_required
def reject_withdrawal(withdrawal_id):

    conn = get_db()

    withdrawal = conn.execute(
        """
        SELECT *
        FROM withdrawals
        WHERE id = ?
        """,
        (withdrawal_id,)
    ).fetchone()

    if not withdrawal:
        conn.close()
        return "Withdrawal not found."

    if withdrawal["status"] != "Pending":
        conn.close()
        return "This withdrawal has already been processed."

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
        """,
        (
            withdrawal["user_id"],
            f"Withdrawal request #{withdrawal_id}"
        )
    )

    conn.commit()
    conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/logout")
def admin_logout():

    session.pop("admin", None)

    return redirect(url_for("admin_login"))
'''

if marker not in text:
    raise SystemExit("Could not find app startup section.")

if "def admin_login()" in text:
    raise SystemExit("Admin functionality already appears to be installed.")

text = text.replace(marker, admin_code + marker)

path.write_text(text)

print("Admin functionality added successfully.")
