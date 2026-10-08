import sqlite3

DB = "investment.db"

conn = sqlite3.connect(DB)

conn.executescript("""
CREATE TABLE IF NOT EXISTS investment_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    minimum_amount REAL NOT NULL,
    term_days INTEGER NOT NULL,
    management_fee_percent REAL NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1
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

CREATE INDEX IF NOT EXISTS idx_investments_user
ON investments(user_id);

CREATE INDEX IF NOT EXISTS idx_investments_status
ON investments(status);
""")

plans = [
    (
        "Starter",
        "Entry-level investment plan. Capital is subject to market and investment risk.",
        10000,
        30,
        0
    ),
    (
        "Growth",
        "Longer-term investment plan with exposure to investment risk.",
        50000,
        90,
        0
    ),
    (
        "Professional",
        "Higher minimum investment plan for users seeking longer-term exposure.",
        100000,
        180,
        0
    )
]

for plan in plans:
    conn.execute("""
        INSERT OR IGNORE INTO investment_plans
        (name, description, minimum_amount, term_days, management_fee_percent)
        VALUES (?, ?, ?, ?, ?)
    """, plan)

conn.commit()

print("Investment tables created successfully.")
print("\nAvailable plans:")

for row in conn.execute("""
    SELECT id, name, minimum_amount, term_days,
           management_fee_percent
    FROM investment_plans
    WHERE active = 1
    ORDER BY id
"""):
    print(
        f"ID {row[0]} | {row[1]} | "
        f"Minimum ₦{row[2]:,.2f} | "
        f"{row[3]} days | Fee {row[4]:.2f}%"
    )

conn.close()
