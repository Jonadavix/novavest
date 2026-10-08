import sqlite3

conn = sqlite3.connect("investment.db")
conn.execute("PRAGMA foreign_keys = ON")

conn.execute("""
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
)
""")

conn.execute("""
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
)
""")

conn.execute("""
CREATE INDEX IF NOT EXISTS idx_daily_tasks_plan
ON daily_tasks(plan_id)
""")

conn.execute("""
CREATE INDEX IF NOT EXISTS idx_daily_task_completions_user_date
ON daily_task_completions(user_id, task_date)
""")

conn.commit()
conn.close()

print("Daily Tasks database tables created successfully.")
