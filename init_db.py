import sqlite3

conn = sqlite3.connect('database.db')
c = conn.cursor()

c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    activated INTEGER DEFAULT 0,
    expiry_date TEXT,
    device_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

c.execute('''
CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plan TEXT,
    start_date TEXT,
    end_date TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

conn.commit()
conn.close()

print("✅ قاعدة البيانات تم إنشاؤها بنجاح!")
