import os
from psycopg2 import connect, extras
from dotenv import load_dotenv

# 1) Load DATABASE_URL from .env
load_dotenv()  
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("Set DATABASE_URL in your .env file")

# 2) Connect
conn = connect(DATABASE_URL)
cur  = conn.cursor(cursor_factory=extras.RealDictCursor)

# 3) Schema: create tables if missing
cur.execute("""
CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  price REAL NOT NULL DEFAULT 0.0,
  reorder_level INTEGER NOT NULL DEFAULT 5
);
""")
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','viewer')),
  email TEXT
);
""")
cur.execute("""
CREATE TABLE IF NOT EXISTS request_history (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL REFERENCES users(username),
  product_id INTEGER NOT NULL REFERENCES products(id),
  product_name TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  reason TEXT NOT NULL,
  sub_reason TEXT,
  drone_number TEXT NOT NULL,
  status TEXT NOT NULL,
  requested_at TIMESTAMP NOT NULL DEFAULT NOW(),
  decision_at TIMESTAMP,
  decided_by TEXT,
  used INTEGER NOT NULL DEFAULT 0,
  remaining INTEGER NOT NULL DEFAULT 0,
  gst_exclusive REAL NOT NULL DEFAULT 0.0,
  total_inclusive REAL NOT NULL DEFAULT 0.0,
  comment TEXT
);
""")
cur.execute("""
CREATE TABLE IF NOT EXISTS stock_history (
  id SERIAL PRIMARY KEY,
  product_id INTEGER REFERENCES products(id),
  product_name TEXT,
  changed_by TEXT,
  old_quantity INTEGER,
  new_quantity INTEGER,
  change_amount INTEGER,
  changed_at TIMESTAMP NOT NULL DEFAULT NOW()
);
""")
cur.execute("""
CREATE TABLE IF NOT EXISTS attachments (
  id SERIAL PRIMARY KEY,
  request_id INTEGER NOT NULL REFERENCES request_history(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  uploaded_by TEXT NOT NULL,
  uploaded_at TIMESTAMP NOT NULL DEFAULT NOW()
);
""")
cur.execute("""
CREATE TABLE IF NOT EXISTS request_comments (
  id SERIAL PRIMARY KEY,
  request_id INTEGER NOT NULL REFERENCES request_history(id) ON DELETE CASCADE,
  commenter TEXT NOT NULL,
  comment_text TEXT NOT NULL,
  commented_at TIMESTAMP NOT NULL DEFAULT NOW()
);
""")

# 4) Seed admins
admins = [
    (1,'Chetan_Singhal','Chetan@1002','admin','chetan@example.com'),
    (2,'Pulkit','Pulkit_Mittal','admin','pulkit@example.com'),
    (3,'Karthik','Karthik@1234','admin','karthik@example.com'),
]
extras.execute_batch(cur, """
INSERT INTO users(id,username,password,role,email)
VALUES (%s,%s,%s,%s,%s)
ON CONFLICT (id) DO NOTHING;
""", admins)

# 5) Seed viewers
viewers = [
    ('viewer1','viewpass1','viewer','viewer1@example.com'),
    ('viewer2','viewpass2','viewer','viewer2@example.com'),
    ('viewer3','viewpass3','viewer','viewer3@example.com'),
    ('viewer4','viewpass4','viewer','viewer4@example.com'),
    ('viewer5','viewpass5','viewer','viewer5@example.com'),
]
extras.execute_batch(cur, """
INSERT INTO users(username,password,role,email)
VALUES (%s,%s,%s,%s)
ON CONFLICT (username) DO NOTHING;
""", viewers)

conn.commit()
cur.close()
conn.close()

print("✅ Local Postgres initialized with schema and seeded users.")