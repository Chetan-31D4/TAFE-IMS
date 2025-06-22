-- products
CREATE TABLE IF NOT EXISTS products (
  id       SERIAL PRIMARY KEY,
  name     TEXT    NOT NULL,
  type     TEXT    NOT NULL,
  quantity INTEGER NOT NULL,
  price    REAL    NOT NULL DEFAULT 0.0
);

-- users
CREATE TABLE IF NOT EXISTS users (
  id       SERIAL PRIMARY KEY,
  username TEXT UNIQUE    NOT NULL,
  password TEXT           NOT NULL,
  role     TEXT CHECK (role IN ('admin','viewer')) NOT NULL,
  email    TEXT           -- optional: for notifications
);

-- edit_requests (not used if you’ve moved to request_history)
CREATE TABLE IF NOT EXISTS edit_requests (
  id                 SERIAL PRIMARY KEY,
  product_id         INTEGER NOT NULL REFERENCES products(id),
  requested_name     TEXT    NOT NULL,
  requested_type     TEXT    NOT NULL,
  requested_quantity INTEGER NOT NULL,
  requested_by       TEXT    NOT NULL REFERENCES users(username),
  status             TEXT    NOT NULL DEFAULT 'pending'
);

-- request_history
CREATE TABLE IF NOT EXISTS request_history (
  id              SERIAL   PRIMARY KEY,
  username        TEXT     NOT NULL REFERENCES users(username),
  product_id      INTEGER  NOT NULL REFERENCES products(id),
  product_name    TEXT     NOT NULL,
  quantity        INTEGER  NOT NULL,         -- approved quantity
  reason          TEXT     NOT NULL,
  sub_reason      TEXT,
  drone_number    TEXT     NOT NULL,
  status          TEXT     NOT NULL,         -- 'pending','approved','rejected'
  requested_at    TIMESTAMP NOT NULL,
  decision_at     TIMESTAMP,
  decided_by      TEXT,
  used            INTEGER  NOT NULL DEFAULT 0,
  remaining       INTEGER  NOT NULL DEFAULT 0,
  gst_exclusive   REAL     NOT NULL DEFAULT 0.0,
  total_inclusive REAL     NOT NULL DEFAULT 0.0,
  comment         TEXT     -- for audit trail
);

-- stock_history
CREATE TABLE IF NOT EXISTS stock_history (
  id            SERIAL   PRIMARY KEY,
  product_id    INTEGER  REFERENCES products(id),
  product_name  TEXT,
  changed_by    TEXT,
  old_quantity  INTEGER,
  new_quantity  INTEGER,
  change_amount INTEGER,
  changed_at    TIMESTAMP
);

-- requests (if you still need this legacy table)
CREATE TABLE IF NOT EXISTS requests (
  id           SERIAL   PRIMARY KEY,
  username     TEXT     NOT NULL REFERENCES users(username),
  product_id   INTEGER  NOT NULL REFERENCES products(id),
  quantity     INTEGER  NOT NULL,
  reason       TEXT     NOT NULL,
  sub_reason   TEXT,
  drone_number TEXT     NOT NULL,
  status       TEXT     NOT NULL,
  timestamp    TIMESTAMP NOT NULL
);

-- seed the three admins
INSERT INTO users (id, username, password, role)
VALUES
  (1, 'Chetan_Singhal', 'Chetan@1002', 'admin'),
  (2, 'Pulkit',         'Pulkit_Mittal', 'admin'),
  (3, 'Karthik',        'Karthik@1234',  'admin')
ON CONFLICT (id) DO NOTHING;

-- seed the five viewers
INSERT INTO users (username, password, role)
VALUES
  ('viewer1', 'viewpass1', 'viewer'),
  ('viewer2', 'viewpass2', 'viewer'),
  ('viewer3', 'viewpass3', 'viewer'),
  ('viewer4', 'viewpass4', 'viewer'),
  ('viewer5', 'viewpass5', 'viewer')
ON CONFLICT (username) DO NOTHING;
