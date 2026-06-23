CREATE TABLE IF NOT EXISTS users (
  id                    TEXT PRIMARY KEY,
  email                 TEXT UNIQUE NOT NULL,
  name                  TEXT NOT NULL,
  password_hash         TEXT NOT NULL,
  salt                  TEXT NOT NULL,
  created_at            INTEGER NOT NULL,
  trial_ends_at         INTEGER NOT NULL,
  stripe_customer_id    TEXT,
  stripe_subscription_id TEXT,
  subscription_status   TEXT NOT NULL DEFAULT 'trial',
  subscription_ends_at  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_users_email       ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_stripe_cust ON users(stripe_customer_id);
CREATE INDEX IF NOT EXISTS idx_users_stripe_sub  ON users(stripe_subscription_id);
