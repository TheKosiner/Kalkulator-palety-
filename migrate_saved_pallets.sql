CREATE TABLE IF NOT EXISTS saved_pallets (
  id         TEXT NOT NULL,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  data_json  TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (id, user_id)
);
