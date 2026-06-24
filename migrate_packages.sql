CREATE TABLE IF NOT EXISTS packages (
  id         TEXT NOT NULL,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  type       TEXT NOT NULL DEFAULT 'box',
  dims_json  TEXT NOT NULL,
  color      TEXT NOT NULL DEFAULT '#3498db',
  top_face   TEXT,
  weight     REAL NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (id, user_id)
);
