CREATE TABLE IF NOT EXISTS usage_analytics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_name TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  metadata TEXT
);
