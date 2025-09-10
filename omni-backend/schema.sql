-- ==========================================================
-- FWEA-I Complete Database Schema (D1 / SQLite)
-- Run: wrangler d1 execute omnidb --file=schema.sql
-- ==========================================================

PRAGMA foreign_keys = ON;

-- =========================
-- TABLES
-- =========================

-- User subscriptions
CREATE TABLE IF NOT EXISTS user_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,                                    -- browser fingerprint (hashed)
  plan_type TEXT NOT NULL CHECK (plan_type IN ('single_track','day_pass','dj_pro','studio_elite')),
  created_at INTEGER NOT NULL,                              -- ms epoch
  expires_at INTEGER,                                       -- NULL = no expiry
  updated_at INTEGER DEFAULT (strftime('%s','now')*1000),
  is_active BOOLEAN DEFAULT TRUE,                           -- 1/0
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  stripe_session_id TEXT,
  email TEXT,
  device_count INTEGER DEFAULT 1,
  last_accessed INTEGER DEFAULT (strftime('%s','now')*1000),
  UNIQUE(user_id, plan_type)
);

-- Processing history
CREATE TABLE IF NOT EXISTS processing_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  process_id TEXT NOT NULL UNIQUE,
  original_filename TEXT,
  file_size INTEGER,
  detected_languages TEXT,             -- JSON array
  words_removed INTEGER DEFAULT 0,
  profanity_timestamps TEXT,           -- JSON array of {start,end,word,...}
  processing_time_ms INTEGER,
  plan_type TEXT DEFAULT 'free',
  result TEXT,                         -- JSON blob (full result)
  watermark_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL,         -- ms epoch
  status TEXT DEFAULT 'completed' CHECK (status IN ('processing','completed','failed','expired')),
  expires_at INTEGER                   -- when temp files expire
);

-- Admin users (RBAC)
CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  permissions TEXT DEFAULT '["full_access"]', -- JSON array
  created_at INTEGER NOT NULL,
  updated_at INTEGER DEFAULT (strftime('%s','now')*1000),
  is_active BOOLEAN DEFAULT TRUE,
  last_login INTEGER,
  created_by INTEGER REFERENCES admin_users(id)
);

-- Payment transactions
CREATE TABLE IF NOT EXISTS payment_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_session_id TEXT UNIQUE,
  stripe_payment_intent_id TEXT,
  stripe_subscription_id TEXT,
  user_id TEXT NOT NULL,
  plan_type TEXT NOT NULL,
  amount INTEGER NOT NULL,           -- cents
  currency TEXT DEFAULT 'usd',
  status TEXT NOT NULL CHECK (status IN ('pending','processing','completed','failed','refunded','cancelled')),
  failure_reason TEXT,
  metadata TEXT,                     -- JSON
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  completed_at INTEGER
);

-- Usage analytics (lightweight events)
CREATE TABLE IF NOT EXISTS usage_analytics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  session_id TEXT,
  event_type TEXT NOT NULL,          -- 'page_view', 'file_upload', 'payment', ...
  event_action TEXT,                 -- sub-action
  plan_type TEXT,
  file_size INTEGER,
  processing_time_ms INTEGER,
  languages_detected TEXT,           -- JSON array
  user_agent TEXT,
  ip_address TEXT,
  referrer TEXT,
  country TEXT,
  device_type TEXT,                  -- mobile/desktop/tablet
  created_at INTEGER NOT NULL,
  value REAL
);

-- File storage references for R2 objects
CREATE TABLE IF NOT EXISTS file_storage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  process_id TEXT NOT NULL,
  file_type TEXT NOT NULL CHECK (file_type IN ('original','preview','full','watermarked')),
  storage_key TEXT NOT NULL UNIQUE,  -- R2 key
  file_size INTEGER,
  mime_type TEXT,
  watermark_id TEXT,
  access_count INTEGER DEFAULT 0,
  max_access_count INTEGER,
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  last_accessed INTEGER
);

-- Email verification codes
CREATE TABLE IF NOT EXISTS verification_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  code TEXT NOT NULL,
  plan_type TEXT NOT NULL,
  attempts INTEGER DEFAULT 0,
  max_attempts INTEGER DEFAULT 3,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  ip_address TEXT
);

-- Simple rate limits (per endpoint / window)
CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identifier TEXT NOT NULL,          -- IP or user_id
  endpoint TEXT NOT NULL,
  requests INTEGER DEFAULT 1,
  window_start INTEGER NOT NULL,
  window_size INTEGER DEFAULT 3600000, -- 1h ms
  created_at INTEGER NOT NULL,
  UNIQUE(identifier, endpoint, window_start)
);

-- System config (key/value)
CREATE TABLE IF NOT EXISTS system_config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  config_key TEXT NOT NULL UNIQUE,
  config_value TEXT NOT NULL,
  config_type TEXT DEFAULT 'string' CHECK (config_type IN ('string','number','boolean','json')),
  description TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER DEFAULT (strftime('%s','now')*1000)
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  action TEXT NOT NULL,
  resource TEXT,
  old_value TEXT,
  new_value TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);

-- Webhook events (Stripe)
CREATE TABLE IF NOT EXISTS webhook_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_event_id TEXT UNIQUE,
  event_type TEXT NOT NULL,
  event_data TEXT NOT NULL,   -- JSON blob
  processed BOOLEAN DEFAULT FALSE,
  processing_attempts INTEGER DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  processed_at INTEGER
);

-- =========================
-- INDEXES
-- =========================

-- Subscriptions hot paths
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_id          ON user_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_plan_type        ON user_subscriptions(plan_type);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_expires_at       ON user_subscriptions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_active           ON user_subscriptions(is_active, expires_at);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_stripe_session   ON user_subscriptions(stripe_session_id);
-- Extra composites to match worker queries
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_plan_active ON user_subscriptions(user_id, plan_type, is_active);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_session_plan ON user_subscriptions(user_id, stripe_session_id, plan_type);

-- Processing history
CREATE INDEX IF NOT EXISTS idx_processing_history_user_id   ON processing_history(user_id);
CREATE INDEX IF NOT EXISTS idx_processing_history_created_at ON processing_history(created_at);
CREATE INDEX IF NOT EXISTS idx_processing_history_plan_type ON processing_history(plan_type);
CREATE INDEX IF NOT EXISTS idx_processing_history_status    ON processing_history(status);
CREATE INDEX IF NOT EXISTS idx_processing_history_expires   ON processing_history(expires_at);

-- Payments
CREATE INDEX IF NOT EXISTS idx_payment_transactions_user_id       ON payment_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_transactions_status        ON payment_transactions(status);
CREATE INDEX IF NOT EXISTS idx_payment_transactions_created_at    ON payment_transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_payment_transactions_stripe_session ON payment_transactions(stripe_session_id);

-- Analytics
CREATE INDEX IF NOT EXISTS idx_usage_analytics_event_type ON usage_analytics(event_type);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_created_at ON usage_analytics(created_at);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_user_id    ON usage_analytics(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_session    ON usage_analytics(session_id);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_plan_type  ON usage_analytics(plan_type);

-- Files
CREATE INDEX IF NOT EXISTS idx_file_storage_process_id ON file_storage(process_id);
CREATE INDEX IF NOT EXISTS idx_file_storage_expires_at ON file_storage(expires_at);
CREATE INDEX IF NOT EXISTS idx_file_storage_storage_key ON file_storage(storage_key);

-- Verification codes
CREATE INDEX IF NOT EXISTS idx_verification_codes_email_code ON verification_codes(email, code);
CREATE INDEX IF NOT EXISTS idx_verification_codes_expires_at ON verification_codes(expires_at);

-- Rate limits
CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier, endpoint);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window     ON rate_limits(window_start, window_size);

-- Audit
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action     ON audit_log(action);

-- Webhooks
CREATE INDEX IF NOT EXISTS idx_webhook_events_stripe_id ON webhook_events(stripe_event_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_processed ON webhook_events(processed);
CREATE INDEX IF NOT EXISTS idx_webhook_events_created_at ON webhook_events(created_at);

-- =========================
-- VIEWS (analytics convenience)
-- =========================

-- Active subscriptions (+derived status/days_remaining)
CREATE VIEW IF NOT EXISTS active_subscriptions AS
SELECT 
  us.*,
  CASE 
    WHEN us.expires_at IS NULL THEN 'active'
    WHEN us.expires_at > (strftime('%s','now')*1000) THEN 'active'
    ELSE 'expired'
  END AS subscription_status,
  CASE
    WHEN us.expires_at IS NOT NULL THEN 
      ROUND((us.expires_at - (strftime('%s','now')*1000)) / 86400000.0, 1)
    ELSE NULL
  END AS days_remaining
FROM user_subscriptions us
WHERE us.is_active = TRUE;

-- Per-day processing stats
CREATE VIEW IF NOT EXISTS processing_stats AS
SELECT 
  plan_type,
  COUNT(*) AS total_processes,
  AVG(processing_time_ms) AS avg_processing_time,
  AVG(words_removed) AS avg_words_removed,
  AVG(file_size) AS avg_file_size,
  SUM(file_size) AS total_data_processed,
  COUNT(DISTINCT user_id) AS unique_users,
  DATE(created_at/1000,'unixepoch') AS process_date
FROM processing_history 
WHERE status = 'completed'
GROUP BY plan_type, DATE(created_at/1000,'unixepoch');

-- Revenue by plan/day
CREATE VIEW IF NOT EXISTS revenue_analytics AS
SELECT 
  plan_type,
  COUNT(*) AS transaction_count,
  SUM(amount) AS total_revenue_cents,
  ROUND(SUM(amount)/100.0, 2) AS total_revenue_dollars,
  AVG(amount) AS avg_transaction_cents,
  COUNT(DISTINCT user_id) AS unique_customers,
  DATE(created_at/1000,'unixepoch') AS transaction_date
FROM payment_transactions 
WHERE status = 'completed'
GROUP BY plan_type, DATE(created_at/1000,'unixepoch');

-- User engagement rollup
CREATE VIEW IF NOT EXISTS user_engagement AS
SELECT 
  user_id,
  plan_type,
  COUNT(*) AS total_actions,
  COUNT(DISTINCT DATE(created_at/1000,'unixepoch')) AS active_days,
  MIN(created_at) AS first_seen,
  MAX(created_at) AS last_seen,
  COUNT(CASE WHEN event_type='file_upload' THEN 1 END) AS files_uploaded,
  COUNT(CASE WHEN event_type='payment' THEN 1 END) AS payments_made
FROM usage_analytics 
GROUP BY user_id, plan_type;

-- Daily usage summary
CREATE VIEW IF NOT EXISTS daily_usage_summary AS
SELECT 
  DATE(created_at/1000,'unixepoch') AS usage_date,
  plan_type,
  COUNT(DISTINCT user_id) AS unique_users,
  COUNT(*) AS total_events,
  COUNT(CASE WHEN event_type='file_upload' THEN 1 END) AS file_uploads,
  COUNT(CASE WHEN event_type='payment' THEN 1 END) AS payments,
  SUM(file_size) AS total_data_processed
FROM usage_analytics 
GROUP BY DATE(created_at/1000,'unixepoch'), plan_type;

-- =========================
-- TRIGGERS
-- =========================

-- Keep updated_at fresh on subs
CREATE TRIGGER IF NOT EXISTS update_user_subscriptions_updated_at
AFTER UPDATE ON user_subscriptions
BEGIN
  UPDATE user_subscriptions 
  SET updated_at = strftime('%s','now')*1000 
  WHERE id = NEW.id;
END;

-- Keep updated_at fresh on payments
CREATE TRIGGER IF NOT EXISTS update_payment_transactions_updated_at
AFTER UPDATE ON payment_transactions
BEGIN
  UPDATE payment_transactions 
  SET updated_at = strftime('%s','now')*1000 
  WHERE id = NEW.id;
END;

-- Audit on subscription state changes
CREATE TRIGGER IF NOT EXISTS audit_user_subscriptions_changes
AFTER UPDATE ON user_subscriptions
BEGIN
  INSERT INTO audit_log (user_id, action, resource, old_value, new_value, created_at)
  VALUES (
    NEW.user_id,
    'subscription_updated',
    'user_subscriptions',
    json_object('plan_type', OLD.plan_type, 'is_active', OLD.is_active),
    json_object('plan_type', NEW.plan_type, 'is_active', NEW.is_active),
    strftime('%s','now')*1000
  );
END;

-- Clear expired verification codes opportunistically
CREATE TRIGGER IF NOT EXISTS cleanup_expired_verification_codes
AFTER INSERT ON verification_codes
BEGIN
  DELETE FROM verification_codes 
  WHERE expires_at < strftime('%s','now')*1000;
END;

-- =========================
-- DEFAULTS & SEED
-- =========================

-- Default admin (change email!)
INSERT OR IGNORE INTO admin_users (email, permissions, created_at) 
VALUES ('admin@yourdomain.com','["full_access","user_management","analytics"]',strftime('%s','now')*1000);

-- System config defaults
INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description, created_at) VALUES
('max_file_size_free','52428800','number','Max file size for free users (50MB)',strftime('%s','now')*1000),
('max_file_size_premium','104857600','number','Max file size for premium users (100MB)',strftime('%s','now')*1000),
('max_file_size_studio','524288000','number','Max file size for studio users (500MB)',strftime('%s','now')*1000),
('preview_duration_default','30','number','Default preview duration (s)',strftime('%s','now')*1000),
('preview_duration_studio','60','number','Studio preview duration (s)',strftime('%s','now')*1000),
('file_retention_hours','48','number','Hours to keep processed files',strftime('%s','now')*1000),
('rate_limit_uploads_per_hour','10','number','Max uploads/hour for free users',strftime('%s','now')*1000),
('maintenance_mode','false','boolean','Global maintenance mode flag',strftime('%s','now')*1000);

-- Schema version
INSERT OR REPLACE INTO system_config (config_key, config_value, config_type, description, created_at)
VALUES ('schema_version','1.0.1','string','Database schema version',strftime('%s','now')*1000);

-- =========================
-- OPTIONAL CLEANUPS (manual/cron)
-- =========================
-- DELETE FROM file_storage WHERE expires_at < strftime('%s','now')*1000;
-- DELETE FROM processing_history WHERE created_at < strftime('%s','now','-30 days')*1000 AND status='completed';
-- DELETE FROM verification_codes WHERE expires_at < strftime('%s','now')*1000;
-- DELETE FROM usage_analytics WHERE created_at < strftime('%s','now','-90 days')*1000;

-- End of schema
