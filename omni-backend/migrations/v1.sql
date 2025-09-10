-- ==========================================================
-- FWEA-I Migrations -> Schema 1.0.1
-- Safe to run multiple times (idempotent)
-- Run: wrangler d1 execute omnidb --file=migrations.sql
-- ==========================================================

PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

-- ------------------------------------------
-- Ensure system_config table exists (for versioning)
-- (If your DB already has it, this is a no-op.)
-- ------------------------------------------
CREATE TABLE IF NOT EXISTS system_config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  config_key TEXT NOT NULL UNIQUE,
  config_value TEXT NOT NULL,
  config_type TEXT DEFAULT 'string' CHECK (config_type IN ('string','number','boolean','json')),
  description TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER DEFAULT (strftime('%s','now')*1000)
);

-- ------------------------------------------
-- INDEXES (added or ensured)
-- ------------------------------------------

-- user_subscriptions
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_id           ON user_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_plan_type         ON user_subscriptions(plan_type);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_expires_at        ON user_subscriptions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_active            ON user_subscriptions(is_active, expires_at);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_stripe_session    ON user_subscriptions(stripe_session_id);
-- New composite hot paths
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_plan_active  ON user_subscriptions(user_id, plan_type, is_active);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_session_plan ON user_subscriptions(user_id, stripe_session_id, plan_type);

-- processing_history
CREATE INDEX IF NOT EXISTS idx_processing_history_user_id   ON processing_history(user_id);
CREATE INDEX IF NOT EXISTS idx_processing_history_created_at ON processing_history(created_at);
CREATE INDEX IF NOT EXISTS idx_processing_history_plan_type ON processing_history(plan_type);
CREATE INDEX IF NOT EXISTS idx_processing_history_status    ON processing_history(status);
CREATE INDEX IF NOT EXISTS idx_processing_history_expires   ON processing_history(expires_at);

-- payment_transactions
CREATE INDEX IF NOT EXISTS idx_payment_transactions_user_id        ON payment_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_transactions_status         ON payment_transactions(status);
CREATE INDEX IF NOT EXISTS idx_payment_transactions_created_at     ON payment_transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_payment_transactions_stripe_session ON payment_transactions(stripe_session_id);

-- usage_analytics
CREATE INDEX IF NOT EXISTS idx_usage_analytics_event_type ON usage_analytics(event_type);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_created_at ON usage_analytics(created_at);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_user_id    ON usage_analytics(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_session    ON usage_analytics(session_id);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_plan_type  ON usage_analytics(plan_type);

-- file_storage
CREATE INDEX IF NOT EXISTS idx_file_storage_process_id  ON file_storage(process_id);
CREATE INDEX IF NOT EXISTS idx_file_storage_expires_at  ON file_storage(expires_at);
CREATE INDEX IF NOT EXISTS idx_file_storage_storage_key ON file_storage(storage_key);

-- verification_codes
CREATE INDEX IF NOT EXISTS idx_verification_codes_email_code ON verification_codes(email, code);
CREATE INDEX IF NOT EXISTS idx_verification_codes_expires_at ON verification_codes(expires_at);

-- rate_limits
CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier, endpoint);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window     ON rate_limits(window_start, window_size);

-- audit_log
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id    ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action     ON audit_log(action);

-- webhook_events
CREATE INDEX IF NOT EXISTS idx_webhook_events_stripe_id  ON webhook_events(stripe_event_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_processed  ON webhook_events(processed);
CREATE INDEX IF NOT EXISTS idx_webhook_events_created_at ON webhook_events(created_at);

-- ------------------------------------------
-- VIEWS (recreate to latest definitions)
-- ------------------------------------------

DROP VIEW IF EXISTS active_subscriptions;
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

DROP VIEW IF EXISTS processing_stats;
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

DROP VIEW IF EXISTS revenue_analytics;
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

DROP VIEW IF EXISTS user_engagement;
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

DROP VIEW IF EXISTS daily_usage_summary;
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

-- ------------------------------------------
-- TRIGGERS (ensure present)
-- ------------------------------------------

CREATE TRIGGER IF NOT EXISTS update_user_subscriptions_updated_at
AFTER UPDATE ON user_subscriptions
BEGIN
  UPDATE user_subscriptions 
  SET updated_at = strftime('%s','now')*1000 
  WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_payment_transactions_updated_at
AFTER UPDATE ON payment_transactions
BEGIN
  UPDATE payment_transactions 
  SET updated_at = strftime('%s','now')*1000 
  WHERE id = NEW.id;
END;

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

CREATE TRIGGER IF NOT EXISTS cleanup_expired_verification_codes
AFTER INSERT ON verification_codes
BEGIN
  DELETE FROM verification_codes 
  WHERE expires_at < strftime('%s','now')*1000;
END;

-- ------------------------------------------
-- DEFAULTS / SEED (safe upserts)
-- ------------------------------------------

INSERT OR IGNORE INTO admin_users (email, permissions, created_at) 
VALUES ('admin@yourdomain.com','["full_access","user_management","analytics"]',strftime('%s','now')*1000);

INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description, created_at) VALUES
('max_file_size_free','52428800','number','Max file size for free users (50MB)',strftime('%s','now')*1000),
('max_file_size_premium','104857600','number','Max file size for premium users (100MB)',strftime('%s','now')*1000),
('max_file_size_studio','524288000','number','Max file size for studio users (500MB)',strftime('%s','now')*1000),
('preview_duration_default','30','number','Default preview duration (s)',strftime('%s','now')*1000),
('preview_duration_studio','60','number','Studio preview duration (s)',strftime('%s','now')*1000),
('file_retention_hours','48','number','Hours to keep processed files',strftime('%s','now')*1000),
('rate_limit_uploads_per_hour','10','number','Max uploads/hour for free users',strftime('%s','now')*1000),
('maintenance_mode','false','boolean','Global maintenance mode flag',strftime('%s','now')*1000);

-- Bump schema version
INSERT OR REPLACE INTO system_config (config_key, config_value, config_type, description, created_at)
VALUES ('schema_version','1.0.1','string','Database schema version',strftime('%s','now')*1000);

COMMIT;
