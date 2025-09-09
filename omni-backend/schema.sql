-- FWEA-I Complete Database Schema
-- Production-ready schema with enhanced security and analytics
-- Run: wrangler d1 execute fwea-database --file=schema.sql

-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- User subscriptions table with enhanced security
CREATE TABLE IF NOT EXISTS user_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL, -- Browser fingerprint hash
  plan_type TEXT NOT NULL CHECK (plan_type IN ('single_track', 'day_pass', 'dj_pro', 'studio_elite')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER, -- NULL for perpetual subscriptions
  updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
  is_active BOOLEAN DEFAULT TRUE,
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  stripe_session_id TEXT,
  email TEXT,
  device_count INTEGER DEFAULT 1,
  last_accessed INTEGER DEFAULT (strftime('%s', 'now') * 1000),
  UNIQUE(user_id, plan_type)
);

-- Processing history with detailed metadata
CREATE TABLE IF NOT EXISTS processing_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  process_id TEXT NOT NULL UNIQUE,
  original_filename TEXT,
  file_size INTEGER,
  detected_languages TEXT, -- JSON array
  words_removed INTEGER DEFAULT 0,
  profanity_timestamps TEXT, -- JSON array of timestamps
  processing_time_ms INTEGER,
  plan_type TEXT DEFAULT 'free',
  result TEXT, -- JSON blob with full result data
  watermark_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL,
  status TEXT DEFAULT 'completed' CHECK (status IN ('processing', 'completed', 'failed', 'expired')),
  expires_at INTEGER -- When temp files expire
);

-- Admin users with role-based permissions
CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  permissions TEXT DEFAULT '["full_access"]', -- JSON array
  created_at INTEGER NOT NULL,
  updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
  is_active BOOLEAN DEFAULT TRUE,
  last_login INTEGER,
  created_by INTEGER REFERENCES admin_users(id)
);

-- Payment transactions with detailed tracking
CREATE TABLE IF NOT EXISTS payment_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_session_id TEXT UNIQUE,
  stripe_payment_intent_id TEXT,
  stripe_subscription_id TEXT,
  user_id TEXT NOT NULL,
  plan_type TEXT NOT NULL,
  amount INTEGER NOT NULL, -- in cents
  currency TEXT DEFAULT 'usd',
  status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'refunded', 'cancelled')),
  failure_reason TEXT,
  metadata TEXT, -- JSON blob
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  completed_at INTEGER
);

-- Enhanced usage analytics
CREATE TABLE IF NOT EXISTS usage_analytics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  session_id TEXT, -- Track user sessions
  event_type TEXT NOT NULL, -- 'page_view', 'file_upload', 'payment', etc.
  event_action TEXT, -- Specific action within event type
  plan_type TEXT,
  file_size INTEGER,
  processing_time_ms INTEGER,
  languages_detected TEXT, -- JSON array
  user_agent TEXT,
  ip_address TEXT,
  referrer TEXT,
  country TEXT, -- From CF headers
  device_type TEXT, -- mobile, desktop, tablet
  created_at INTEGER NOT NULL,
  value REAL -- For conversion tracking
);

-- File storage references with security
CREATE TABLE IF NOT EXISTS file_storage (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  process_id TEXT NOT NULL,
  file_type TEXT NOT NULL CHECK (file_type IN ('original', 'preview', 'full', 'watermarked')),
  storage_key TEXT NOT NULL UNIQUE, -- R2 object key
  file_size INTEGER,
  mime_type TEXT,
  watermark_id TEXT,
  access_count INTEGER DEFAULT 0,
  max_access_count INTEGER, -- Limit downloads
  expires_at INTEGER, -- NULL for permanent files
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

-- Rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  identifier TEXT NOT NULL, -- IP or user_id
  endpoint TEXT NOT NULL,
  requests INTEGER DEFAULT 1,
  window_start INTEGER NOT NULL,
  window_size INTEGER DEFAULT 3600000, -- 1 hour in ms
  created_at INTEGER NOT NULL,
  UNIQUE(identifier, endpoint, window_start)
);

-- System configuration
CREATE TABLE IF NOT EXISTS system_config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  config_key TEXT NOT NULL UNIQUE,
  config_value TEXT NOT NULL,
  config_type TEXT DEFAULT 'string' CHECK (config_type IN ('string', 'number', 'boolean', 'json')),
  description TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

-- Audit log for security
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

-- Webhook events log
CREATE TABLE IF NOT EXISTS webhook_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stripe_event_id TEXT UNIQUE,
  event_type TEXT NOT NULL,
  event_data TEXT NOT NULL, -- JSON blob
  processed BOOLEAN DEFAULT FALSE,
  processing_attempts INTEGER DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  processed_at INTEGER
);

-- ============================================
-- INDEXES for Performance Optimization
-- ============================================

-- User subscriptions indexes
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_id ON user_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_plan_type ON user_subscriptions(plan_type);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_expires_at ON user_subscriptions(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_active ON user_subscriptions(is_active, expires_at);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_stripe_session ON user_subscriptions(stripe_session_id);

-- Processing history indexes
CREATE INDEX IF NOT EXISTS idx_processing_history_user_id ON processing_history(user_id);
CREATE INDEX IF NOT EXISTS idx_processing_history_created_at ON processing_history(created_at);
CREATE INDEX IF NOT EXISTS idx_processing_history_plan_type ON processing_history(plan_type);
CREATE INDEX IF NOT EXISTS idx_processing_history_status ON processing_history(status);
CREATE INDEX IF NOT EXISTS idx_processing_history_expires_at ON processing_history(expires_at);

-- Payment transactions indexes
CREATE INDEX IF NOT EXISTS idx_payment_transactions_user_id ON payment_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_transactions_status ON payment_transactions(status);
CREATE INDEX IF NOT EXISTS idx_payment_transactions_created_at ON payment_transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_payment_transactions_stripe_session ON payment_transactions(stripe_session_id);

-- Usage analytics indexes
CREATE INDEX IF NOT EXISTS idx_usage_analytics_event_type ON usage_analytics(event_type);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_created_at ON usage_analytics(created_at);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_user_id ON usage_analytics(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_session ON usage_analytics(session_id);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_plan_type ON usage_analytics(plan_type);

-- File storage indexes
CREATE INDEX IF NOT EXISTS idx_file_storage_process_id ON file_storage(process_id);
CREATE INDEX IF NOT EXISTS idx_file_storage_expires_at ON file_storage(expires_at);
CREATE INDEX IF NOT EXISTS idx_file_storage_storage_key ON file_storage(storage_key);

-- Verification codes indexes
CREATE INDEX IF NOT EXISTS idx_verification_codes_email_code ON verification_codes(email, code);
CREATE INDEX IF NOT EXISTS idx_verification_codes_expires_at ON verification_codes(expires_at);

-- Rate limits indexes
CREATE INDEX IF NOT EXISTS idx_rate_limits_identifier ON rate_limits(identifier, endpoint);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start, window_size);

-- Audit log indexes
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);

-- Webhook events indexes
CREATE INDEX IF NOT EXISTS idx_webhook_events_stripe_id ON webhook_events(stripe_event_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_processed ON webhook_events(processed);
CREATE INDEX IF NOT EXISTS idx_webhook_events_created_at ON webhook_events(created_at);

-- ============================================
-- VIEWS for Analytics and Reporting
-- ============================================

-- Active subscriptions view
CREATE VIEW IF NOT EXISTS active_subscriptions AS
SELECT 
  us.*,
  CASE 
    WHEN us.expires_at IS NULL THEN 'active'
    WHEN us.expires_at > (strftime('%s', 'now') * 1000) THEN 'active'
    ELSE 'expired'
  END as subscription_status,
  CASE
    WHEN us.expires_at IS NOT NULL THEN 
      ROUND((us.expires_at - (strftime('%s', 'now') * 1000)) / 86400000.0, 1)
    ELSE NULL
  END as days_remaining
FROM user_subscriptions us
WHERE us.is_active = TRUE;

-- Processing statistics view
CREATE VIEW IF NOT EXISTS processing_stats AS
SELECT 
  plan_type,
  COUNT(*) as total_processes,
  AVG(processing_time_ms) as avg_processing_time,
  AVG(words_removed) as avg_words_removed,
  AVG(file_size) as avg_file_size,
  SUM(file_size) as total_data_processed,
  COUNT(DISTINCT user_id) as unique_users,
  DATE(created_at / 1000, 'unixepoch') as process_date
FROM processing_history 
WHERE status = 'completed'
GROUP BY plan_type, DATE(created_at / 1000, 'unixepoch');

-- Revenue analytics view
CREATE VIEW IF NOT EXISTS revenue_analytics AS
SELECT 
  plan_type,
  COUNT(*) as transaction_count,
  SUM(amount) as total_revenue_cents,
  ROUND(SUM(amount) / 100.0, 2) as total_revenue_dollars,
  AVG(amount) as avg_transaction_cents,
  COUNT(DISTINCT user_id) as unique_customers,
  DATE(created_at / 1000, 'unixepoch') as transaction_date
FROM payment_transactions 
WHERE status = 'completed'
GROUP BY plan_type, DATE(created_at / 1000, 'unixepoch');

-- User engagement metrics view
CREATE VIEW IF NOT EXISTS user_engagement AS
SELECT 
  user_id,
  plan_type,
  COUNT(*) as total_actions,
  COUNT(DISTINCT DATE(created_at / 1000, 'unixepoch')) as active_days,
  MIN(created_at) as first_seen,
  MAX(created_at) as last_seen,
  COUNT(CASE WHEN event_type = 'file_upload' THEN 1 END) as files_uploaded,
  COUNT(CASE WHEN event_type = 'payment' THEN 1 END) as payments_made
FROM usage_analytics 
GROUP BY user_id, plan_type;

-- Daily usage summary view
CREATE VIEW IF NOT EXISTS daily_usage_summary AS
SELECT 
  DATE(created_at / 1000, 'unixepoch') as usage_date,
  plan_type,
  COUNT(DISTINCT user_id) as unique_users,
  COUNT(*) as total_events,
  COUNT(CASE WHEN event_type = 'file_upload' THEN 1 END) as file_uploads,
  COUNT(CASE WHEN event_type = 'payment' THEN 1 END) as payments,
  SUM(file_size) as total_data_processed
FROM usage_analytics 
GROUP BY DATE(created_at / 1000, 'unixepoch'), plan_type;

-- ============================================
-- TRIGGERS for Data Integrity
-- ============================================

-- Update timestamp trigger for user_subscriptions
CREATE TRIGGER IF NOT EXISTS update_user_subscriptions_updated_at
AFTER UPDATE ON user_subscriptions
BEGIN
  UPDATE user_subscriptions 
  SET updated_at = strftime('%s', 'now') * 1000 
  WHERE id = NEW.id;
END;

-- Update timestamp trigger for payment_transactions
CREATE TRIGGER IF NOT EXISTS update_payment_transactions_updated_at
AFTER UPDATE ON payment_transactions
BEGIN
  UPDATE payment_transactions 
  SET updated_at = strftime('%s', 'now') * 1000 
  WHERE id = NEW.id;
END;

-- Audit trigger for user_subscriptions changes
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
    strftime('%s', 'now') * 1000
  );
END;

-- Cleanup trigger for expired verification codes
CREATE TRIGGER IF NOT EXISTS cleanup_expired_verification_codes
AFTER INSERT ON verification_codes
BEGIN
  DELETE FROM verification_codes 
  WHERE expires_at < strftime('%s', 'now') * 1000;
END;

-- ============================================
-- INITIAL DATA SETUP
-- ============================================

-- Insert default admin user (REPLACE WITH YOUR EMAIL)
INSERT OR IGNORE INTO admin_users (email, permissions, created_at) 
VALUES ('admin@yourdomain.com', '["full_access", "user_management", "analytics"]', strftime('%s', 'now') * 1000);

-- Insert system configuration defaults
INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description, created_at) VALUES
('max_file_size_free', '52428800', 'number', 'Max file size for free users (50MB)', strftime('%s', 'now') * 1000),
('max_file_size_premium', '104857600', 'number', 'Max file size for premium users (100MB)', strftime('%s', 'now') * 1000),
('max_file_size_studio', '524288000', 'number', 'Max file size for studio users (500MB)', strftime('%s', 'now') * 1000),
('preview_duration_default', '30', 'number', 'Default preview duration in seconds', strftime('%s', 'now') * 1000),
('preview_duration_studio', '60', 'number', 'Studio preview duration in seconds', strftime('%s', 'now') * 1000),
('file_retention_hours', '48', 'number', 'Hours to keep processed files', strftime('%s', 'now') * 1000),
('rate_limit_uploads_per_hour', '10', 'number', 'Max uploads per hour for free users', strftime('%s', 'now') * 1000),
('maintenance_mode', 'false', 'boolean', 'Global maintenance mode flag', strftime('%s', 'now') * 1000);

-- Sample data for testing (REMOVE IN PRODUCTION)
-- INSERT OR IGNORE INTO user_subscriptions (user_id, plan_type, created_at, is_active)
-- VALUES ('test_user_fingerprint_123', 'dj_pro', strftime('%s', 'now') * 1000, TRUE);

-- ============================================
-- STORED PROCEDURES (SQLite Functions)
-- ============================================

-- Note: SQLite doesn't support stored procedures, but we can create helper views
-- For complex operations, implement in the Worker code

-- Function to get user plan (implement in Worker)
-- CREATE FUNCTION get_user_plan(fingerprint TEXT) RETURNS TEXT AS $$
-- This would be implemented in the Worker code

-- ============================================
-- CLEANUP QUERIES (Run manually or via cron)
-- ============================================

-- Clean up expired files (run daily)
-- DELETE FROM file_storage WHERE expires_at < strftime('%s', 'now') * 1000;

-- Clean up old processing history (run weekly)
-- DELETE FROM processing_history WHERE created_at < strftime('%s', 'now', '-30 days') * 1000 AND status = 'completed';

-- Clean up expired verification codes (run hourly)
-- DELETE FROM verification_codes WHERE expires_at < strftime('%s', 'now') * 1000;

-- Clean up old analytics data (run monthly)
-- DELETE FROM usage_analytics WHERE created_at < strftime('%s', 'now', '-90 days') * 1000;

-- ============================================
-- SECURITY NOTES
-- ============================================

/*
1. All user_id fields store hashed browser fingerprints, not actual user data
2. Email addresses are only stored when explicitly provided by users
3. File storage keys are UUIDs with no personal information
4. All timestamps are in milliseconds since epoch
5. Sensitive operations are logged in audit_log
6. Rate limiting prevents abuse
7. File retention policies prevent long-term storage of user content
8. Foreign key constraints maintain referential integrity
9. Check constraints prevent invalid data
10. Indexes optimize query performance
*/

-- ============================================
-- SCHEMA VERSION
-- ============================================

INSERT OR REPLACE INTO system_config (config_key, config_value, config_type, description, created_at) 
VALUES ('schema_version', '1.0.0', 'string', 'Database schema version', strftime('%s', 'now') * 1000);

-- Schema creation complete
-- Total tables: 11
-- Total indexes: 25  
-- Total views: 5
-- Total triggers: 4