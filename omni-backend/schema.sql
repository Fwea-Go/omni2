-- FWEA-I Database Schema
-- This file creates the database schema for user subscriptions, processing history, and analytics

-- User subscriptions table
CREATE TABLE IF NOT EXISTS user_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    plan_type TEXT NOT NULL CHECK (plan_type IN ('free', 'single_track', 'day_pass', 'dj_pro', 'studio_elite')),
    stripe_session_id TEXT,
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    email TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
    expires_at INTEGER, -- NULL for non-expiring plans
    is_active INTEGER NOT NULL DEFAULT 1,
    cancelled_at INTEGER,
    metadata TEXT -- JSON metadata
);

-- Payment intents tracking
CREATE TABLE IF NOT EXISTS payment_intents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    plan_type TEXT NOT NULL,
    price_id TEXT NOT NULL,
    amount INTEGER,
    currency TEXT DEFAULT 'usd',
    status TEXT DEFAULT 'pending',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
    completed_at INTEGER,
    metadata TEXT -- JSON metadata
);

-- Processing history for all audio processing requests
CREATE TABLE IF NOT EXISTS processing_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    process_id TEXT NOT NULL UNIQUE,
    plan_type TEXT NOT NULL,
    file_name TEXT,
    file_size INTEGER,
    file_type TEXT,
    languages_detected TEXT, -- JSON array
    profanity_found INTEGER DEFAULT 0,
    processing_duration INTEGER, -- milliseconds
    result TEXT, -- JSON result data including URLs
    status TEXT DEFAULT 'processing', -- processing, completed, failed
    error_message TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    completed_at INTEGER
);

-- Usage analytics and event tracking
CREATE TABLE IF NOT EXISTS usage_analytics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    event_type TEXT NOT NULL, -- page_load, file_upload, processing_start, etc.
    plan_type TEXT,
    file_size INTEGER,
    processing_time INTEGER,
    languages_detected TEXT, -- JSON array
    profanity_count INTEGER,
    user_agent TEXT,
    ip_address TEXT,
    country_code TEXT,
    referrer TEXT,
    session_id TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    metadata TEXT -- JSON metadata for additional data
);

-- Admin users table
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    api_token_hash TEXT,
    permissions TEXT, -- JSON array of permissions
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    last_login_at INTEGER
);

-- Email verification codes
CREATE TABLE IF NOT EXISTS verification_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    purpose TEXT NOT NULL, -- email_verification, password_reset, etc.
    expires_at INTEGER NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    used_at INTEGER
);

-- Feature flags and configuration
CREATE TABLE IF NOT EXISTS feature_flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flag_name TEXT NOT NULL UNIQUE,
    is_enabled INTEGER NOT NULL DEFAULT 0,
    rollout_percentage INTEGER DEFAULT 0, -- 0-100
    target_plans TEXT, -- JSON array of plan types
    target_users TEXT, -- JSON array of user IDs
    metadata TEXT, -- JSON metadata
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

-- Profanity detection feedback (for improving AI models)
CREATE TABLE IF NOT EXISTS profanity_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    process_id TEXT NOT NULL,
    original_text TEXT NOT NULL,
    language_code TEXT NOT NULL,
    is_profane INTEGER NOT NULL, -- 1 = profane, 0 = not profane
    confidence_score REAL,
    user_reported INTEGER DEFAULT 0, -- 1 if user reported this
    feedback_type TEXT, -- false_positive, false_negative, correct
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_user_id ON user_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_plan_type ON user_subscriptions(plan_type);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_active ON user_subscriptions(is_active);
CREATE INDEX IF NOT EXISTS idx_user_subscriptions_created_at ON user_subscriptions(created_at);

CREATE INDEX IF NOT EXISTS idx_payment_intents_session_id ON payment_intents(session_id);
CREATE INDEX IF NOT EXISTS idx_payment_intents_user_id ON payment_intents(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_intents_status ON payment_intents(status);

CREATE INDEX IF NOT EXISTS idx_processing_history_user_id ON processing_history(user_id);
CREATE INDEX IF NOT EXISTS idx_processing_history_process_id ON processing_history(process_id);
CREATE INDEX IF NOT EXISTS idx_processing_history_created_at ON processing_history(created_at);
CREATE INDEX IF NOT EXISTS idx_processing_history_plan_type ON processing_history(plan_type);

CREATE INDEX IF NOT EXISTS idx_usage_analytics_user_id ON usage_analytics(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_event_type ON usage_analytics(event_type);
CREATE INDEX IF NOT EXISTS idx_usage_analytics_created_at ON usage_analytics(created_at);

CREATE INDEX IF NOT EXISTS idx_verification_codes_email ON verification_codes(email);
CREATE INDEX IF NOT EXISTS idx_verification_codes_code ON verification_codes(code);
CREATE INDEX IF NOT EXISTS idx_verification_codes_expires_at ON verification_codes(expires_at);

CREATE INDEX IF NOT EXISTS idx_profanity_feedback_process_id ON profanity_feedback(process_id);
CREATE INDEX IF NOT EXISTS idx_profanity_feedback_language_code ON profanity_feedback(language_code);
CREATE INDEX IF NOT EXISTS idx_profanity_feedback_created_at ON profanity_feedback(created_at);

-- Triggers for updated_at columns
CREATE TRIGGER IF NOT EXISTS update_user_subscriptions_updated_at 
    AFTER UPDATE ON user_subscriptions
    BEGIN
        UPDATE user_subscriptions 
        SET updated_at = strftime('%s', 'now') * 1000 
        WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS update_payment_intents_updated_at 
    AFTER UPDATE ON payment_intents
    BEGIN
        UPDATE payment_intents 
        SET updated_at = strftime('%s', 'now') * 1000 
        WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS update_feature_flags_updated_at 
    AFTER UPDATE ON feature_flags
    BEGIN
        UPDATE feature_flags 
        SET updated_at = strftime('%s', 'now') * 1000 
        WHERE id = NEW.id;
    END;
