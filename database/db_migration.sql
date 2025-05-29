-- Migration script for older MySQL versions (compatible with MySQL 5.7+)
-- Run this to upgrade from simplified to enhanced schema

USE legitdb;

-- Drop procedure if exists to avoid conflicts
DROP PROCEDURE IF EXISTS AddColumnIfNotExists;

-- Create procedure to safely add columns
DELIMITER $$
CREATE PROCEDURE AddColumnIfNotExists(
    IN tableName VARCHAR(100),
    IN columnName VARCHAR(100), 
    IN columnDefinition VARCHAR(500)
)
BEGIN
    DECLARE column_exists INT DEFAULT 0;
    
    SELECT COUNT(*) INTO column_exists 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = tableName 
      AND COLUMN_NAME = columnName;
    
    IF column_exists = 0 THEN
        SET @sql = CONCAT('ALTER TABLE ', tableName, ' ADD COLUMN ', columnName, ' ', columnDefinition);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
        SELECT CONCAT('Added column ', columnName, ' to ', tableName) AS result;
    ELSE
        SELECT CONCAT('Column ', columnName, ' already exists in ', tableName) AS result;
    END IF;
END$$
DELIMITER ;

-- Add missing columns to users table
CALL AddColumnIfNotExists('users', 'analysis_flags', 'TEXT NULL');
CALL AddColumnIfNotExists('users', 'totp_secret', 'VARCHAR(32) NULL');
CALL AddColumnIfNotExists('users', 'totp_enabled', 'BOOLEAN DEFAULT FALSE');
CALL AddColumnIfNotExists('users', 'email_verified', 'BOOLEAN DEFAULT FALSE');
CALL AddColumnIfNotExists('users', 'email_verification_token', 'VARCHAR(64) NULL');
CALL AddColumnIfNotExists('users', 'last_login_at', 'DATETIME NULL');
CALL AddColumnIfNotExists('users', 'last_login_ip', 'VARCHAR(45) NULL');
CALL AddColumnIfNotExists('users', 'failed_login_attempts', 'INT DEFAULT 0');

-- Add missing columns to products table
CALL AddColumnIfNotExists('products', 'max_concurrent_sessions', 'INT DEFAULT 1');
CALL AddColumnIfNotExists('products', 'hwid_reset_interval_days', 'INT DEFAULT 24');
CALL AddColumnIfNotExists('products', 'max_hwid_changes', 'INT DEFAULT 3');
CALL AddColumnIfNotExists('products', 'anti_analysis_enabled', 'BOOLEAN DEFAULT TRUE');
CALL AddColumnIfNotExists('products', 'features', 'TEXT NULL');
CALL AddColumnIfNotExists('products', 'category', 'VARCHAR(50) DEFAULT "software"');
CALL AddColumnIfNotExists('products', 'created_by_admin_id', 'CHAR(36) NULL');
CALL AddColumnIfNotExists('products', 'updated_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');

-- Add missing columns to user_licenses table
CALL AddColumnIfNotExists('user_licenses', 'hwid_locked_at', 'DATETIME NULL');
CALL AddColumnIfNotExists('user_licenses', 'last_hwid_reset', 'DATETIME NULL');
CALL AddColumnIfNotExists('user_licenses', 'hwid_changes_count', 'INT DEFAULT 0');
CALL AddColumnIfNotExists('user_licenses', 'last_auth_at', 'DATETIME NULL');
CALL AddColumnIfNotExists('user_licenses', 'last_auth_ip', 'VARCHAR(45) NULL');
CALL AddColumnIfNotExists('user_licenses', 'current_sessions', 'INT DEFAULT 0');
CALL AddColumnIfNotExists('user_licenses', 'max_daily_auths', 'INT DEFAULT 100');
CALL AddColumnIfNotExists('user_licenses', 'created_by_admin_id', 'CHAR(36) NULL');
CALL AddColumnIfNotExists('user_licenses', 'updated_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');

-- Add missing columns to auth_logs table
CALL AddColumnIfNotExists('auth_logs', 'license_id', 'CHAR(36) NULL');
CALL AddColumnIfNotExists('auth_logs', 'geo_country', 'VARCHAR(2) NULL');
CALL AddColumnIfNotExists('auth_logs', 'geo_city', 'VARCHAR(100) NULL');
CALL AddColumnIfNotExists('auth_logs', 'session_duration', 'INT NULL');
CALL AddColumnIfNotExists('auth_logs', 'analysis_score', 'INT DEFAULT 0');

-- Add missing columns to admin_users table
CALL AddColumnIfNotExists('admin_users', 'permissions', 'TEXT NULL');
CALL AddColumnIfNotExists('admin_users', 'totp_secret', 'VARCHAR(32) NULL');
CALL AddColumnIfNotExists('admin_users', 'totp_enabled', 'BOOLEAN DEFAULT FALSE');
CALL AddColumnIfNotExists('admin_users', 'last_login_at', 'DATETIME NULL');
CALL AddColumnIfNotExists('admin_users', 'last_login_ip', 'VARCHAR(45) NULL');
CALL AddColumnIfNotExists('admin_users', 'created_by_admin_id', 'CHAR(36) NULL');
CALL AddColumnIfNotExists('admin_users', 'updated_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');

-- Create missing tables (safe creation)
CREATE TABLE IF NOT EXISTS active_sessions (
    id CHAR(36) PRIMARY KEY,
    license_id CHAR(36) NOT NULL,
    session_token VARCHAR(64) UNIQUE NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    hwid VARCHAR(64) NOT NULL,
    user_agent TEXT NULL,
    geo_country VARCHAR(2) NULL,
    geo_city VARCHAR(100) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    KEY idx_session_token (session_token),
    KEY idx_license_id (license_id),
    KEY idx_expires_at (expires_at),
    KEY idx_ip_address (ip_address)
);

CREATE TABLE IF NOT EXISTS analysis_detections (
    id CHAR(36) PRIMARY KEY,
    license_id CHAR(36) NOT NULL,
    user_id CHAR(36) NULL,
    detection_flags TEXT NOT NULL,
    suspicion_score INT NOT NULL DEFAULT 0,
    system_fingerprint TEXT NULL,
    ip_address VARCHAR(45) NOT NULL,
    geo_country VARCHAR(2) NULL,
    action_taken ENUM('none', 'flagged', 'banned', 'quarantined') DEFAULT 'none',
    reviewed_by_admin_id CHAR(36) NULL,
    reviewed_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    KEY idx_license_id (license_id),
    KEY idx_user_id (user_id),
    KEY idx_suspicion_score (suspicion_score),
    KEY idx_action_taken (action_taken),
    KEY idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS downloads (
    id CHAR(36) PRIMARY KEY,
    product_id CHAR(36) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    file_key VARCHAR(512) NOT NULL,
    thumbnail_key VARCHAR(512) NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NULL,
    version VARCHAR(50) DEFAULT '1.0.0',
    description TEXT NULL,
    changelog TEXT NULL,
    is_update BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    download_count INT DEFAULT 0,
    upload_admin_id CHAR(36) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    KEY idx_product_id (product_id),
    KEY idx_version (version),
    KEY idx_active (is_active),
    KEY idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS download_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    download_id CHAR(36) NOT NULL,
    license_id CHAR(36) NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    geo_country VARCHAR(2) NULL,
    geo_city VARCHAR(100) NULL,
    download_completed BOOLEAN DEFAULT FALSE,
    download_size BIGINT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME NULL,
    
    KEY idx_user_id (user_id),
    KEY idx_download_id (download_id),
    KEY idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS download_tokens (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    download_id CHAR(36) NOT NULL,
    token VARCHAR(64) UNIQUE NOT NULL,
    max_downloads INT DEFAULT 1,
    download_count INT DEFAULT 0,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    
    KEY idx_token (token),
    KEY idx_expires_at (expires_at),
    KEY idx_user_id (user_id)
);

CREATE TABLE IF NOT EXISTS hwid_changes (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    license_id CHAR(36) NOT NULL,
    old_hwid VARCHAR(64) NULL,
    new_hwid VARCHAR(64) NULL,
    ip_address VARCHAR(45) NOT NULL,
    geo_country VARCHAR(2) NULL,
    change_reason ENUM('initial', 'user_request', 'admin_reset', 'suspicious') NOT NULL,
    admin_id CHAR(36) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    KEY idx_license_id (license_id),
    KEY idx_created_at (created_at),
    KEY idx_change_reason (change_reason)
);

CREATE TABLE IF NOT EXISTS fraud_alerts (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NULL,
    license_id CHAR(36) NULL,
    alert_type VARCHAR(50) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    description TEXT NOT NULL,
    metadata TEXT NULL,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_by_admin_id CHAR(36) NULL,
    resolved_at DATETIME NULL,
    escalated_by_admin_id CHAR(36) NULL,
    escalated_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    KEY idx_user_id (user_id),
    KEY idx_license_id (license_id),
    KEY idx_alert_type (alert_type),
    KEY idx_severity (severity),
    KEY idx_resolved (is_resolved),
    KEY idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    admin_id CHAR(36) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NULL,
    target_id CHAR(36) NULL,
    target_count INT NULL,
    old_values TEXT NULL,
    new_values TEXT NULL,
    operation_data TEXT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    KEY idx_admin_id (admin_id),
    KEY idx_action (action),
    KEY idx_target_type (target_type),
    KEY idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id CHAR(36) PRIMARY KEY,
    key_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    permissions TEXT NULL,
    rate_limit_per_hour INT DEFAULT 1000,
    is_active BOOLEAN DEFAULT TRUE,
    created_by_admin_id CHAR(36) NOT NULL,
    last_used_at DATETIME NULL,
    expires_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    KEY idx_api_key (api_key),
    KEY idx_active (is_active)
);

CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT NOT NULL,
    description TEXT NULL,
    updated_by_admin_id CHAR(36) NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    KEY idx_config_key (config_key)
);

-- Insert default system configuration (with proper JSON for older MySQL)
INSERT IGNORE INTO system_config (config_key, config_value, description) VALUES
('anti_analysis_enabled', 'true', 'Global anti-analysis detection toggle'),
('max_suspicion_score', '30', 'Maximum suspicion score before automatic ban'),
('hwid_reset_cooldown_hours', '24', 'Hours between HWID resets'),
('max_concurrent_sessions', '3', 'Default maximum concurrent sessions'),
('download_token_expiry_hours', '2', 'Download token expiry time in hours'),
('fraud_alert_retention_days', '30', 'Days to retain resolved fraud alerts'),
('auth_log_retention_days', '90', 'Days to retain authentication logs');

-- Add some indexes for better performance (safe creation)
DROP PROCEDURE IF EXISTS CreateIndexIfNotExists;

DELIMITER $
CREATE PROCEDURE CreateIndexIfNotExists(
    IN indexName VARCHAR(100),
    IN tableName VARCHAR(100),
    IN indexDefinition VARCHAR(500)
)
BEGIN
    DECLARE index_exists INT DEFAULT 0;
    
    SELECT COUNT(*) INTO index_exists 
    FROM INFORMATION_SCHEMA.STATISTICS 
    WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = tableName 
      AND INDEX_NAME = indexName;
    
    IF index_exists = 0 THEN
        SET @sql = CONCAT('CREATE INDEX ', indexName, ' ON ', tableName, ' ', indexDefinition);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
        SELECT CONCAT('Created index ', indexName, ' on ', tableName) AS result;
    ELSE
        SELECT CONCAT('Index ', indexName, ' already exists on ', tableName) AS result;
    END IF;
END$
DELIMITER ;

CALL CreateIndexIfNotExists('idx_auth_logs_composite', 'auth_logs', '(user_id, created_at, success)');
CALL CreateIndexIfNotExists('idx_user_licenses_composite', 'user_licenses', '(user_id, is_active, expires_at)');

DROP PROCEDURE CreateIndexIfNotExists;

-- Clean up the helper procedure
DROP PROCEDURE AddColumnIfNotExists;

-- Show final status
SELECT 'Migration completed successfully!' as status;
SELECT 'Tables created:' as info;
SHOW TABLES;