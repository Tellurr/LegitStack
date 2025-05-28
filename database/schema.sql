-- Enhanced Authentication System Database Schema
-- Supports anti-reversing detection, Cloudflare R2 integration, and advanced fraud detection

-- Core Users Table (Enhanced)
CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_banned BOOLEAN DEFAULT FALSE,
    banned_until DATETIME NULL,
    ban_reason TEXT NULL,
    analysis_flags JSON NULL,
    totp_secret VARCHAR(32) NULL,
    totp_enabled BOOLEAN DEFAULT FALSE,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(64) NULL,
    last_login_at DATETIME NULL,
    last_login_ip VARCHAR(45) NULL,
    failed_login_attempts INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_banned (is_banned),
    INDEX idx_email_verified (email_verified)
);

-- Products Table (New)
CREATE TABLE IF NOT EXISTS products (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT NULL,
    price DECIMAL(10,2) DEFAULT 0.00,
    max_concurrent_sessions INT DEFAULT 1,
    hwid_reset_interval_days INT DEFAULT 24,
    max_hwid_changes INT DEFAULT 3,
    anti_analysis_enabled BOOLEAN DEFAULT TRUE,
    features JSON NULL,
    category VARCHAR(50) DEFAULT 'software',
    is_active BOOLEAN DEFAULT TRUE,
    created_by_admin_id CHAR(36) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_slug (slug),
    INDEX idx_category (category),
    INDEX idx_active (is_active)
);

-- User Licenses Table (Enhanced)
CREATE TABLE IF NOT EXISTS user_licenses (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id CHAR(36) NOT NULL,
    product_id CHAR(36) NOT NULL,
    license_key VARCHAR(19) UNIQUE NOT NULL, -- Format: XXXX-XXXX-XXXX-XXXX
    hwid VARCHAR(64) NULL,
    hwid_locked_at DATETIME NULL,
    last_hwid_reset DATETIME NULL,
    hwid_changes_count INT DEFAULT 0,
    expires_at DATETIME NULL,
    is_lifetime BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    last_auth_at DATETIME NULL,
    last_auth_ip VARCHAR(45) NULL,
    total_auth_count INT DEFAULT 0,
    current_sessions INT DEFAULT 0,
    max_daily_auths INT DEFAULT 100,
    created_by_admin_id CHAR(36) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
    
    INDEX idx_license_key (license_key),
    INDEX idx_user_id (user_id),
    INDEX idx_product_id (product_id),
    INDEX idx_hwid (hwid),
    INDEX idx_expires_at (expires_at),
    INDEX idx_active (is_active)
);

-- Active Sessions Table (Enhanced)
CREATE TABLE IF NOT EXISTS active_sessions (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
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
    
    FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE CASCADE,
    
    INDEX idx_session_token (session_token),
    INDEX idx_license_id (license_id),
    INDEX idx_expires_at (expires_at),
    INDEX idx_ip_address (ip_address)
);

-- Authentication Logs Table (Enhanced)  
CREATE TABLE IF NOT EXISTS auth_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id CHAR(36) NULL,
    license_key VARCHAR(19) NULL,
    product_id CHAR(36) NULL,
    license_id CHAR(36) NULL,
    ip_address VARCHAR(45) NOT NULL,
    hwid VARCHAR(64) NULL,
    user_agent TEXT NULL,
    geo_country VARCHAR(2) NULL,
    geo_city VARCHAR(100) NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255) NULL,
    session_duration INT NULL, -- seconds
    analysis_score INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL,
    FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE SET NULL,
    
    INDEX idx_user_id (user_id),
    INDEX idx_license_key (license_key),
    INDEX idx_product_id (product_id),
    INDEX idx_ip_address (ip_address),
    INDEX idx_success (success),
    INDEX idx_created_at (created_at),
    INDEX idx_geo_country (geo_country)
);

-- Analysis Detections Table (New - Anti-Reversing)
CREATE TABLE IF NOT EXISTS analysis_detections (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    license_id CHAR(36) NOT NULL,
    user_id CHAR(36) NULL,
    detection_flags JSON NOT NULL,
    suspicion_score INT NOT NULL DEFAULT 0,
    system_fingerprint JSON NULL,
    ip_address VARCHAR(45) NOT NULL,
    geo_country VARCHAR(2) NULL,
    action_taken ENUM('none', 'flagged', 'banned', 'quarantined') DEFAULT 'none',
    reviewed_by_admin_id CHAR(36) NULL,
    reviewed_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    
    INDEX idx_license_id (license_id),
    INDEX idx_user_id (user_id),
    INDEX idx_suspicion_score (suspicion_score),
    INDEX idx_action_taken (action_taken),
    INDEX idx_created_at (created_at)
);

-- Downloads Table (New - Cloudflare R2)
CREATE TABLE IF NOT EXISTS downloads (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    product_id CHAR(36) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    file_key VARCHAR(512) NOT NULL, -- R2 object key
    thumbnail_key VARCHAR(512) NULL, -- R2 thumbnail key
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64) NULL, -- SHA-256 hash
    version VARCHAR(50) DEFAULT '1.0.0',
    description TEXT NULL,
    changelog TEXT NULL,
    is_update BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    download_count INT DEFAULT 0,
    upload_admin_id CHAR(36) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
    
    INDEX idx_product_id (product_id),
    INDEX idx_version (version),
    INDEX idx_active (is_active),
    INDEX idx_created_at (created_at)
);

-- Download Logs Table (New)
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
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (download_id) REFERENCES downloads(id) ON DELETE CASCADE,
    FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE SET NULL,
    
    INDEX idx_user_id (user_id),
    INDEX idx_download_id (download_id),
    INDEX idx_created_at (created_at)
);

-- Download Tokens Table (Enhanced)
CREATE TABLE IF NOT EXISTS download_tokens (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id CHAR(36) NOT NULL,
    download_id CHAR(36) NOT NULL,
    token VARCHAR(64) UNIQUE NOT NULL,
    max_downloads INT DEFAULT 1,
    download_count INT DEFAULT 0,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (download_id) REFERENCES downloads(id) ON DELETE CASCADE,
    
    INDEX idx_token (token),
    INDEX idx_expires_at (expires_at),
    INDEX idx_user_id (user_id)
);

-- HWID Changes Table (Enhanced)
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
    
    FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE CASCADE,
    
    INDEX idx_license_id (license_id),
    INDEX idx_created_at (created_at),
    INDEX idx_change_reason (change_reason)
);

-- Fraud Alerts Table (Enhanced)
CREATE TABLE IF NOT EXISTS fraud_alerts (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id CHAR(36) NULL,
    license_id CHAR(36) NULL,
    alert_type VARCHAR(50) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    description TEXT NOT NULL,
    metadata JSON NULL,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_by_admin_id CHAR(36) NULL,
    resolved_at DATETIME NULL,
    escalated_by_admin_id CHAR(36) NULL,
    escalated_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE SET NULL,
    
    INDEX idx_user_id (user_id),
    INDEX idx_license_id (license_id),
    INDEX idx_alert_type (alert_type),
    INDEX idx_severity (severity),
    INDEX idx_resolved (is_resolved),
    INDEX idx_created_at (created_at)
);

-- Admin Users Table (Enhanced)
CREATE TABLE IF NOT EXISTS admin_users (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('support', 'moderator', 'admin', 'super_admin') DEFAULT 'support',
    permissions JSON NULL,
    totp_secret VARCHAR(32) NULL,
    totp_enabled BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    last_login_at DATETIME NULL,
    last_login_ip VARCHAR(45) NULL,
    created_by_admin_id CHAR(36) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_username (username),
    INDEX idx_role (role),
    INDEX idx_active (is_active)
);

-- Admin Audit Log Table (New)
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    admin_id CHAR(36) NOT NULL,
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50) NULL,
    target_id CHAR(36) NULL,
    target_count INT NULL, -- for bulk operations
    old_values JSON NULL,
    new_values JSON NULL,
    operation_data JSON NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    
    INDEX idx_admin_id (admin_id),
    INDEX idx_action (action),
    INDEX idx_target_type (target_type),
    INDEX idx_created_at (created_at)
);

-- API Keys Table (New)
CREATE TABLE IF NOT EXISTS api_keys (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    key_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    permissions JSON NULL,
    rate_limit_per_hour INT DEFAULT 1000,
    is_active BOOLEAN DEFAULT TRUE,
    created_by_admin_id CHAR(36) NOT NULL,
    last_used_at DATETIME NULL,
    expires_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (created_by_admin_id) REFERENCES admin_users(id) ON DELETE CASCADE,
    
    INDEX idx_api_key (api_key),
    INDEX idx_active (is_active)
);

-- System Configuration Table (New)
CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value JSON NOT NULL,
    description TEXT NULL,
    updated_by_admin_id CHAR(36) NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_config_key (config_key)
);

-- Views for Enhanced Reporting
CREATE OR REPLACE VIEW fraud_dashboard_view AS
SELECT 
    f.id,
    f.alert_type,
    f.severity,
    f.description,
    f.is_resolved,
    f.created_at,
    u.username,
    ul.license_key,
    p.name as product_name,
    COUNT(al.id) as related_auth_attempts
FROM fraud_alerts f
LEFT JOIN users u ON f.user_id = u.id
LEFT JOIN user_licenses ul ON f.license_id = ul.id
LEFT JOIN products p ON ul.product_id = p.id
LEFT JOIN auth_logs al ON al.user_id = f.user_id AND al.created_at >= f.created_at - INTERVAL 1 HOUR
GROUP BY f.id;

CREATE OR REPLACE VIEW user_analytics_view AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.is_banned,
    COUNT(DISTINCT ul.id) as total_licenses,
    COUNT(DISTINCT al.id) as total_auth_attempts,
    COUNT(DISTINCT CASE WHEN al.success = 1 THEN al.id END) as successful_auths,
    COUNT(DISTINCT ad.id) as analysis_detections,
    MAX(al.created_at) as last_auth_attempt,
    COUNT(DISTINCT al.ip_address) as unique_ips_used
FROM users u
LEFT JOIN user_licenses ul ON u.id = ul.user_id
LEFT JOIN auth_logs al ON u.id = al.user_id
LEFT JOIN analysis_detections ad ON u.id = ad.user_id
GROUP BY u.id;

CREATE OR REPLACE VIEW product_analytics_view AS
SELECT 
    p.id,
    p.name,
    p.slug,
    p.category,
    COUNT(DISTINCT ul.id) as active_licenses,
    COUNT(DISTINCT d.id) as available_downloads,
    COUNT(DISTINCT dl.id) as total_downloads,
    COUNT(DISTINCT al.id) as total_auth_attempts,
    COUNT(DISTINCT ad.id) as analysis_detections,
    AVG(ad.suspicion_score) as avg_suspicion_score
FROM products p
LEFT JOIN user_licenses ul ON p.id = ul.product_id AND ul.is_active = 1
LEFT JOIN downloads d ON p.id = d.product_id AND d.is_active = 1
LEFT JOIN download_logs dl ON d.id = dl.download_id
LEFT JOIN auth_logs al ON p.id = al.product_id
LEFT JOIN analysis_detections ad ON ul.id = ad.license_id
GROUP BY p.id;

-- Stored Procedures for Advanced Operations
DELIMITER $$

CREATE PROCEDURE DetectRapidHwidChanges()
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE license_id CHAR(36);
    DECLARE change_count INT;
    
    DECLARE cur CURSOR FOR 
        SELECT hc.license_id, COUNT(*) as changes
        FROM hwid_changes hc
        WHERE hc.created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY hc.license_id
        HAVING changes >= 3;
    
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
    
    OPEN cur;
    
    read_loop: LOOP
        FETCH cur INTO license_id, change_count;
        IF done THEN
            LEAVE read_loop;
        END IF;
        
        -- Create fraud alert for rapid HWID changes
        INSERT INTO fraud_alerts (license_id, alert_type, severity, description, metadata)
        SELECT 
            license_id,
            'rapid_hwid_change',
            CASE 
                WHEN change_count >= 5 THEN 'critical'
                WHEN change_count >= 4 THEN 'high'
                ELSE 'medium'
            END,
            CONCAT('Rapid HWID changes detected: ', change_count, ' changes in 24 hours'),
            JSON_OBJECT('change_count', change_count, 'detection_time', NOW())
        WHERE NOT EXISTS (
            SELECT 1 FROM fraud_alerts 
            WHERE license_id = license_id 
            AND alert_type = 'rapid_hwid_change' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        );
        
    END LOOP;
    
    CLOSE cur;
END$$

CREATE PROCEDURE AnalyzeUserBehavior(IN user_id CHAR(36))
BEGIN
    DECLARE auth_frequency DECIMAL(10,2);
    DECLARE unique_ips INT;
    DECLARE suspicious_score INT DEFAULT 0;
    
    -- Calculate authentication frequency (auths per day)
    SELECT 
        COUNT(*) / DATEDIFF(NOW(), MIN(created_at)) as freq,
        COUNT(DISTINCT ip_address) as ips
    INTO auth_frequency, unique_ips
    FROM auth_logs 
    WHERE user_id = user_id AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY);
    
    -- Score based on frequency
    IF auth_frequency > 50 THEN
        SET suspicious_score = suspicious_score + 15;
    ELSEIF auth_frequency > 20 THEN
        SET suspicious_score = suspicious_score + 8;
    END IF;
    
    -- Score based on IP diversity
    IF unique_ips > 10 THEN
        SET suspicious_score = suspicious_score + 12;
    ELSEIF unique_ips > 5 THEN
        SET suspicious_score = suspicious_score + 6;
    END IF;
    
    -- Create alert if suspicious
    IF suspicious_score >= 15 THEN
        INSERT INTO fraud_alerts (user_id, alert_type, severity, description, metadata)
        VALUES (
            user_id,
            'behavioral_analysis',
            CASE WHEN suspicious_score >= 25 THEN 'high' ELSE 'medium' END,
            'Suspicious user behavior detected',
            JSON_OBJECT(
                'auth_frequency', auth_frequency,
                'unique_ips', unique_ips,
                'suspicion_score', suspicious_score
            )
        );
    END IF;
END$$

DELIMITER ;

-- Indexes for Performance Optimization
CREATE INDEX idx_auth_logs_composite ON auth_logs(user_id, created_at, success);
CREATE INDEX idx_analysis_detections_composite ON analysis_detections(license_id, suspicion_score, created_at);
CREATE INDEX idx_fraud_alerts_composite ON fraud_alerts(severity, is_resolved, created_at);
CREATE INDEX idx_user_licenses_composite ON user_licenses(user_id, is_active, expires_at);

-- Insert Default System Configuration
INSERT INTO system_config (config_key, config_value, description) VALUES
('anti_analysis_enabled', 'true', 'Global anti-analysis detection toggle'),
('max_suspicion_score', '30', 'Maximum suspicion score before automatic ban'),
('hwid_reset_cooldown_hours', '24', 'Hours between HWID resets'),
('max_concurrent_sessions', '3', 'Default maximum concurrent sessions'),
('download_token_expiry_hours', '2', 'Download token expiry time in hours'),
('fraud_alert_retention_days', '30', 'Days to retain resolved fraud alerts'),
('auth_log_retention_days', '90', 'Days to retain authentication logs')
ON DUPLICATE KEY UPDATE config_value = VALUES(config_value);

-- Insert Default Admin User (Change password in production!)
INSERT INTO admin_users (username, email, password_hash, role) VALUES
('admin', 'admin@localhost', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewWuIRZMGKNODJQK', 'super_admin')
ON DUPLICATE KEY UPDATE username = VALUES(username);

-- Create Triggers for Audit Trail
DELIMITER $$

CREATE TRIGGER user_ban_audit AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    IF OLD.is_banned != NEW.is_banned THEN
        INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, old_values, new_values, ip_address)
        VALUES (
            '00000000-0000-0000-0000-000000000000', -- System trigger
            IF(NEW.is_banned = 1, 'ban_user', 'unban_user'),
            'user',
            NEW.id,
            JSON_OBJECT('is_banned', OLD.is_banned, 'banned_until', OLD.banned_until),
            JSON_OBJECT('is_banned', NEW.is_banned, 'banned_until', NEW.banned_until),
            '127.0.0.1'
        );
    END IF;
END$$

CREATE TRIGGER license_creation_audit AFTER INSERT ON user_licenses
FOR EACH ROW
BEGIN
    INSERT INTO admin_audit_log (admin_id, action, target_type, target_id, new_values, ip_address)
    VALUES (
        COALESCE(NEW.created_by_admin_id, '00000000-0000-0000-0000-000000000000'),
        'create_license',
        'license',
        NEW.id,
        JSON_OBJECT('license_key', NEW.license_key, 'product_id', NEW.product_id, 'user_id', NEW.user_id),
        '127.0.0.1'
    );
END$$

DELIMITER ;

-- Performance Optimization: Create Partitioned Tables for Large Data
-- Partition auth_logs by month for better performance
ALTER TABLE auth_logs PARTITION BY RANGE (YEAR(created_at) * 100 + MONTH(created_at)) (
    PARTITION p202401 VALUES LESS THAN (202402),
    PARTITION p202402 VALUES LESS THAN (202403),
    PARTITION p202403 VALUES LESS THAN (202404),
    PARTITION p202404 VALUES LESS THAN (202405),
    PARTITION p202405 VALUES LESS THAN (202406),
    PARTITION p202406 VALUES LESS THAN (202407),
    PARTITION p202407 VALUES LESS THAN (202408),
    PARTITION p202408 VALUES LESS THAN (202409),
    PARTITION p202409 VALUES LESS THAN (202410),
    PARTITION p202410 VALUES LESS THAN (202411),
    PARTITION p202411 VALUES LESS THAN (202412),
    PARTITION p202412 VALUES LESS THAN (202501),
    PARTITION p_future VALUES LESS THAN MAXVALUE
);

-- Set up event scheduler for automated maintenance
SET GLOBAL event_scheduler = ON;

DELIMITER $$

CREATE EVENT IF NOT EXISTS cleanup_expired_data
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    -- Clean up expired sessions
    DELETE FROM active_sessions WHERE expires_at < NOW();
    
    -- Clean up expired download tokens
    DELETE FROM download_tokens WHERE expires_at < NOW();
    
    -- Clean up old auth logs (keep last 90 days)
    DELETE FROM auth_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
    
    -- Clean up resolved fraud alerts (keep last 30 days)
    DELETE FROM fraud_alerts 
    WHERE is_resolved = 1 AND resolved_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
    
    -- Update download counts
    UPDATE downloads d 
    SET download_count = (
        SELECT COUNT(*) FROM download_logs dl 
        WHERE dl.download_id = d.id AND dl.download_completed = 1
    );
END$$

CREATE EVENT IF NOT EXISTS analyze_user_behavior
ON SCHEDULE EVERY 2 HOUR
DO
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE user_id CHAR(36);
    
    DECLARE cur CURSOR FOR 
        SELECT DISTINCT u.id
        FROM users u
        JOIN auth_logs al ON u.id = al.user_id
        WHERE al.created_at >= DATE_SUB(NOW(), INTERVAL 2 HOUR)
        AND u.is_banned = 0;
    
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
    
    OPEN cur;
    
    read_loop: LOOP
        FETCH cur INTO user_id;
        IF done THEN
            LEAVE read_loop;
        END IF;
        
        CALL AnalyzeUserBehavior(user_id);
    END LOOP;
    
    CLOSE cur;
END$$

DELIMITER ;