-- Simplified schema for local development
CREATE DATABASE IF NOT EXISTS advanced_auth;
USE advanced_auth;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_banned BOOLEAN DEFAULT FALSE,
    banned_until DATETIME NULL,
    ban_reason TEXT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Products table
CREATE TABLE IF NOT EXISTS products (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT NULL,
    price DECIMAL(10,2) DEFAULT 0.00,
    max_concurrent_sessions INT DEFAULT 1,
    anti_analysis_enabled BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- User Licenses table
CREATE TABLE IF NOT EXISTS user_licenses (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id CHAR(36) NOT NULL,
    product_id CHAR(36) NOT NULL,
    license_key VARCHAR(19) UNIQUE NOT NULL,
    hwid VARCHAR(64) NULL,
    expires_at DATETIME NULL,
    is_lifetime BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    total_auth_count INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
);

-- Auth Logs table
CREATE TABLE IF NOT EXISTS auth_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id CHAR(36) NULL,
    license_key VARCHAR(19) NULL,
    product_id CHAR(36) NULL,
    ip_address VARCHAR(45) NOT NULL,
    hwid VARCHAR(64) NULL,
    user_agent TEXT NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255) NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_license_key (license_key),
    INDEX idx_created_at (created_at)
);

-- Security Incidents table
CREATE TABLE IF NOT EXISTS security_incidents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    description TEXT NOT NULL,
    ip_address VARCHAR(45) NULL,
    metadata JSON NULL,
    resolved BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Admin Users table
CREATE TABLE IF NOT EXISTS admin_users (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('support', 'moderator', 'admin', 'super_admin') DEFAULT 'admin',
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default admin user (password: admin123)
INSERT INTO admin_users (username, email, password_hash, role) VALUES
('admin', 'admin@localhost', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewWuIRZMGKNODJQK', 'super_admin')
ON DUPLICATE KEY UPDATE username = VALUES(username);

-- Insert sample product
INSERT INTO products (name, slug, description, price) VALUES
('Sample Product', 'sample-product', 'A sample product for testing', 29.99)
ON DUPLICATE KEY UPDATE name = VALUES(name);

-- Insert sample user
INSERT INTO users (username, email, password_hash) VALUES
('testuser', 'test@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewWuIRZMGKNODJQK')
ON DUPLICATE KEY UPDATE username = VALUES(username);

-- Insert sample license
INSERT INTO user_licenses (user_id, product_id, license_key, is_lifetime) 
SELECT u.id, p.id, 'TEST-1234-5678-9012', TRUE
FROM users u, products p 
WHERE u.username = 'testuser' AND p.slug = 'sample-product'
ON DUPLICATE KEY UPDATE license_key = VALUES(license_key);
