
-- Run this SQL to set up proper test data
-- init_test_data.sql

-- First, ensure we have the admin user
INSERT IGNORE INTO admin_users (username, password_hash, role, is_active) VALUES 
('admin', '$2b$12$HoKKxWwU1bmQYRCDD0FO8OsPdRREKZY8p6rW5VbGyUuoGb4P8Wi7i', 'super_admin', 1);

-- Create test customer user
INSERT IGNORE INTO users (username, email, password_hash, is_active, email_verified) VALUES 
('testuser', 'test@example.com', '$2b$12$IllF4tFKD2mbPR7IJmVmAeEm53zuVv0PAW0LqyOpbj3yL7SywH8Q2', 1, 1);

-- Create a sample product
INSERT IGNORE INTO products (name, slug, description, max_concurrent_sessions, anti_analysis_enabled, is_active) VALUES 
('Sample Product', 'sample-product', 'Test product for development', 3, 1, 1);

-- Get the user and product IDs
SET @user_id = (SELECT id FROM users WHERE username = 'testuser' LIMIT 1);
SET @product_id = (SELECT id FROM products WHERE slug = 'sample-product' LIMIT 1);

-- Create working test license
INSERT IGNORE INTO user_licenses (
    user_id, 
    product_id, 
    license_key, 
    is_lifetime, 
    is_active,
    created_at,
    expires_at
) VALUES (
    @user_id,
    @product_id,
    'TEST-1234-5678-9012',
    1,  -- Lifetime license
    1,  -- Active
    NOW(),
    NULL -- No expiry for lifetime
);

-- Add more test licenses for comprehensive testing
INSERT IGNORE INTO user_licenses (
    user_id, 
    product_id, 
    license_key, 
    is_lifetime, 
    is_active,
    created_at,
    expires_at
) VALUES 
(@user_id, @product_id, 'PREM-1234-5678-9012', 0, 1, NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY)),
(@user_id, @product_id, 'BASIC-1234-ABCD-5678', 0, 1, NOW(), DATE_ADD(NOW(), INTERVAL 7 DAY)),
(@user_id, @product_id, 'VIP-LIFE-TIME-2024', 1, 1, NOW(), NULL);

-- Verify the data
SELECT 
    ul.license_key,
    ul.is_lifetime,
    ul.is_active,
    ul.hwid,
    u.username,
    p.name as product_name
FROM user_licenses ul
JOIN users u ON ul.user_id = u.id
JOIN products p ON ul.product_id = p.id
WHERE ul.is_active = 1;
