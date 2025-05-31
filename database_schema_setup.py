#!/usr/bin/env python3
"""
Complete Database Schema Setup for LegitStack
This will create all required tables and columns
"""

import mysql.connector
import json
from datetime import datetime, timedelta

def create_database_schema():
    """Create complete database schema"""
    
    # Update this with your MySQL password
    db_config = {
        'host': 'localhost',
        'user': 'root',
        'password': 'your_new_password',  # UPDATE THIS WITH YOUR MYSQL ROOT PASSWORD
        'database': 'legitdb'
    }
    
    # SQL to create all required tables
    schema_sql = """
    -- Create admin_users table
    CREATE TABLE IF NOT EXISTS admin_users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('support', 'moderator', 'admin', 'super_admin') DEFAULT 'support',
        is_active BOOLEAN DEFAULT TRUE,
        last_login_ip VARCHAR(45),
        last_login_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );

    -- Create users table
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        is_active BOOLEAN DEFAULT TRUE,
        is_banned BOOLEAN DEFAULT FALSE,
        banned_until TIMESTAMP NULL,
        ban_reason TEXT,
        email_verified BOOLEAN DEFAULT FALSE,
        email_verification_token VARCHAR(128),
        totp_secret VARCHAR(32),
        totp_enabled BOOLEAN DEFAULT FALSE,
        analysis_flags JSON,
        last_login_ip VARCHAR(45),
        last_login_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );

    -- Create products table
    CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        slug VARCHAR(100) UNIQUE NOT NULL,
        description TEXT,
        max_concurrent_sessions INT DEFAULT 3,
        hwid_reset_interval_days INT DEFAULT 7,
        max_hwid_changes INT DEFAULT 5,
        anti_analysis_enabled BOOLEAN DEFAULT TRUE,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );

    -- Create user_licenses table
    CREATE TABLE IF NOT EXISTS user_licenses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        product_id INT NOT NULL,
        license_key VARCHAR(50) UNIQUE NOT NULL,
        hwid VARCHAR(128),
        hwid_locked_at TIMESTAMP NULL,
        is_lifetime BOOLEAN DEFAULT FALSE,
        is_active BOOLEAN DEFAULT TRUE,
        total_auth_count INT DEFAULT 0,
        hwid_changes_count INT DEFAULT 0,
        last_hwid_reset TIMESTAMP NULL,
        last_auth_ip VARCHAR(45),
        last_auth_at TIMESTAMP NULL,
        expires_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
    );

    -- Create auth_logs table
    CREATE TABLE IF NOT EXISTS auth_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        license_key VARCHAR(50),
        product_id INT,
        ip_address VARCHAR(45) NOT NULL,
        hwid VARCHAR(128),
        user_agent TEXT,
        success BOOLEAN NOT NULL,
        failure_reason VARCHAR(100),
        geo_country VARCHAR(2),
        geo_city VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_license_key (license_key),
        INDEX idx_ip_address (ip_address),
        INDEX idx_created_at (created_at),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
    );

    -- Create active_sessions table
    CREATE TABLE IF NOT EXISTS active_sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        license_id INT NOT NULL,
        session_token VARCHAR(128) UNIQUE NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        hwid VARCHAR(128),
        user_agent TEXT,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE CASCADE,
        INDEX idx_expires_at (expires_at),
        INDEX idx_session_token (session_token)
    );

    -- Create hwid_changes table
    CREATE TABLE IF NOT EXISTS hwid_changes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        license_id INT NOT NULL,
        old_hwid VARCHAR(128),
        new_hwid VARCHAR(128),
        ip_address VARCHAR(45) NOT NULL,
        change_reason VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE CASCADE
    );

    -- Create fraud_alerts table
    CREATE TABLE IF NOT EXISTS fraud_alerts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        license_id INT,
        alert_type VARCHAR(50) NOT NULL,
        severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
        description TEXT NOT NULL,
        metadata JSON,
        is_resolved BOOLEAN DEFAULT FALSE,
        resolved_by INT,
        resolved_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE SET NULL,
        FOREIGN KEY (resolved_by) REFERENCES admin_users(id) ON DELETE SET NULL
    );

    -- Create analysis_detections table
    CREATE TABLE IF NOT EXISTS analysis_detections (
        id INT AUTO_INCREMENT PRIMARY KEY,
        license_id INT NOT NULL,
        detection_flags JSON,
        suspicion_score INT NOT NULL,
        system_fingerprint JSON,
        ip_address VARCHAR(45) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE CASCADE,
        INDEX idx_suspicion_score (suspicion_score),
        INDEX idx_created_at (created_at)
    );

    -- Create downloads table
    CREATE TABLE IF NOT EXISTS downloads (
        id INT AUTO_INCREMENT PRIMARY KEY,
        product_id INT NOT NULL,
        filename VARCHAR(255) NOT NULL,
        display_name VARCHAR(255) NOT NULL,
        file_path VARCHAR(500) NOT NULL,
        file_size BIGINT,
        version VARCHAR(50),
        is_active BOOLEAN DEFAULT TRUE,
        download_count INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
    );

    -- Create download_tokens table
    CREATE TABLE IF NOT EXISTS download_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        download_id INT NOT NULL,
        token VARCHAR(128) UNIQUE NOT NULL,
        download_count INT DEFAULT 0,
        max_downloads INT DEFAULT 1,
        ip_address VARCHAR(45) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (download_id) REFERENCES downloads(id) ON DELETE CASCADE,
        INDEX idx_expires_at (expires_at),
        INDEX idx_token (token)
    );

    -- Create admin_audit_log table
    CREATE TABLE IF NOT EXISTS admin_audit_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id INT NOT NULL,
        action VARCHAR(100) NOT NULL,
        target_type VARCHAR(50),
        target_id INT,
        old_values JSON,
        new_values JSON,
        ip_address VARCHAR(45) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE,
        INDEX idx_admin_id (admin_id),
        INDEX idx_created_at (created_at)
    );
    """
    
    try:
        print("🔧 Connecting to MySQL database...")
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        print("🔧 Creating database schema...")
        
        # Execute schema creation
        for statement in schema_sql.split(';'):
            if statement.strip():
                cursor.execute(statement)
        
        conn.commit()
        print("✅ Database schema created successfully!")
        
        # Now populate with test data
        populate_test_data(cursor, conn)
        
    except mysql.connector.Error as e:
        print(f"❌ MySQL error: {e}")
        if 'conn' in locals():
            conn.rollback()
    except Exception as e:
        print(f"❌ Setup error: {e}")
        if 'conn' in locals():
            conn.rollback()
    finally:
        if 'conn' in locals():
            conn.close()

def populate_test_data(cursor, conn):
    """Populate database with test data"""
    
    print("🔧 Populating test data...")
    
    # 1. Create admin user with bcrypt hash for 'admin123'
    admin_password = '$2b$12$HoKKxWwU1bmQYRCDD0FO8OsPdRREKZY8p6rW5VbGyUuoGb4P8Wi7i'
    
    cursor.execute("""
        INSERT INTO admin_users (username, password_hash, role, is_active) 
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE 
            password_hash = VALUES(password_hash),
            role = VALUES(role),
            is_active = VALUES(is_active)
    """, ('admin', admin_password, 'super_admin', 1))
    
    print("✅ Created admin user: admin / admin123")
    
    # 2. Create test customer with bcrypt hash for 'test123'
    test_password = '$2b$12$IllF4tFKD2mbPR7IJmVmAeEm53zuVv0PAW0LqyOpbj3yL7SywH8Q2'
    
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, is_active, email_verified) 
        VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE 
            password_hash = VALUES(password_hash),
            is_active = VALUES(is_active),
            email_verified = VALUES(email_verified)
    """, ('testuser', 'test@example.com', test_password, 1, 1))
    
    print("✅ Created test user: testuser / test123")
    
    # 3. Create sample product
    cursor.execute("""
        INSERT INTO products (name, slug, description, max_concurrent_sessions, anti_analysis_enabled, is_active) 
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE 
            name = VALUES(name),
            description = VALUES(description),
            max_concurrent_sessions = VALUES(max_concurrent_sessions),
            anti_analysis_enabled = VALUES(anti_analysis_enabled),
            is_active = VALUES(is_active)
    """, ('Sample Product', 'sample-product', 'Test product for development', 3, 1, 1))
    
    print("✅ Created sample product")
    
    # 4. Get IDs
    cursor.execute("SELECT id FROM users WHERE username = 'testuser'")
    user_result = cursor.fetchone()
    if not user_result:
        raise Exception("Failed to find/create test user")
    user_id = user_result[0]
    
    cursor.execute("SELECT id FROM products WHERE slug = 'sample-product'")
    product_result = cursor.fetchone()
    if not product_result:
        raise Exception("Failed to find/create test product")
    product_id = product_result[0]
    
    # 5. Delete existing test licenses to avoid conflicts
    cursor.execute("""
        DELETE FROM user_licenses 
        WHERE license_key IN ('TEST-1234-5678-9012', 'PREM-1234-5678-9012', 'BASIC-1234-ABCD-5678', 'VIP-LIFE-TIME-2024')
    """)
    
    # 6. Create test licenses
    test_licenses = [
        ('TEST-1234-5678-9012', 1, None),  # Lifetime, no expiry
        ('PREM-1234-5678-9012', 0, datetime.now() + timedelta(days=30)),  # 30 day license
        ('BASIC-1234-ABCD-5678', 0, datetime.now() + timedelta(days=7)),   # 7 day license
        ('VIP-LIFE-TIME-2024', 1, None),   # Another lifetime
    ]
    
    for license_key, is_lifetime, expires_at in test_licenses:
        cursor.execute("""
            INSERT INTO user_licenses (
                user_id, product_id, license_key, is_lifetime, is_active, created_at, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (user_id, product_id, license_key, is_lifetime, 1, datetime.now(), expires_at))
        
        print(f"✅ Created license: {license_key}")
    
    conn.commit()
    
    # 7. Verify and create test config
    cursor.execute("""
        SELECT 
            ul.license_key,
            ul.hwid,
            ul.is_lifetime,
            u.username,
            p.name as product
        FROM user_licenses ul
        JOIN users u ON ul.user_id = u.id
        JOIN products p ON ul.product_id = p.id
        WHERE ul.is_active = 1
        ORDER BY ul.license_key
    """)
    
    licenses = cursor.fetchall()
    
    if not licenses:
        raise Exception("No licenses found after creation!")
    
    # 8. Generate working test config
    valid_licenses = []
    for license_key, hwid, is_lifetime, username, product in licenses:
        valid_licenses.append({
            'license_key': license_key,
            'hwid': hwid,
            'is_lifetime': bool(is_lifetime),
            'user': username,
            'product': product
        })
    
    config = {'valid_licenses': valid_licenses}
    
    with open('working_test_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"\n✅ Database setup complete!")
    print(f"✅ Created {len(licenses)} test licenses:")
    for license in licenses:
        hwid_status = f"HWID: {license[1]}" if license[1] else "No HWID"
        lifetime_status = "LIFETIME" if license[2] else "TIMED"
        print(f"  • {license[0]} ({license[4]}) - {lifetime_status} - {hwid_status}")
    
    print(f"✅ Generated working_test_config.json")
    print(f"\n🔑 Test Credentials:")
    print(f"  Admin: admin / admin123")
    print(f"  Customer: testuser / test123")
    print(f"\n🚀 Database is ready! Now restart your Node.js server and run tests.")

if __name__ == "__main__":
    print("🚀 LegitStack Complete Database Setup")
    print("=" * 50)
    create_database_schema()
