#!/usr/bin/env python3
"""
Database Test Setup Script
Run this to ensure your test database has the correct data
"""

import mysql.connector
import json
import bcrypt
from datetime import datetime, timedelta

def setup_test_database():
    """Set up test database with proper data"""
    
    db_config = {
        'host': 'localhost',
        'user': 'root',
        'password': 'your_new_password',  # Update with your MySQL password
        'database': 'advanced_auth'
    }
    
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        print("🔧 Setting up test database...")
        
        # 1. Create admin user
        admin_password = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        cursor.execute("""
            INSERT IGNORE INTO admin_users (username, password_hash, role, is_active) 
            VALUES (%s, %s, %s, %s)
        """, ('admin', admin_password, 'super_admin', 1))
        
        # 2. Create test customer
        test_password = bcrypt.hashpw('test123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        cursor.execute("""
            INSERT IGNORE INTO users (username, email, password_hash, is_active, email_verified) 
            VALUES (%s, %s, %s, %s, %s)
        """, ('testuser', 'test@example.com', test_password, 1, 1))
        
        # 3. Create sample product
        cursor.execute("""
            INSERT IGNORE INTO products (name, slug, description, max_concurrent_sessions, anti_analysis_enabled, is_active) 
            VALUES (%s, %s, %s, %s, %s, %s)
        """, ('Sample Product', 'sample-product', 'Test product for development', 3, 1, 1))
        
        # 4. Get IDs
        cursor.execute("SELECT id FROM users WHERE username = 'testuser'")
        user_result = cursor.fetchone()
        if not user_result:
            raise Exception("Failed to create test user")
        user_id = user_result[0]
        
        cursor.execute("SELECT id FROM products WHERE slug = 'sample-product'")
        product_result = cursor.fetchone()
        if not product_result:
            raise Exception("Failed to create test product")
        product_id = product_result[0]
        
        # 5. Create test licenses
        test_licenses = [
            ('TEST-1234-5678-9012', 1, None),  # Lifetime, no expiry
            ('PREM-1234-5678-9012', 0, datetime.now() + timedelta(days=30)),  # 30 day license
            ('BASIC-1234-ABCD-5678', 0, datetime.now() + timedelta(days=7)),   # 7 day license
            ('VIP-LIFE-TIME-2024', 1, None),   # Another lifetime
        ]
        
        for license_key, is_lifetime, expires_at in test_licenses:
            cursor.execute("""
                INSERT IGNORE INTO user_licenses (
                    user_id, product_id, license_key, is_lifetime, is_active, created_at, expires_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, product_id, license_key, is_lifetime, 1, datetime.now(), expires_at))
        
        conn.commit()
        
        # 6. Verify and create test config
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
            raise Exception("No licenses created!")
        
        # 7. Generate working test config
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
        
        print(f"✅ Created {len(licenses)} test licenses:")
        for license in licenses:
            print(f"  • {license[0]} ({license[4]}) - User: {license[3]}")
        
        print(f"✅ Test database setup complete!")
        print(f"✅ Generated working_test_config.json")
        print(f"\n🔑 Test Credentials:")
        print(f"  Admin: admin / admin123")
        print(f"  Customer: testuser / test123")
        
    except Exception as e:
        print(f"❌ Database setup error: {e}")
        conn.rollback()
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    setup_test_database()
    