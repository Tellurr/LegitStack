#!/usr/bin/env python3
"""
Database Test Setup Script for LegitStack
Run this to ensure your test database has the correct data
"""

import mysql.connector
import json
import bcrypt
from datetime import datetime, timedelta

def setup_test_database():
    """Set up test database with proper data"""
    
    # Update this with your MySQL password
    db_config = {
        'host': 'localhost',
        'user': 'root',
        'password': 'your_new_password',  # UPDATE THIS WITH YOUR MYSQL ROOT PASSWORD
        'database': 'legitdb'
    }
    
    try:
        print("🔧 Connecting to MySQL database...")
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        print("🔧 Setting up test database...")
        
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
        print(f"\n🚀 Now restart your Node.js server and run the tests!")
        
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

if __name__ == "__main__":
    print("🚀 LegitStack Database Setup")
    print("=" * 50)
    setup_test_database()
