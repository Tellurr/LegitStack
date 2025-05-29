#!/usr/bin/env python3
"""
Database License Checker - Verifies what license keys exist in the database
and optionally inserts missing test license keys
"""

import mysql.connector
import bcrypt
import uuid
import json
from datetime import datetime, timedelta

class DatabaseChecker:
    def __init__(self, host='localhost', user='root', password='your_new_password', database='legitdb'):
        self.config = {
            'host': host,
            'user': user,
            'password': password,
            'database': database,
            'charset': 'utf8mb4'
        }
        self.connection = None
    
    def connect(self):
        """Connect to the database"""
        try:
            self.connection = mysql.connector.connect(**self.config)
            print(f"✅ Connected to database: {self.config['database']}")
            return True
        except mysql.connector.Error as e:
            print(f"❌ Database connection failed: {e}")
            return False
    
    def check_existing_licenses(self):
        """Check what license keys currently exist in the database"""
        if not self.connection:
            return []
        
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT ul.license_key, u.username, p.name as product_name, p.slug,
                       ul.is_lifetime, ul.expires_at, ul.is_active, ul.hwid
                FROM user_licenses ul
                JOIN users u ON ul.user_id = u.id
                JOIN products p ON ul.product_id = p.id
                ORDER BY ul.created_at
            """)
            
            licenses = cursor.fetchall()
            cursor.close()
            
            print(f"\n📋 Found {len(licenses)} existing license(s):")
            print("-" * 80)
            
            for license in licenses:
                status = "🟢 ACTIVE" if license['is_active'] else "🔴 INACTIVE"
                lifetime = "🔄 LIFETIME" if license['is_lifetime'] else f"📅 Expires: {license['expires_at']}"
                hwid_status = f"🔒 HWID: {license['hwid']}" if license['hwid'] else "🔓 No HWID"
                
                print(f"License: {license['license_key']}")
                print(f"  User: {license['username']}")
                print(f"  Product: {license['product_name']} ({license['slug']})")
                print(f"  Status: {status} | {lifetime} | {hwid_status}")
                print()
            
            return licenses
            
        except mysql.connector.Error as e:
            print(f"❌ Error checking licenses: {e}")
            return []
    
    def check_products(self):
        """Check what products exist in the database"""
        if not self.connection:
            return []
        
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM products ORDER BY created_at")
            products = cursor.fetchall()
            cursor.close()
            
            print(f"\n🏷️  Found {len(products)} product(s):")
            print("-" * 50)
            
            for product in products:
                status = "🟢 ACTIVE" if product['is_active'] else "🔴 INACTIVE"
                print(f"ID: {product['id']}")
                print(f"Name: {product['name']} ({product['slug']})")
                print(f"Status: {status}")
                print(f"Price: ${product['price']}")
                print()
            
            return products
            
        except mysql.connector.Error as e:
            print(f"❌ Error checking products: {e}")
            return []
    
    def check_users(self):
        """Check what users exist in the database"""
        if not self.connection:
            return []
        
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute("SELECT id, username, email, is_banned FROM users ORDER BY created_at")
            users = cursor.fetchall()
            cursor.close()
            
            print(f"\n👥 Found {len(users)} user(s):")
            print("-" * 50)
            
            for user in users:
                status = "🚫 BANNED" if user['is_banned'] else "✅ ACTIVE"
                print(f"Username: {user['username']} | Email: {user['email']} | Status: {status}")
            
            return users
            
        except mysql.connector.Error as e:
            print(f"❌ Error checking users: {e}")
            return []
    
    def insert_missing_test_data(self):
        """Insert missing test license keys that the test script expects"""
        if not self.connection:
            return False
        
        try:
            cursor = self.connection.cursor()
            
            # First, check if we have the required products and users
            cursor.execute("SELECT COUNT(*) FROM products")
            product_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE username NOT LIKE 'admin%'")
            user_count = cursor.fetchone()[0]
            
            print(f"\n🔧 Current database state: {product_count} products, {user_count} regular users")
            
            # Create test products if they don't exist
            test_products = [
                {
                    'name': 'Premium Security Tool',
                    'slug': 'premium-security',
                    'description': 'Premium security research tool',
                    'price': 99.99
                },
                {
                    'name': 'VIP Lifetime Access',
                    'slug': 'vip-lifetime',
                    'description': 'Lifetime access to all tools',
                    'price': 499.99
                },
                {
                    'name': 'Kernel Driver Development Kit',
                    'slug': 'kernel-dev-kit',
                    'description': 'Advanced kernel development tools',
                    'price': 299.99
                },
                {
                    'name': 'DMA PCIe Analysis Tool',
                    'slug': 'dma-pcie-tool',
                    'description': 'Direct Memory Access analysis utilities',
                    'price': 199.99
                },
                {
                    'name': 'Legacy Research Tools',
                    'slug': 'legacy-tools',
                    'description': 'Legacy security research utilities',
                    'price': 49.99
                }
            ]
            
            # Insert products
            product_ids = {}
            for product in test_products:
                product_id = str(uuid.uuid4())
                cursor.execute("""
                    INSERT INTO products (id, name, slug, description, price, is_active)
                    VALUES (%s, %s, %s, %s, %s, 1)
                    ON DUPLICATE KEY UPDATE name = VALUES(name)
                """, (product_id, product['name'], product['slug'], product['description'], product['price']))
                
                # Get the actual product ID (in case it already existed)
                cursor.execute("SELECT id FROM products WHERE slug = %s", (product['slug'],))
                actual_id = cursor.fetchone()[0]
                product_ids[product['slug']] = actual_id
            
            # Create test users if they don't exist
            test_users = [
                {
                    'username': 'premium_user',
                    'email': 'premium@test.com',
                    'password': 'premium123'
                },
                {
                    'username': 'vip_user', 
                    'email': 'vip@test.com',
                    'password': 'vip123'
                },
                {
                    'username': 'kernel_user',
                    'email': 'kernel@test.com', 
                    'password': 'kernel123'
                },
                {
                    'username': 'dma_user',
                    'email': 'dma@test.com',
                    'password': 'dma123'
                },
                {
                    'username': 'legacy_user',
                    'email': 'legacy@test.com',
                    'password': 'legacy123'
                }
            ]
            
            user_ids = {}
            for user in test_users:
                user_id = str(uuid.uuid4())
                password_hash = bcrypt.hashpw(user['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                
                cursor.execute("""
                    INSERT INTO users (id, username, email, password_hash, email_verified)
                    VALUES (%s, %s, %s, %s, 1)
                    ON DUPLICATE KEY UPDATE username = VALUES(username)
                """, (user_id, user['username'], user['email'], password_hash))
                
                # Get the actual user ID
                cursor.execute("SELECT id FROM users WHERE username = %s", (user['username'],))
                result = cursor.fetchone()
                if result:
                    user_ids[user['username']] = result[0]
            
            # Insert the test license keys that the test script expects
            test_licenses = [
                {
                    'license_key': 'PREM-1234-5678-9012',
                    'user': 'premium_user',
                    'product': 'premium-security',
                    'is_lifetime': False,
                    'expires_days': 30
                },
                {
                    'license_key': 'VIP-LIFE-TIME-2024',
                    'user': 'vip_user', 
                    'product': 'vip-lifetime',
                    'is_lifetime': True,
                    'expires_days': None
                },
                {
                    'license_key': 'KERN-DEV-TEST-2024',
                    'user': 'kernel_user',
                    'product': 'kernel-dev-kit',
                    'is_lifetime': False,
                    'expires_days': 60
                },
                {
                    'license_key': 'DMA-PCIE-LEECH-2024',
                    'user': 'dma_user',
                    'product': 'dma-pcie-tool',
                    'is_lifetime': False,
                    'expires_days': 45
                },
                {
                    'license_key': 'LEGACY-TEST-1234',
                    'user': 'legacy_user',
                    'product': 'legacy-tools',
                    'is_lifetime': True,
                    'expires_days': None
                }
            ]
            
            # Insert licenses
            for license_data in test_licenses:
                license_id = str(uuid.uuid4())
                user_id = user_ids.get(license_data['user'])
                product_id = product_ids.get(license_data['product'])
                
                if not user_id or not product_id:
                    print(f"⚠️ Skipping license {license_data['license_key']} - missing user or product")
                    continue
                
                expires_at = None
                if not license_data['is_lifetime'] and license_data['expires_days']:
                    expires_at = datetime.now() + timedelta(days=license_data['expires_days'])
                
                cursor.execute("""
                    INSERT INTO user_licenses (id, user_id, product_id, license_key, is_lifetime, expires_at, is_active)
                    VALUES (%s, %s, %s, %s, %s, %s, 1)
                    ON DUPLICATE KEY UPDATE license_key = VALUES(license_key)
                """, (license_id, user_id, product_id, license_data['license_key'], 
                     license_data['is_lifetime'], expires_at))
                
                print(f"✅ Inserted license: {license_data['license_key']}")
            
            self.connection.commit()
            cursor.close()
            
            print(f"\n🎉 Successfully inserted missing test data!")
            return True
            
        except mysql.connector.Error as e:
            print(f"❌ Error inserting test data: {e}")
            if self.connection:
                self.connection.rollback()
            return False
    
    def generate_working_test_config(self):
        """Generate a configuration file with working license keys"""
        licenses = self.check_existing_licenses()
        
        if not licenses:
            print("❌ No licenses found to generate test config")
            return
        
        working_config = {
            'valid_licenses': [],
            'test_cases': []
        }
        
        for license in licenses:
            if license['is_active']:
                working_config['valid_licenses'].append({
                    'license_key': license['license_key'],
                    'product': license['product_name'],
                    'user': license['username'],
                    'is_lifetime': license['is_lifetime'],
                    'hwid': license['hwid']
                })
                
                # Generate test case
                hwid = license['hwid'] if license['hwid'] else f"TEST_{license['license_key'][-4:]}"
                working_config['test_cases'].append({
                    'name': f"{license['product_name']} License",
                    'key': license['license_key'],
                    'hwid': hwid,
                    'should_work': True
                })
        
        # Save to file
        with open('working_test_config.json', 'w') as f:
            json.dump(working_config, f, indent=2, default=str)
        
        print(f"\n💾 Generated working test config: working_test_config.json")
        print("Use this file to update your test script with actual working license keys.")
        
        return working_config
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            print("📤 Database connection closed")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Database License Checker')
    parser.add_argument('--host', default='localhost', help='MySQL host')
    parser.add_argument('--user', default='root', help='MySQL user')
    parser.add_argument('--password', default='', help='MySQL password')
    parser.add_argument('--database', default='advanced_auth', help='Database name')
    parser.add_argument('--insert-test-data', action='store_true', 
                       help='Insert missing test license keys')
    parser.add_argument('--fix-tests', action='store_true',
                       help='Insert test data and generate working config')
    
    args = parser.parse_args()
    
    checker = DatabaseChecker(args.host, args.user, args.password, args.database)
    
    if not checker.connect():
        return 1
    
    print("🔍 Checking current database state...")
    
    # Check current state
    checker.check_users()
    checker.check_products() 
    existing_licenses = checker.check_existing_licenses()
    
    if args.insert_test_data or args.fix_tests:
        print("\n🔧 Inserting missing test data...")
        if checker.insert_missing_test_data():
            print("✅ Test data insertion completed")
            # Check again to show updated state
            checker.check_existing_licenses()
        else:
            print("❌ Test data insertion failed")
            return 1
    
    if args.fix_tests or len(existing_licenses) > 0:
        checker.generate_working_test_config()
    
    checker.close()
    
    if len(existing_licenses) == 0:
        print("\n⚠️  No license keys found in database!")
        print("Run with --insert-test-data to add the expected test license keys.")
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
