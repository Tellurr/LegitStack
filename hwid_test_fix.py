#!/usr/bin/env python3
"""
HWID Test Configuration Fix
Run this to update test HWIDs to avoid override conflicts
"""

import json
import mysql.connector
from datetime import datetime

def fix_test_hwids():
    """Update test HWIDs to use formats that won't trigger overrides"""
    
    # Database connection
    db_config = {
        'host': 'localhost',
        'user': 'root', 
        'password': 'your_new_password',  # Update with your password
        'database': 'advanced_auth'
    }
    
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        # Find test licenses that might be causing issues
        cursor.execute("""
            SELECT id, license_key, hwid, product_id
            FROM user_licenses 
            WHERE hwid LIKE 'HWID_TEST%' OR hwid LIKE 'TEST_%'
        """)
        
        test_licenses = cursor.fetchall()
        
        print(f"Found {len(test_licenses)} test licenses to fix")
        
        # Update HWIDs to use non-conflicting format
        for license_id, license_key, old_hwid, product_id in test_licenses:
            # Generate new HWID that won't trigger override
            new_hwid = f"BOUND_{license_key[-8:].upper()}"
            
            cursor.execute("""
                UPDATE user_licenses 
                SET hwid = ?
                WHERE id = ?
            """, (new_hwid, license_id))
            
            print(f"  Updated {license_key}: {old_hwid} -> {new_hwid}")
        
        conn.commit()
        print(f"✅ Fixed {len(test_licenses)} test HWIDs")
        
        # Update working test config
        cursor.execute("""
            SELECT ul.license_key, ul.hwid, ul.is_lifetime, u.username, p.name as product
            FROM user_licenses ul
            JOIN users u ON ul.user_id = u.id  
            JOIN products p ON ul.product_id = p.id
            WHERE ul.is_active = 1
        """)
        
        valid_licenses = []
        for row in cursor.fetchall():
            valid_licenses.append({
                'license_key': row[0],
                'hwid': row[1],
                'is_lifetime': bool(row[2]),
                'user': row[3],
                'product': row[4]
            })
        
        # Save updated config
        config = {'valid_licenses': valid_licenses}
        with open('working_test_config.json', 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Updated working_test_config.json with {len(valid_licenses)} licenses")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    fix_test_hwids()