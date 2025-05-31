#!/usr/bin/env node
const mysql = require('mysql2/promise');
require('dotenv').config();

async function validateFixes() {
    console.log('🔍 Validating Backend Fixes...');
    
    const dbConfig = {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'advanced_auth'
    };
    
    try {
        const pool = mysql.createPool(dbConfig);
        
        // Check testuser1 exists
        const [users] = await pool.execute('SELECT COUNT(*) as count FROM users WHERE username = ?', ['testuser1']);
        console.log(users[0].count > 0 ? '✅ testuser1 exists' : '❌ testuser1 missing');
        
        // Check for unbound licenses
        const [licenses] = await pool.execute('SELECT COUNT(*) as count FROM user_licenses WHERE hwid IS NULL');
        console.log(`📊 Found ${licenses[0].count} unbound licenses for HWID testing`);
        
        // Check empty HWID strings
        const [emptyHwids] = await pool.execute('SELECT COUNT(*) as count FROM user_licenses WHERE hwid = ""');
        if (emptyHwids[0].count > 0) {
            console.log(`⚠️ Found ${emptyHwids[0].count} empty string HWIDs - should be NULL`);
        } else {
            console.log('✅ No empty string HWIDs found');
        }
        
        await pool.end();
        console.log('\n🎯 Backend validation complete!');
        
    } catch (error) {
        console.error('❌ Validation error:', error.message);
    }
}

validateFixes();
