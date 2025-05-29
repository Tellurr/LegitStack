// verify_migration.js - Run after database migration
const mysql = require('mysql2/promise');
require('dotenv').config();

async function verifyMigration() {
  console.log('🔍 Verifying Database Migration\n');
  
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'legitdb'
    });
    
    console.log('✅ Database connection successful\n');
    
    // Check all required tables exist
    const requiredTables = [
      'users', 'products', 'user_licenses', 'auth_logs', 'admin_users',
      'active_sessions', 'analysis_detections', 'downloads', 'download_logs',
      'download_tokens', 'hwid_changes', 'fraud_alerts', 'admin_audit_log',
      'api_keys', 'system_config'
    ];
    
    console.log('📋 Checking required tables:');
    for (const table of requiredTables) {
      try {
        const [rows] = await connection.execute(`SELECT COUNT(*) as count FROM ${table}`);
        console.log(`✅ ${table}: ${rows[0].count} records`);
      } catch (error) {
        console.log(`❌ ${table}: MISSING or ERROR - ${error.message}`);
      }
    }
    
    // Check specific columns that were added
    console.log('\n🔧 Checking enhanced columns:');
    
    const columnChecks = [
      { table: 'users', column: 'totp_secret' },
      { table: 'products', column: 'anti_analysis_enabled' },
      { table: 'user_licenses', column: 'hwid_changes_count' },
      { table: 'auth_logs', column: 'geo_country' },
      { table: 'admin_users', column: 'permissions' }
    ];
    
    for (const check of columnChecks) {
      try {
        await connection.execute(`SELECT ${check.column} FROM ${check.table} LIMIT 1`);
        console.log(`✅ ${check.table}.${check.column}: EXISTS`);
      } catch (error) {
        console.log(`❌ ${check.table}.${check.column}: MISSING`);
      }
    }
    
    // Check views
    console.log('\n👁️  Checking views:');
    try {
      const [rows] = await connection.execute('SELECT COUNT(*) as count FROM fraud_dashboard_view');
      console.log(`✅ fraud_dashboard_view: ${rows[0].count} records`);
    } catch (error) {
      console.log(`❌ fraud_dashboard_view: ${error.message}`);
    }
    
    // Check system config
    console.log('\n⚙️  System Configuration:');
    const [config] = await connection.execute('SELECT config_key, config_value FROM system_config');
    config.forEach(item => {
      console.log(`✅ ${item.config_key}: ${item.config_value}`);
    });
    
    // Test the admin dashboard query that was failing
    console.log('\n🎯 Testing Admin Dashboard Query:');
    try {
      const [stats] = await connection.execute(`
        SELECT 
          (SELECT COUNT(*) FROM users WHERE is_banned = 0) as active_users,
          (SELECT COUNT(*) FROM user_licenses WHERE is_active = 1) as active_licenses,
          (SELECT COUNT(*) FROM auth_logs WHERE created_at >= CURDATE()) as today_auths,
          (SELECT COUNT(*) FROM fraud_alerts WHERE is_resolved = 0) as pending_alerts
      `);
      
      console.log('✅ Admin Dashboard Query SUCCESS:');
      console.log(`   Active Users: ${stats[0].active_users}`);
      console.log(`   Active Licenses: ${stats[0].active_licenses}`);
      console.log(`   Today's Auths: ${stats[0].today_auths}`);
      console.log(`   Pending Alerts: ${stats[0].pending_alerts}`);
    } catch (error) {
      console.log(`❌ Admin Dashboard Query FAILED: ${error.message}`);
    }
    
    await connection.end();
    
    console.log('\n🎉 Migration Verification Complete!');
    console.log('\n✨ Your admin dashboard should now work properly!');
    console.log('🔗 Try accessing: http://localhost:3000/admin/login');
    
  } catch (error) {
    console.error('❌ Verification failed:', error.message);
    
    if (error.code === 'ER_BAD_DB_ERROR') {
      console.log('\n💡 Database does not exist. Check your .env configuration.');
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.log('\n💡 Access denied. Check your database credentials in .env file.');
    }
  }
}

// Run verification
verifyMigration()
  .then(() => process.exit(0))
  .catch(error => {
    console.error('Script error:', error);
    process.exit(1);
  });