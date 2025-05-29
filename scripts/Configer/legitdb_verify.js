// Save as verify_legitdb.js and run: node verify_legitdb.js

const mysql = require('mysql2/promise');
require('dotenv').config();

async function verifySetup() {
  console.log('🔍 Verifying LegitDB Setup\n');
  
  try {
    // Connect using .env config
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'legitdb'
    });
    
    console.log('✅ Database connection successful');
    console.log(`📦 Connected to: ${process.env.DB_NAME || 'legitdb'}\n`);
    
    // Check tables
    const tables = [
      'admin_users',
      'users', 
      'products',
      'user_licenses',
      'auth_logs',
      'consumers'
    ];
    
    console.log('🏗️  Checking tables:');
    for (const table of tables) {
      try {
        const [rows] = await connection.execute(`SELECT COUNT(*) as count FROM ${table}`);
        console.log(`✅ ${table}: ${rows[0].count} records`);
      } catch (error) {
        console.log(`❌ ${table}: ${error.message}`);
      }
    }
    
    console.log('\n👤 Admin Users:');
    const [admins] = await connection.execute('SELECT username, role, created_at FROM admin_users');
    admins.forEach(admin => {
      console.log(`✅ ${admin.username} (${admin.role}) - ${admin.created_at}`);
    });
    
    console.log('\n🛍️  Products:');
    const [products] = await connection.execute('SELECT name, slug, price FROM products');
    products.forEach(product => {
      console.log(`✅ ${product.name} (${product.slug}) - $${product.price}`);
    });
    
    console.log('\n🎫 Sample Licenses:');
    const [licenses] = await connection.execute(`
      SELECT ul.license_key, u.username, p.name as product, 
             CASE WHEN ul.is_lifetime THEN 'LIFETIME' 
                  WHEN ul.expires_at > NOW() THEN 'ACTIVE' 
                  ELSE 'EXPIRED' END as status
      FROM user_licenses ul
      JOIN users u ON ul.user_id = u.id  
      JOIN products p ON ul.product_id = p.id
      LIMIT 5
    `);
    licenses.forEach(license => {
      console.log(`✅ ${license.license_key} - ${license.username} (${license.product}) [${license.status}]`);
    });
    
    console.log('\n🔑 Legacy Test Keys:');
    const [consumers] = await connection.execute('SELECT product_key, script_public, script_private FROM consumers LIMIT 5');
    consumers.forEach(consumer => {
      console.log(`✅ ${consumer.product_key} - Public: ${consumer.script_public} | Private: ${consumer.script_private}`);
    });
    
    // Test authentication simulation
    console.log('\n🧪 Testing Authentication Logic:');
    
    // Test 1: Valid license key
    const testKey = 'PREM-1234-5678-9012';
    const [validLicense] = await connection.execute(`
      SELECT ul.*, u.username, u.is_banned, p.name as product_name
      FROM user_licenses ul
      JOIN users u ON ul.user_id = u.id
      JOIN products p ON ul.product_id = p.id  
      WHERE ul.license_key = ? AND ul.is_active = 1
    `, [testKey]);
    
    if (validLicense.length > 0) {
      const license = validLicense[0];
      console.log(`✅ License ${testKey} is valid`);
      console.log(`   User: ${license.username}`);
      console.log(`   Product: ${license.product_name}`);
      console.log(`   Status: ${license.is_lifetime ? 'LIFETIME' : 'TIMED'}`);
      console.log(`   Banned: ${license.is_banned ? 'YES' : 'NO'}`);
    } else {
      console.log(`❌ License ${testKey} not found or inactive`);
    }
    
    await connection.end();
    
    console.log('\n🎉 Verification Complete!');
    console.log('\n⚡ Ready to start server:');
    console.log('1. npm start');
    console.log('2. Visit http://localhost:3000/admin/login');
    console.log('3. Login with: admin / admin123');
    
    console.log('\n🧪 Test API endpoints:');
    console.log('curl "http://localhost:3000/auth.php?product_key=PREM-1234-5678-9012&hwid=test123"');
    console.log('curl "http://localhost:3000/auth.php?product_key=TEST1-ABCD-1234&hwid=test456"');
    
  } catch (error) {
    console.error('❌ Verification failed:', error.message);
    
    if (error.code === 'ER_BAD_DB_ERROR') {
      console.log('\n💡 Database "legitdb" does not exist. Run setup first:');
      console.log('node setup_legitdb.js');
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.log('\n💡 Database access denied. Check your .env file:');
      console.log('DB_USER=root');
      console.log('DB_PASSWORD= (empty for no password)');
    }
  }
}

verifySetup();