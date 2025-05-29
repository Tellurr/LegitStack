// Save this as "diagnose.js" and run: node diagnose.js

console.log('🔍 Database Connection Diagnostic\n');

// Check if dotenv is installed
try {
  require('dotenv').config();
  console.log('✅ dotenv loaded');
} catch (error) {
  console.log('❌ dotenv not found - run: npm install dotenv');
  process.exit(1);
}

// Check environment variables
console.log('\n📋 Environment Variables:');
console.log('DB_HOST:', process.env.DB_HOST || '❌ NOT SET');
console.log('DB_USER:', process.env.DB_USER || '❌ NOT SET');
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '✅ SET' : '❌ NOT SET');
console.log('DB_NAME:', process.env.DB_NAME || '❌ NOT SET');

// Check if .env file exists
const fs = require('fs');
if (fs.existsSync('.env')) {
  console.log('\n✅ .env file exists');
  const envContent = fs.readFileSync('.env', 'utf8');
  console.log('📄 .env file contents:');
  envContent.split('\n').forEach(line => {
    if (line.trim() && !line.startsWith('#')) {
      const [key, value] = line.split('=');
      if (key && key.includes('PASSWORD')) {
        console.log(`${key}=***HIDDEN***`);
      } else {
        console.log(line);
      }
    }
  });
} else {
  console.log('\n❌ .env file NOT FOUND - You need to create it!');
}

// Test database connection
async function testDatabase() {
  try {
    const mysql = require('mysql2/promise');
    
    console.log('\n🔌 Testing database connection...');
    
    const config = {
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'test'
    };
    
    console.log('Connection config:', {
      host: config.host,
      user: config.user,
      password: config.password ? '***SET***' : '***NOT SET***',
      database: config.database
    });
    
    const connection = await mysql.createConnection(config);
    console.log('✅ Database connection successful!');
    
    // Test admin_users table
    try {
      const [rows] = await connection.execute('SELECT COUNT(*) as count FROM admin_users');
      console.log(`✅ Found ${rows[0].count} admin users`);
    } catch (error) {
      console.log('❌ admin_users table not found:', error.message);
    }
    
    await connection.end();
    
  } catch (error) {
    console.log('❌ Database connection failed:', error.message);
    
    if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.log('\n💡 Fix suggestions:');
      console.log('1. Check your database credentials in .env file');
      console.log('2. Make sure MySQL user exists and has correct password');
      console.log('3. Run: mysql -u ' + (process.env.DB_USER || 'root') + ' -p');
    }
    
    if (error.code === 'ECONNREFUSED') {
      console.log('\n💡 Fix suggestions:');
      console.log('1. Start MySQL: brew services start mysql (macOS)');
      console.log('2. Or: sudo systemctl start mysql (Linux)');
      console.log('3. Check if MySQL is running on port 3306');
    }
  }
}

// Check if mysql2 is installed
try {
  require('mysql2');
  console.log('\n✅ mysql2 package installed');
  testDatabase();
} catch (error) {
  console.log('\n❌ mysql2 not found - run: npm install mysql2');
}