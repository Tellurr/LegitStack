// Save as setup_legitdb.js and run: node setup_legitdb.js

const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const fs = require('fs');

async function setupLegitDB() {
  console.log('🚀 Setting up LegitDB Authentication System\n');
  
  // Test different connection methods
  const connectionTests = [
    { name: 'Root without password', config: { host: 'localhost', user: 'root', password: '' }},
    { name: 'Root with empty password prompt', config: { host: 'localhost', user: 'root', password: '' }},
  ];
  
  let workingConnection = null;
  
  // Find working connection
  for (const test of connectionTests) {
    try {
      console.log(`⚡ Testing: ${test.name}`);
      const connection = await mysql.createConnection(test.config);
      console.log('✅ Connection successful!\n');
      workingConnection = connection;
      break;
    } catch (error) {
      console.log(`❌ Failed: ${error.message}\n`);
    }
  }
  
  if (!workingConnection) {
    console.log('❌ Could not establish database connection!');
    console.log('\n💡 Manual setup required:');
    console.log('1. Connect to MySQL: mysql -u root -p');
    console.log('2. Copy and paste the SQL setup code');
    return;
  }
  
  try {
    // Create database
    console.log('📦 Creating legitdb database...');
    await workingConnection.execute('DROP DATABASE IF EXISTS legitdb');
    await workingConnection.execute('CREATE DATABASE legitdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    await workingConnection.execute('USE legitdb');
    console.log('✅ Database created successfully');
    
    // Create tables
    console.log('🏗️  Creating tables...');
    
    // Admin Users table
    await workingConnection.execute(`
      CREATE TABLE admin_users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('support', 'moderator', 'admin', 'super_admin') DEFAULT 'admin',
        is_active BOOLEAN DEFAULT TRUE,
        last_login TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_username (username)
      )
    `);
    
    // Users table
    await workingConnection.execute(`
      CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        is_banned BOOLEAN DEFAULT FALSE,
        banned_until DATETIME NULL,
        ban_reason TEXT NULL,
        last_login_at DATETIME NULL,
        last_login_ip VARCHAR(45) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_username (username)
      )
    `);
    
    // Products table
    await workingConnection.execute(`
      CREATE TABLE products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        slug VARCHAR(100) UNIQUE NOT NULL,
        description TEXT NULL,
        price DECIMAL(10,2) DEFAULT 0.00,
        max_concurrent_sessions INT DEFAULT 1,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_slug (slug)
      )
    `);
    
    // User Licenses table
    await workingConnection.execute(`
      CREATE TABLE user_licenses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        product_id INT NOT NULL,
        license_key VARCHAR(19) UNIQUE NOT NULL,
        hwid VARCHAR(64) NULL,
        expires_at DATETIME NULL,
        is_lifetime BOOLEAN DEFAULT FALSE,
        is_active BOOLEAN DEFAULT TRUE,
        last_auth_at DATETIME NULL,
        last_auth_ip VARCHAR(45) NULL,
        total_auth_count INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
        INDEX idx_license_key (license_key)
      )
    `);
    
    // Auth Logs table
    await workingConnection.execute(`
      CREATE TABLE auth_logs (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NULL,
        license_key VARCHAR(19) NULL,
        product_id INT NULL,
        ip_address VARCHAR(45) NOT NULL,
        hwid VARCHAR(64) NULL,
        user_agent TEXT NULL,
        success BOOLEAN NOT NULL,
        failure_reason VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_license_key (license_key),
        INDEX idx_success (success)
      )
    `);
    
    // Legacy Consumers table
    await workingConnection.execute(`
      CREATE TABLE consumers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        hwid VARCHAR(255) DEFAULT '0',
        start_date VARCHAR(50) DEFAULT '0',
        product_key VARCHAR(50) NOT NULL UNIQUE,
        script_public VARCHAR(100) DEFAULT '0',
        script_private VARCHAR(100) DEFAULT '0',
        is_banned TINYINT(1) DEFAULT 0,
        ip VARCHAR(45) DEFAULT '0',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_product_key (product_key)
      )
    `);
    
    console.log('✅ Tables created successfully');
    
    // Insert default data
    console.log('📝 Inserting default data...');
    
    // Admin user
    const adminHash = await bcrypt.hash('admin123', 12);
    await workingConnection.execute(`
      INSERT INTO admin_users (username, password_hash, role) 
      VALUES ('admin', ?, 'super_admin')
    `, [adminHash]);
    
    // Test products
    await workingConnection.execute(`
      INSERT INTO products (name, slug, description, price, max_concurrent_sessions) VALUES
      ('Premium Loader', 'premium-loader', 'High-performance game loader', 29.99, 3),
      ('Basic Loader', 'basic-loader', 'Entry-level loader', 9.99, 1)
    `);
    
    // Test users  
    const userHash = await bcrypt.hash('admin123', 12);
    await workingConnection.execute(`
      INSERT INTO users (username, password_hash) VALUES
      ('testuser1', ?),
      ('testuser2', ?)
    `, [userHash, userHash]);
    
    // Test licenses
    await workingConnection.execute(`
      INSERT INTO user_licenses (user_id, product_id, license_key, is_lifetime, expires_at) VALUES
      (1, 1, 'PREM-1234-5678-9012', FALSE, DATE_ADD(NOW(), INTERVAL 30 DAY)),
      (2, 1, 'PREM-LIFE-VIP1-2024', TRUE, NULL)
    `);
    
    // Legacy test data
    await workingConnection.execute(`
      INSERT INTO consumers (product_key, script_public, script_private) VALUES
      ('TEST1-ABCD-1234', '7 Days', '0'),
      ('TEST2-EFGH-5678', '0', '30 Days'),
      ('TEST3-IJKL-9012', 'LIFETIME', 'LIFETIME'),
      ('VIP-PREMIUM-2024', 'LIFETIME', 'LIFETIME')
    `);
    
    console.log('✅ Default data inserted');
    
    // Create .env file
    const envContent = `# Database Configuration for LegitDB
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_new_password
DB_NAME=legitdb
DB_PORT=3306

# Server Configuration
PORT=3000
NODE_ENV=development

# Session Configuration
SESSION_SECRET=super-secure-session-secret-change-this-now
SESSION_NAME=auth_session

# Admin Configuration
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123

# Logging
LOG_FILE_PATH=./logs/app.log

# Application Info
APP_NAME=LegitStack Auth Panel
APP_VERSION=1.0.0
`;
    
    fs.writeFileSync('.env', envContent);
    console.log('✅ .env file created');
    
    await workingConnection.end();
    
    // Success summary
    console.log('\n🎉 LegitDB Setup Complete!\n');
    console.log('📋 Summary:');
    console.log('✅ Database: legitdb');
    console.log('✅ Admin user created');
    console.log('✅ Test data inserted');
    console.log('✅ .env file configured');
    
    console.log('\n🔑 Login Credentials:');
    console.log('Admin Username: admin');
    console.log('Admin Password: admin123');
    console.log('Customer Usernames: testuser1, testuser2');
    console.log('Customer Password: admin123');
    
    console.log('\n🌐 URLs:');
    console.log('Admin Panel: http://localhost:3000/admin/login');
    console.log('Customer Portal: http://localhost:3000/customer/login');
    
    console.log('\n🧪 Test Authentication:');
    console.log('curl "http://localhost:3000/auth.php?product_key=PREM-1234-5678-9012&hwid=test123"');
    console.log('curl "http://localhost:3000/auth.php?product_key=TEST1-ABCD-1234&hwid=test456"');
    
    console.log('\n⚡ Next Steps:');
    console.log('1. npm install (if not done)');
    console.log('2. npm start');
    console.log('3. Visit http://localhost:3000/admin/login');
    
  } catch (error) {
    console.error('❌ Setup failed:', error.message);
    console.log('\n💡 Try manual setup with the SQL script instead');
  }
}

// Check dependencies
try {
  require('mysql2');
  require('bcrypt');
} catch (error) {
  console.log('❌ Missing dependencies. Run: npm install mysql2 bcrypt');
  process.exit(1);
}

setupLegitDB();