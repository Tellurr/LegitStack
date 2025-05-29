// Simplified setup_legitdb.js without email/fraud features
// ⚠️ WARNING: Password logging is a SEVERE SECURITY RISK - USE ONLY FOR TESTING!

const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ⚠️ SECURITY WARNING: This is for testing only!
const PASSWORD_LOG_FILE = './test_passwords.txt';

async function logPassword(username, plainPassword, hashedPassword, userType = 'user') {
  const logEntry = `[${new Date().toISOString()}] ${userType.toUpperCase()} - Username: ${username} | Password: ${plainPassword} | Hash: ${hashedPassword}\n`;
  
  // Append to password log file
  fs.appendFileSync(PASSWORD_LOG_FILE, logEntry);
  
  // Also create a JSON version for easier parsing
  const jsonLogFile = './test_passwords.json';
  let jsonData = [];
  
  if (fs.existsSync(jsonLogFile)) {
    jsonData = JSON.parse(fs.readFileSync(jsonLogFile, 'utf8'));
  }
  
  jsonData.push({
    timestamp: new Date().toISOString(),
    userType,
    username,
    password: plainPassword,
    hash: hashedPassword
  });
  
  fs.writeFileSync(jsonLogFile, JSON.stringify(jsonData, null, 2));
}

function generateSecurePassword(length = 12) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  let password = '';
  for (let i = 0; i < length; i++) {
    password += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return password;
}

async function setupSimplifiedLegitDB() {
  console.log('🚀 Setting up Simplified LegitDB Authentication System\n');
  console.log('⚠️  WARNING: This setup includes password logging for testing!');
  console.log('⚠️  Never use this in production!\n');
  
  // Create logs directory
  if (!fs.existsSync('./logs')) {
    fs.mkdirSync('./logs');
  }
  
  // Initialize password log
  fs.writeFileSync(PASSWORD_LOG_FILE, `=== LegitDB Test Passwords ===\n⚠️ FOR TESTING ONLY - DELETE IN PRODUCTION!\nGenerated: ${new Date().toISOString()}\n\n`);
  
  let connection = null;
  let dbConnection = null; // New connection for database operations
  
  try {
    // Connect without specifying database to create/drop database
    dbConnection = await mysql.createConnection({
      host: 'localhost',
      user: 'root',
      password: 'your_new_password'
    });
    
    console.log('✅ Connected to MySQL (for database creation)\n');
    
    // Create database
    console.log('📦 Creating legitdb database...');
    await dbConnection.execute('DROP DATABASE IF EXISTS legitdb');
    await dbConnection.execute('CREATE DATABASE legitdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    
    console.log('✅ Database legitdb created\n');
    
    // Close the initial connection
    await dbConnection.end();
    console.log('✅ Initial connection closed\n');

    // Establish a new connection specifically for the legitdb database
    connection = await mysql.createConnection({
      host: 'localhost',
      user: 'root',
      password: 'your_new_password',
      database: 'legitdb' // Specify the database here
    });
    
    console.log('✅ Connected to legitdb database\n');

    // Create all tables (simplified - no email/fraud)
    console.log('🏗️  Creating table structure...');
    
    // Admin Users table (no email)
    await connection.execute(`
      CREATE TABLE admin_users (
        id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('support', 'moderator', 'admin', 'super_admin') DEFAULT 'support',
        permissions JSON NULL,
        totp_secret VARCHAR(32) NULL,
        totp_enabled BOOLEAN DEFAULT FALSE,
        is_active BOOLEAN DEFAULT TRUE,
        last_login_at DATETIME NULL,
        last_login_ip VARCHAR(45) NULL,
        created_by_admin_id CHAR(36) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_username (username),
        INDEX idx_role (role),
        INDEX idx_active (is_active)
      )
    `);
    
    // Users table (no email)
    await connection.execute(`
      CREATE TABLE users (
        id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        is_banned BOOLEAN DEFAULT FALSE,
        banned_until DATETIME NULL,
        ban_reason TEXT NULL,
        analysis_flags JSON NULL,
        totp_secret VARCHAR(32) NULL,
        totp_enabled BOOLEAN DEFAULT FALSE,
        last_login_at DATETIME NULL,
        last_login_ip VARCHAR(45) NULL,
        failed_login_attempts INT DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_username (username),
        INDEX idx_banned (is_banned)
      )
    `);
    
    // Products table
    await connection.execute(`
      CREATE TABLE products (
        id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
        name VARCHAR(255) NOT NULL,
        slug VARCHAR(100) UNIQUE NOT NULL,
        description TEXT NULL,
        price DECIMAL(10,2) DEFAULT 0.00,
        max_concurrent_sessions INT DEFAULT 1,
        hwid_reset_interval_days INT DEFAULT 24,
        max_hwid_changes INT DEFAULT 3,
        anti_analysis_enabled BOOLEAN DEFAULT TRUE,
        features JSON NULL,
        category VARCHAR(50) DEFAULT 'software',
        is_active BOOLEAN DEFAULT TRUE,
        created_by_admin_id CHAR(36) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_slug (slug),
        INDEX idx_active (is_active)
      )
    `);
    
    // User Licenses table
    await connection.execute(`
      CREATE TABLE user_licenses (
        id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
        user_id CHAR(36) NOT NULL,
        product_id CHAR(36) NOT NULL,
        license_key VARCHAR(19) UNIQUE NOT NULL,
        hwid VARCHAR(64) NULL,
        hwid_locked_at DATETIME NULL,
        last_hwid_reset DATETIME NULL,
        hwid_changes_count INT DEFAULT 0,
        expires_at DATETIME NULL,
        is_lifetime BOOLEAN DEFAULT FALSE,
        is_active BOOLEAN DEFAULT TRUE,
        last_auth_at DATETIME NULL,
        last_auth_ip VARCHAR(45) NULL,
        total_auth_count INT DEFAULT 0,
        current_sessions INT DEFAULT 0,
        max_daily_auths INT DEFAULT 100,
        created_by_admin_id CHAR(36) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
        INDEX idx_license_key (license_key),
        INDEX idx_user_id (user_id),
        INDEX idx_hwid (hwid),
        INDEX idx_active (is_active)
      )
    `);
    
    // Active Sessions table
    await connection.execute(`
      CREATE TABLE active_sessions (
        id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
        license_id CHAR(36) NOT NULL,
        session_token VARCHAR(64) UNIQUE NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        hwid VARCHAR(64) NOT NULL,
        user_agent TEXT NULL,
        geo_country VARCHAR(2) NULL,
        geo_city VARCHAR(100) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE CASCADE,
        INDEX idx_session_token (session_token),
        INDEX idx_expires_at (expires_at)
      )
    `);
    
    // Auth Logs table
    await connection.execute(`
      CREATE TABLE auth_logs (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        user_id CHAR(36) NULL,
        license_key VARCHAR(19) NULL,
        product_id CHAR(36) NULL,
        license_id CHAR(36) NULL,
        ip_address VARCHAR(45) NOT NULL,
        hwid VARCHAR(64) NULL,
        user_agent TEXT NULL,
        geo_country VARCHAR(2) NULL,
        geo_city VARCHAR(100) NULL,
        success BOOLEAN NOT NULL,
        failure_reason VARCHAR(255) NULL,
        session_duration INT NULL,
        analysis_score INT DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL,
        INDEX idx_license_key (license_key),
        INDEX idx_success (success),
        INDEX idx_created_at (created_at)
      )
    `);
    
    // Analysis Detections table (Anti-cheat/Anti-reverse)
    await connection.execute(`
      CREATE TABLE analysis_detections (
        id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
        license_id CHAR(36) NOT NULL,
        user_id CHAR(36) NULL,
        detection_flags JSON NOT NULL,
        suspicion_score INT NOT NULL DEFAULT 0,
        system_fingerprint JSON NULL,
        ip_address VARCHAR(45) NOT NULL,
        geo_country VARCHAR(2) NULL,
        action_taken ENUM('none', 'flagged', 'banned', 'quarantined') DEFAULT 'none',
        reviewed_by_admin_id CHAR(36) NULL,
        reviewed_at DATETIME NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        INDEX idx_suspicion_score (suspicion_score),
        INDEX idx_action_taken (action_taken)
      )
    `);
    
    // HWID Changes table
    await connection.execute(`
      CREATE TABLE hwid_changes (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        license_id CHAR(36) NOT NULL,
        old_hwid VARCHAR(64) NULL,
        new_hwid VARCHAR(64) NULL,
        ip_address VARCHAR(45) NOT NULL,
        geo_country VARCHAR(2) NULL,
        change_reason ENUM('initial', 'user_request', 'admin_reset', 'suspicious') NOT NULL,
        admin_id CHAR(36) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (license_id) REFERENCES user_licenses(id) ON DELETE CASCADE,
        INDEX idx_license_id (license_id),
        INDEX idx_created_at (created_at)
      )
    `);
    
    // Security Incidents table
    await connection.execute(`
      CREATE TABLE security_incidents (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        type VARCHAR(50) NOT NULL,
        severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
        description TEXT NOT NULL,
        ip_address VARCHAR(45) NULL,
        metadata JSON NULL,
        resolved BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Downloads table (for protected files)
    await connection.execute(`
      CREATE TABLE downloads (
        id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
        product_id CHAR(36) NOT NULL,
        filename VARCHAR(255) NOT NULL,
        display_name VARCHAR(255) NOT NULL,
        file_key VARCHAR(512) NOT NULL,
        thumbnail_key VARCHAR(512) NULL,
        file_size BIGINT NOT NULL,
        file_hash VARCHAR(64) NULL,
        version VARCHAR(50) DEFAULT '1.0.0',
        description TEXT NULL,
        changelog TEXT NULL,
        is_update BOOLEAN DEFAULT FALSE,
        is_active BOOLEAN DEFAULT TRUE,
        download_count INT DEFAULT 0,
        upload_admin_id CHAR(36) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
        INDEX idx_product_id (product_id),
        INDEX idx_active (is_active)
      )
    `);
    
    // Download Logs table
    await connection.execute(`
      CREATE TABLE download_logs (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        user_id CHAR(36) NOT NULL,
        download_id CHAR(36) NOT NULL,
        license_id CHAR(36) NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT NULL,
        geo_country VARCHAR(2) NULL,
        geo_city VARCHAR(100) NULL,
        download_completed BOOLEAN DEFAULT FALSE,
        download_size BIGINT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (download_id) REFERENCES downloads(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id),
        INDEX idx_created_at (created_at)
      )
    `);
    
    // Admin Audit Log table
    await connection.execute(`
      CREATE TABLE admin_audit_log (
        id BIGINT AUTO_INCREMENT PRIMARY KEY,
        admin_id CHAR(36) NOT NULL,
        action VARCHAR(100) NOT NULL,
        target_type VARCHAR(50) NULL,
        target_id CHAR(36) NULL,
        target_count INT NULL,
        old_values JSON NULL,
        new_values JSON NULL,
        operation_data JSON NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admin_users(id) ON DELETE CASCADE,
        INDEX idx_admin_id (admin_id),
        INDEX idx_action (action),
        INDEX idx_created_at (created_at)
      )
    `);
    
    // System Config table
    await connection.execute(`
      CREATE TABLE system_config (
        id INT AUTO_INCREMENT PRIMARY KEY,
        config_key VARCHAR(100) UNIQUE NOT NULL,
        config_value JSON NOT NULL,
        description TEXT NULL,
        updated_by_admin_id CHAR(36) NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_config_key (config_key)
      )
    `);
    
    // Legacy consumers table (for backwards compatibility)
    await connection.execute(`
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
    
    console.log('✅ All tables created successfully\n');
    
    // Insert test data with password logging
    console.log('📝 Inserting test data with password logging...\n');
    
    // Admin users with different roles
    const adminUsers = [
      { username: 'admin', password: 'admin123', role: 'super_admin' },
      { username: 'moderator', password: 'mod123456', role: 'moderator' },
      { username: 'support', password: 'support789', role: 'support' }
    ];
    
    for (const admin of adminUsers) {
      const hash = await bcrypt.hash(admin.password, 12);
      await connection.execute(`
        INSERT INTO admin_users (username, password_hash, role) 
        VALUES (?, ?, ?)
      `, [admin.username, hash, admin.role]);
      
      await logPassword(admin.username, admin.password, hash, 'admin');
      console.log(`✅ Created admin: ${admin.username} (${admin.role})`);
    }
    
    // Test products for anti-cheat/security research
    const products = await connection.execute(`
      INSERT INTO products (name, slug, description, price, anti_analysis_enabled) VALUES
      ('Premium Loader', 'premium-loader', 'Advanced game loader with anti-analysis', 49.99, TRUE),
      ('Basic Loader', 'basic-loader', 'Entry-level loader', 19.99, FALSE),
      ('VIP Package', 'vip-package', 'All-inclusive package', 99.99, TRUE),
      ('Anti-Cheat Bypass', 'ac-bypass', 'Advanced bypass tool', 149.99, TRUE),
      ('Kernel Driver', 'kernel-driver', 'Ring 0 access tool', 299.99, TRUE),
      ('DMA Tool', 'dma-tool', 'DMA attack framework', 499.99, TRUE)
    `);
    
    // Test users with varied passwords (pentester/researcher focused)
// Fix for the UUID foreign key constraint issue
// Replace the user creation section in setup_legitdb.js with this:

// Test users with varied passwords (pentester/researcher focused)
const testUsers = [
  { username: 'testuser1', password: 'test123' },
  { username: 'testuser2', password: 'user456' },
  { username: 'vipuser', password: generateSecurePassword() },
  { username: 'researcher', password: 'research2024!' },
  { username: 'pentester', password: 'h4ck3r101' },
  { username: 'reverser', password: 'ida_pr0' },
  { username: 'kernel_dev', password: 'ring0access' },
  { username: 'dma_user', password: 'pcileech123' }
];

const userIds = [];
for (const user of testUsers) {
  const hash = await bcrypt.hash(user.password, 12);
  
  // Generate UUID manually instead of relying on MySQL's auto-generation
  const userId = crypto.randomUUID();
  
  await connection.execute(`
    INSERT INTO users (id, username, password_hash) 
    VALUES (?, ?, ?)
  `, [userId, user.username, hash]);
  
  userIds.push(userId); // Store the actual UUID
  await logPassword(user.username, user.password, hash, 'user');
  console.log(`✅ Created user: ${user.username}`);
}

// Get product IDs
const [productRows] = await connection.execute('SELECT id, slug FROM products');
const productMap = {};
productRows.forEach(p => productMap[p.slug] = p.id);

// Create various license types - fix the indexing issue
const licenses = [
  { userIndex: 0, productSlug: 'premium-loader', key: 'PREM-1234-5678-9012', lifetime: false, days: 30 },
  { userIndex: 1, productSlug: 'basic-loader', key: 'BASIC-ABCD-EFGH-123', lifetime: false, days: 7 },        // Fixed: 19 chars
  { userIndex: 2, productSlug: 'vip-package', key: 'VIP-LIFE-TIME-2024', lifetime: true },                    // 19 chars - OK
  { userIndex: 3, productSlug: 'ac-bypass', key: 'ACB-RESE-ARCH-2024', lifetime: false, days: 90 },          // 19 chars - OK
  { userIndex: 4, productSlug: 'premium-loader', key: 'PREM-PENT-TEST-24', lifetime: false, days: 365 },     // Fixed: 18 chars
  { userIndex: 5, productSlug: 'kernel-driver', key: 'KERN-DEV-TEST-2024', lifetime: true },                 // 19 chars - OK
  { userIndex: 6, productSlug: 'kernel-driver', key: 'KERN-RING-ZERO-24', lifetime: false, days: 180 },      // Fixed: 17 chars
  { userIndex: 7, productSlug: 'dma-tool', key: 'DMA-PCIE-LEECH-24', lifetime: true }                       // Fixed: 17 chars
];

for (const lic of licenses) {
  // Use the correct user UUID from the array
  const userUuid = userIds[lic.userIndex];
  
  if (!userUuid) {
    console.error(`❌ Invalid user index: ${lic.userIndex}`);
    continue;
  }
  
  // Conditionally build the query
  if (lic.lifetime) {
    await connection.execute(`
      INSERT INTO user_licenses (user_id, product_id, license_key, is_lifetime, expires_at) 
      VALUES (?, ?, ?, ?, NULL)
    `, [userUuid, productMap[lic.productSlug], lic.key, true]);
  } else {
    await connection.execute(`
      INSERT INTO user_licenses (user_id, product_id, license_key, is_lifetime, expires_at) 
      VALUES (?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? DAY))
    `, [userUuid, productMap[lic.productSlug], lic.key, false, lic.days]);
  }
  
  console.log(`✅ Created license: ${lic.key}`);
}
    
    // Legacy consumers for backwards compatibility
    await connection.execute(`
      INSERT INTO consumers (product_key, script_public, script_private) VALUES
      ('LEGACY-TEST-1234', '7 Days', '0'),
      ('LEGACY-LIFE-5678', 'LIFETIME', 'LIFETIME'),
      ('LEGACY-KERN-9012', '30 Days', '30 Days')
    `);
    
    // System configuration for anti-cheat
    await connection.execute(`
      INSERT INTO system_config (config_key, config_value, description) VALUES
      ('anti_analysis_enabled', 'true', 'Global anti-analysis toggle'),
      ('max_suspicion_score', '30', 'Max score before auto-ban'),
      ('hwid_reset_cooldown_hours', '24', 'Hours between HWID resets'),
      ('vm_detection_enabled', 'true', 'Detect virtual machines'),
      ('debugger_detection_enabled', 'true', 'Detect debuggers'),
      ('kernel_detection_enabled', 'true', 'Detect kernel modifications')
    `);
    
    const envContent = `# Simplified LegitDB Configuration (No Email/Fraud)
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=legitdb
DB_PORT=3306

# Server Configuration
PORT=3000
NODE_ENV=development

# Session Configuration
SESSION_SECRET=${crypto.randomBytes(32).toString('hex')}
SESSION_NAME=auth_session

# Security Configuration
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
RATE_LIMIT_WINDOW=15

# Anti-Analysis Configuration
ANTI_VM_CHECK=true
ANTI_DEBUG_CHECK=true
ANTI_REVERSE_CHECK=true
MAX_SUSPICION_SCORE=30

# Cloudflare R2 (Optional)
R2_ENDPOINT=https://your-account.r2.cloudflarestorage.com
R2_ACCESS_KEY_ID=your_access_key
R2_SECRET_ACCESS_KEY=your_secret_key
R2_BUCKET_NAME=auth-downloads

# Logging
LOG_FILE_PATH=./logs/app.log
LOG_LEVEL=debug

# Application Info
APP_NAME=LegitDB Anti-Cheat Auth
APP_VERSION=2.0.0
`;
    
    fs.writeFileSync('.env', envContent);
    console.log('✅ Enhanced .env file created');
    
    // Create summary report
    const summaryReport = `
=== LegitDB Setup Summary (Simplified - No Email/Fraud) ===
Database: legitdb
Tables Created: 13
Admin Users: ${adminUsers.length}
Test Users: ${testUsers.length}
Products: 6 (including kernel/DMA tools)
Licenses: ${licenses.length}

=== Test Credentials ===
See ${PASSWORD_LOG_FILE} for all passwords

=== Quick Test Commands ===
# Test premium license
curl "http://localhost:3000/auth.php?product_key=PREM-1234-5678-9012&hwid=TEST123"

# Test VIP lifetime license
curl "http://localhost:3000/auth.php?product_key=VIP-LIFE-TIME-2024&hwid=VIP456"

# Test kernel driver license
curl "http://localhost:3000/auth.php?product_key=KERN-DEV-TEST-2024&hwid=KERNEL123"

# Test DMA tool license
curl "http://localhost:3000/auth.php?product_key=DMA-PCIE-LEECH-2024&hwid=DMA456"

# Test legacy consumer
curl "http://localhost:3000/auth.php?product_key=LEGACY-TEST-1234&hwid=LEGACY789"

=== Anti-Cheat Test Scenarios ===
# Test with analysis tool detection
curl "http://localhost:3000/auth.php?product_key=PREM-1234-5678-9012&hwid=TEST123&system_data=BASE64_ENCODED_SYSTEM_INFO"

=== Security Notes ===
⚠️ Password logging is enabled in ${PASSWORD_LOG_FILE}
⚠️ Delete this file before production use!
⚠️ Change all default passwords before production!
⚠️ No email functionality included
⚠️ No fraud alerts functionality included
`;
    
    fs.writeFileSync('./setup_summary.txt', summaryReport);
    
    console.log('\n' + summaryReport);
    
    if (connection) await connection.end();
    if (dbConnection) await dbConnection.end(); // Ensure dbConnection is also closed
    
  } catch (error) {
    console.error('❌ Setup failed:', error.message);
    console.error(error);
    if (connection) await connection.end();
    if (dbConnection) await dbConnection.end(); // Ensure dbConnection is also closed
    process.exit(1);
  }
}

// Run setup
setupSimplifiedLegitDB();
