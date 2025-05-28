// Save as "check_env.js" and run: node check_env.js

const fs = require('fs');
const mysql = require('mysql2/promise');
require('dotenv').config();

async function checkEnvironment() {
  console.log('🔍 Environment & Database Diagnostic\n');
  
  // Check .env file exists
  if (fs.existsSync('.env')) {
    console.log('✅ .env file exists');
    
    const envContent = fs.readFileSync('.env', 'utf8');
    console.log('\n📄 Current .env contents:');
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
    console.log('❌ .env file NOT FOUND');
    console.log('💡 Creating a template .env file...');
    createEnvTemplate();
    return;
  }
  
  // Check environment variables
  console.log('\n🔧 Environment Variables:');
  console.log('DB_HOST:', process.env.DB_HOST || '❌ NOT SET (defaults to localhost)');
  console.log('DB_USER:', process.env.DB_USER || '❌ NOT SET (defaults to root)');
  console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '✅ SET' : '❌ NOT SET (defaults to empty)');
  console.log('DB_NAME:', process.env.DB_NAME || '❌ NOT SET (defaults to advanced_auth)');
  console.log('PORT:', process.env.PORT || '❌ NOT SET (defaults to 3000)');
  
  // Test database connections
  await testDatabaseConnections();
}

async function testDatabaseConnections() {
  console.log('\n🔌 Testing Database Connections...');
  
  const configs = [
    {
      name: 'Current .env Config',
      config: {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'advanced_auth'
      }
    },
    {
      name: 'Alternative: loader database',
      config: {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: 'loader'
      }
    }
  ];
  
  for (const testConfig of configs) {
    try {
      console.log(`\n⚡ Testing: ${testConfig.name}`);
      console.log(`   Host: ${testConfig.config.host}`);
      console.log(`   User: ${testConfig.config.user}`);
      console.log(`   Database: ${testConfig.config.database}`);
      
      const connection = await mysql.createConnection(testConfig.config);
      console.log('   ✅ Connection successful!');
      
      // Check for admin_users table
      try {
        const [tables] = await connection.execute("SHOW TABLES LIKE 'admin_users'");
        if (tables.length > 0) {
          console.log('   ✅ admin_users table exists');
          
          const [admins] = await connection.execute('SELECT COUNT(*) as count FROM admin_users');
          console.log(`   ✅ Found ${admins[0].count} admin users`);
        } else {
          console.log('   ❌ admin_users table missing');
        }
      } catch (tableError) {
        console.log('   ❌ Cannot check tables:', tableError.message);
      }
      
      await connection.end();
      
    } catch (error) {
      console.log(`   ❌ Connection failed: ${error.message}`);
      
      if (error.code === 'ER_ACCESS_DENIED_ERROR') {
        console.log('   💡 Check username/password');
      } else if (error.code === 'ER_BAD_DB_ERROR') {
        console.log('   💡 Database does not exist');
      } else if (error.code === 'ECONNREFUSED') {
        console.log('   💡 MySQL server not running');
      }
    }
  }
}

function createEnvTemplate() {
  const envTemplate = `# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=advanced_auth
DB_PORT=3306

# Server Configuration
PORT=3000
NODE_ENV=development

# Session Configuration
SESSION_SECRET=change-this-secret-in-production
SESSION_NAME=auth_session

# Admin Configuration
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123

# Logging
LOG_FILE_PATH=./logs/app.log
`;

  fs.writeFileSync('.env', envTemplate);
  console.log('✅ Created .env template file');
  console.log('📝 Please edit .env with your actual database credentials');
}

checkEnvironment().catch(console.error);