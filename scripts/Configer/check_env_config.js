// check_env_config.js - Check your database configuration
require('dotenv').config();

console.log('🔧 Environment Configuration Check\n');

console.log('Database Configuration:');
console.log('DB_HOST:', process.env.DB_HOST || 'localhost (default)');
console.log('DB_USER:', process.env.DB_USER || 'root (default)');
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? '[SET]' : '[NOT SET - using empty]');
console.log('DB_NAME:', process.env.DB_NAME || 'advanced_auth (default)');

console.log('\n📁 Checking for .env file...');
const fs = require('fs');
const path = require('path');

const envPath = path.join(process.cwd(), '.env');
if (fs.existsSync(envPath)) {
  console.log('✅ .env file found');
  const envContent = fs.readFileSync(envPath, 'utf8');
  console.log('\n.env file contents:');
  console.log(envContent);
} else {
  console.log('❌ .env file not found');
  console.log('\n🔧 Creating a basic .env file...');
  
  const envTemplate = `# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=legitdb

# Server Configuration
PORT=3000
SESSION_SECRET=your-secret-key-change-this
NODE_ENV=development
`;
  
  fs.writeFileSync(envPath, envTemplate);
  console.log('✅ Created .env file with default settings');
  console.log('⚠️  Please update DB_PASSWORD if your MySQL has a password');
}

console.log('\n🗄️  Expected Database: legitdb');
console.log('🗄️  Application expects database name: legitdb');

// Check if server.js uses the right database
const serverPath = path.join(process.cwd(), 'server.js');
const nodejsBackendPath = path.join(process.cwd(), 'nodejs_backend.js');

let serverFile = null;
if (fs.existsSync(serverPath)) {
  serverFile = 'server.js';
} else if (fs.existsSync(nodejsBackendPath)) {
  serverFile = 'nodejs_backend.js';
}

if (serverFile) {
  console.log(`\n📄 Found server file: ${serverFile}`);
  const serverContent = fs.readFileSync(serverFile, 'utf8');
  
  // Check database configuration in server file
  const dbConfigMatch = serverContent.match(/database:\s*process\.env\.DB_NAME\s*\|\|\s*['"]([^'"]+)['"]/);
  if (dbConfigMatch) {
    console.log(`📊 Default database in ${serverFile}: ${dbConfigMatch[1]}`);
    if (dbConfigMatch[1] !== 'legitdb') {
      console.log('⚠️  WARNING: Server expects different database name!');
      console.log(`   Server expects: ${dbConfigMatch[1]}`);
      console.log('   Your database: legitdb');
      console.log('   Either update your .env file or rename your database');
    }
  }
} else {
  console.log('\n❌ Server file not found (server.js or nodejs_backend.js)');
}

console.log('\n🔍 Next Steps:');
console.log('1. Make sure your .env file has the correct database name');
console.log('2. Run the database structure checker: node check_database_structure.js');
console.log('3. Run the quick email fix if needed: mysql -u root -p legitdb < quick_email_fix.sql');
console.log('4. Test your application: npm start');