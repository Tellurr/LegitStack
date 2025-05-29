// check_database_structure.js - Check what columns exist in your users table
const mysql = require('mysql2/promise');
require('dotenv').config();

async function checkDatabaseStructure() {
  console.log('🔍 Checking Database Structure\n');
  
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'legitdb'
    });
    
    console.log('✅ Connected to database:', process.env.DB_NAME || 'legitdb');
    console.log('');
    
    // Check users table structure
    console.log('📋 USERS TABLE STRUCTURE:');
    const [userColumns] = await connection.execute(`
      SHOW COLUMNS FROM users
    `);
    
    console.log('Current columns in users table:');
    userColumns.forEach((col, index) => {
      console.log(`${index + 1}. ${col.Field} (${col.Type}) - ${col.Null === 'YES' ? 'NULL' : 'NOT NULL'} ${col.Key ? `[${col.Key}]` : ''}`);
    });
    
    // Check if email column exists
    const hasEmail = userColumns.some(col => col.Field === 'email');
    console.log('\n📧 Email column exists:', hasEmail ? '✅ YES' : '❌ NO');
    
    if (!hasEmail) {
      console.log('\n⚠️  ISSUE FOUND: The users table is missing the email column!');
      console.log('This is required for user login functionality.');
    }
    
    // Check other important tables
    console.log('\n📋 OTHER TABLES:');
    const [tables] = await connection.execute('SHOW TABLES');
    console.log('Available tables:');
    tables.forEach((table, index) => {
      const tableName = Object.values(table)[0];
      console.log(`${index + 1}. ${tableName}`);
    });
    
    // Check admin_users table structure
    console.log('\n📋 ADMIN_USERS TABLE STRUCTURE:');
    try {
      const [adminColumns] = await connection.execute(`
        SHOW COLUMNS FROM admin_users
      `);
      
      console.log('Current columns in admin_users table:');
      adminColumns.forEach((col, index) => {
        console.log(`${index + 1}. ${col.Field} (${col.Type}) - ${col.Null === 'YES' ? 'NULL' : 'NOT NULL'} ${col.Key ? `[${col.Key}]` : ''}`);
      });
    } catch (error) {
      console.log('❌ Error checking admin_users table:', error.message);
    }
    
    // Check products table structure
    console.log('\n📋 PRODUCTS TABLE STRUCTURE:');
    try {
      const [productColumns] = await connection.execute(`
        SHOW COLUMNS FROM products
      `);
      
      console.log('Current columns in products table:');
      productColumns.forEach((col, index) => {
        console.log(`${index + 1}. ${col.Field} (${col.Type}) - ${col.Null === 'YES' ? 'NULL' : 'NOT NULL'} ${col.Key ? `[${col.Key}]` : ''}`);
      });
    } catch (error) {
      console.log('❌ Error checking products table:', error.message);
    }
    
    await connection.end();
    
    console.log('\n🔧 RECOMMENDED ACTIONS:');
    if (!hasEmail) {
      console.log('1. Add the email column to users table');
      console.log('2. Run the fix script provided');
    } else {
      console.log('✅ Database structure looks good!');
    }
    
  } catch (error) {
    console.error('❌ Database check failed:', error.message);
    
    if (error.code === 'ER_BAD_DB_ERROR') {
      console.log('\n💡 Database does not exist. Check your .env configuration.');
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.log('\n💡 Access denied. Check your database credentials.');
    } else if (error.code === 'ER_NO_SUCH_TABLE') {
      console.log('\n💡 Table does not exist. Your database might be empty.');
    }
  }
}

checkDatabaseStructure();