const mysql = require('mysql2/promise');

async function testConnection() {
  try {
    const connection = await mysql.createConnection({
      host: 'localhost',
      user: 'auth_user',
      password: 'SecurePassword123!',
      database: 'loader'
    });
    
    console.log('✅ Database connection successful!');
    
    // Test query
    const [rows] = await connection.execute('SELECT COUNT(*) as count FROM consumers');
    console.log(`✅ Found ${rows[0].count} consumers in database`);
    
    await connection.end();
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
  }
}

testConnection();