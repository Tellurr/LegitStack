
// FIXED: Customer Authentication Debug in nodejs_backend.js

// Add debug logging to customer login route:
app.post('/customer/login', loginLimiter, async (req, res) => {
  const { username, password, totp_code } = req.body;
  const ip_address = getClientIP(req);
  
  console.log(`Customer login attempt: ${username} from ${ip_address}`);
  
  try {
    const [users] = await pool.execute(`
      SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1
    `, [username, username]);
    
    if (users.length === 0) {
      console.log(`❌ User not found: ${username}`);
      return res.json({ success: false, message: 'Invalid credentials' });
    }
    
    const user = users[0];
    console.log(`User found: ${user.username}, checking password...`);
    
    // Add explicit bcrypt debugging
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    console.log(`Password match result: ${passwordMatch}`);
    
    if (!passwordMatch) {
      console.log(`❌ Password mismatch for user: ${username}`);
      return res.json({ success: false, message: 'Invalid credentials' });
    }
    
    // Rest of the authentication logic...
    console.log(`✅ Customer authentication successful: ${username}`);
    
    // ... existing code ...
  } catch (error) {
    console.error('Customer login error:', error);
    res.json({ success: false, message: 'Login failed' });
  }
});