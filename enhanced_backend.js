const express = require('express');
const mysql = require('mysql2/promise');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const geoip = require('geoip-lite');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs').promises;
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const multer = require('multer');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'advanced_auth',
  waitForConnections: true,
  connectionLimit: 20,
  queueLimit: 0,
  charset: 'utf8mb4'
};

const pool = mysql.createPool(dbConfig);

// Session store
const sessionStore = new MySQLStore({}, pool);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Disable for development
}));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

// Root route - redirect to admin login by default
app.get('/', (req, res) => {
  res.redirect('/admin/login');
});

// Generic login route - redirect to admin login
app.get('/login', (req, res) => {
  res.redirect('/admin/login');
});

// File upload configuration
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /\.(exe|zip|rar|7z|tar|gz)$/i;
    if (allowedTypes.test(file.originalname)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Rate limiting configurations
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many authentication attempts'
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

// Session configuration
app.use(session({
  key: process.env.SESSION_NAME || 'auth_session',
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// Constants
const ERROR_CODES = {
  INVALID_KEY: 'jEL8q7ack',
  INVALID_HWID: 'byYkP36DrwwJ',
  SUB_EXPIRED: '6n9prTpS538B',
  IS_BANNED: '4e9mMzxqfRA4',
  SESSION_LIMIT: '8xPqM2nR5vB9',
  HWID_LOCKED: 'kT9mN4xZ8qR2'
};

// Utility functions
const generateSecureToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

const generateProductKey = () => {
  const segments = [];
  for (let i = 0; i < 4; i++) {
    segments.push(crypto.randomBytes(2).toString('hex').toUpperCase());
  }
  return segments.join('-');
};

const getClientIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress || '127.0.0.1';
};

const getGeoInfo = (ip) => {
  const geo = geoip.lookup(ip);
  return geo ? { country: geo.country, city: geo.city } : { country: null, city: null };
};

const logActivity = async (message, type = 'info', metadata = {}) => {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] [${type.toUpperCase()}] ${message}`;
  
  try {
    console.log(logMessage);
    // Broadcast to admin dashboard if connected
    io.to('admin-room').emit('activity', {
      timestamp,
      type,
      message,
      metadata
    });
  } catch (error) {
    console.error('Logging error:', error);
  }
};

const logAuthAttempt = async (data) => {
  const { user_id, license_key, product_id, ip_address, hwid, user_agent, success, failure_reason } = data;
  const geo = getGeoInfo(ip_address);
  
  try {
    await pool.execute(`
      INSERT INTO auth_logs 
      (user_id, license_key, product_id, ip_address, hwid, user_agent, success, failure_reason, geo_country, geo_city)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [user_id, license_key, product_id, ip_address, hwid, user_agent, success, failure_reason, geo.country, geo.city]);
  } catch (error) {
    console.error('Auth log error:', error);
  }
};

const detectFraud = async (licenseId, authData) => {
  try {
    // Check for rapid HWID changes
    const [hwidChanges] = await pool.execute(`
      SELECT COUNT(*) as count FROM hwid_changes 
      WHERE license_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    `, [licenseId]);
    
    if (hwidChanges[0].count >= 3) {
      await createFraudAlert(licenseId, 'rapid_hwid_change', 'high', 
        `Rapid HWID changes: ${hwidChanges[0].count} in 24 hours`);
    }
    
    // Check for geographical impossibilities
    const [lastAuth] = await pool.execute(`
      SELECT ip_address, geo_country, created_at FROM auth_logs 
      WHERE license_key = ? AND success = 1 
      ORDER BY created_at DESC LIMIT 1
    `, [authData.license_key]);
    
    if (lastAuth.length > 0) {
      const timeDiff = (new Date() - new Date(lastAuth[0].created_at)) / 1000 / 60; // minutes
      const lastGeo = { country: lastAuth[0].geo_country };
      const currentGeo = getGeoInfo(authData.ip_address);
      
      if (timeDiff < 60 && lastGeo.country !== currentGeo.country && 
          lastGeo.country && currentGeo.country) {
        await createFraudAlert(licenseId, 'geo_impossible', 'critical',
          `Impossible travel: ${lastGeo.country} to ${currentGeo.country} in ${Math.round(timeDiff)} minutes`);
      }
    }
  } catch (error) {
    console.error('Fraud detection error:', error);
  }
};

const createFraudAlert = async (licenseId, alertType, severity, description, metadata = {}) => {
  try {
    const [license] = await pool.execute('SELECT user_id FROM user_licenses WHERE id = ?', [licenseId]);
    const userId = license[0]?.user_id;
    
    await pool.execute(`
      INSERT INTO fraud_alerts (user_id, license_id, alert_type, severity, description, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [userId, licenseId, alertType, severity, description, JSON.stringify(metadata)]);
    
    // Broadcast to admin dashboard
    io.to('admin-room').emit('fraud-alert', {
      licenseId,
      alertType,
      severity,
      description,
      timestamp: new Date()
    });
  } catch (error) {
    console.error('Fraud alert creation error:', error);
  }
};

// Middleware functions
const requireAuth = (req, res, next) => {
  if (!req.session.loggedin) {
    return res.redirect('/login');
  }
  next();
};

const requireCustomerAuth = (req, res, next) => {
  if (!req.session.customer_id) {
    return res.redirect('/customer/login');
  }
  next();
};

const requireAdminAuth = (requiredRole = 'support') => {
  const roleHierarchy = { support: 1, moderator: 2, admin: 3, super_admin: 4 };
  
  return (req, res, next) => {
    if (!req.session.admin_id || !req.session.admin_role) {
      return res.redirect('/admin/login');
    }
    
    if (roleHierarchy[req.session.admin_role] < roleHierarchy[requiredRole]) {
      return res.status(403).send('Insufficient permissions');
    }
    
    next();
  };
};

// Authentication endpoint for loaders
app.get('/auth.php', authLimiter, async (req, res) => {
  const { product_key: licenseKey, hwid, product } = req.query;
  const ip_address = getClientIP(req);
  const user_agent = req.get('User-Agent') || '';
  
  if (!licenseKey) {
    await logAuthAttempt({
      license_key: licenseKey,
      ip_address,
      user_agent,
      success: false,
      failure_reason: 'Missing license key'
    });
    return res.send(ERROR_CODES.INVALID_KEY);
  }
  
  try {
    // Get license with user and product info
    const [licenses] = await pool.execute(`
      SELECT ul.*, u.username, u.is_banned, u.banned_until, p.name as product_name, p.max_concurrent_sessions
      FROM user_licenses ul
      JOIN users u ON ul.user_id = u.id
      JOIN products p ON ul.product_id = p.id
      WHERE ul.license_key = ? AND ul.is_active = 1
    `, [licenseKey]);
    
    if (licenses.length === 0) {
      await logAuthAttempt({
        license_key: licenseKey,
        ip_address,
        hwid,
        user_agent,
        success: false,
        failure_reason: 'Invalid license key'
      });
      return res.send(ERROR_CODES.INVALID_KEY);
    }
    
    const license = licenses[0];
    
    // Check if user is banned
    if (license.is_banned) {
      const banExpiry = license.banned_until ? new Date(license.banned_until) : null;
      if (!banExpiry || banExpiry > new Date()) {
        await logAuthAttempt({
          user_id: license.user_id,
          license_key: licenseKey,
          product_id: license.product_id,
          ip_address,
          hwid,
          user_agent,
          success: false,
          failure_reason: 'User banned'
        });
        return res.send(ERROR_CODES.IS_BANNED);
      }
    }
    
    // Check license expiry
    if (!license.is_lifetime && license.expires_at && new Date(license.expires_at) < new Date()) {
      await logAuthAttempt({
        user_id: license.user_id,
        license_key: licenseKey,
        product_id: license.product_id,
        ip_address,
        hwid,
        user_agent,
        success: false,
        failure_reason: 'License expired'
      });
      return res.send(ERROR_CODES.SUB_EXPIRED);
    }
    
    // HWID management
    if (!license.hwid) {
      // First time - lock HWID
      await pool.execute(`
        UPDATE user_licenses 
        SET hwid = ?, hwid_locked_at = NOW(), last_auth_ip = ?, last_auth_at = NOW(), total_auth_count = total_auth_count + 1
        WHERE id = ?
      `, [hwid, ip_address, license.id]);
      
      await pool.execute(`
        INSERT INTO hwid_changes (license_id, old_hwid, new_hwid, ip_address, change_reason)
        VALUES (?, NULL, ?, ?, 'initial')
      `, [license.id, hwid, ip_address]);
      
    } else if (license.hwid !== hwid) {
      await logAuthAttempt({
        user_id: license.user_id,
        license_key: licenseKey,
        product_id: license.product_id,
        ip_address,
        hwid,
        user_agent,
        success: false,
        failure_reason: 'HWID mismatch'
      });
      return res.send(ERROR_CODES.INVALID_HWID);
    }
    
    // Check concurrent sessions
    const [activeSessions] = await pool.execute(`
      SELECT COUNT(*) as count FROM active_sessions 
      WHERE license_id = ? AND expires_at > NOW()
    `, [license.id]);
    
    if (activeSessions[0].count >= license.max_concurrent_sessions) {
      await logAuthAttempt({
        user_id: license.user_id,
        license_key: licenseKey,
        product_id: license.product_id,
        ip_address,
        hwid,
        user_agent,
        success: false,
        failure_reason: 'Session limit exceeded'
      });
      return res.send(ERROR_CODES.SESSION_LIMIT);
    }
    
    // Create session
    const sessionToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + (60 * 60 * 1000)); // 1 hour
    
    await pool.execute(`
      INSERT INTO active_sessions (license_id, session_token, ip_address, hwid, user_agent, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [license.id, sessionToken, ip_address, hwid, user_agent, expiresAt]);
    
    // Update license stats
    await pool.execute(`
      UPDATE user_licenses 
      SET last_auth_ip = ?, last_auth_at = NOW(), total_auth_count = total_auth_count + 1, current_sessions = current_sessions + 1
      WHERE id = ?
    `, [ip_address, license.id]);
    
    // Log successful auth
    await logAuthAttempt({
      user_id: license.user_id,
      license_key: licenseKey,
      product_id: license.product_id,
      ip_address,
      hwid,
      user_agent,
      success: true,
      failure_reason: null
    });
    
    // Run fraud detection
    await detectFraud(license.id, { license_key: licenseKey, ip_address, hwid });
    
    // Calculate time remaining
    let timeResponse = 'LIFETIME:0:0';
    if (!license.is_lifetime && license.expires_at) {
      const timeLeft = new Date(license.expires_at) - new Date();
      const daysLeft = Math.floor(timeLeft / (1000 * 60 * 60 * 24));
      const hoursLeft = Math.floor((timeLeft % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      timeResponse = `${Math.max(0, daysLeft)}:${Math.max(0, hoursLeft)}:0`;
    }
    
    await logActivity(`Successful auth: ${license.username} (${licenseKey}) from ${ip_address}`, 'auth');
    
    res.send(`${timeResponse}:${sessionToken}`);
    
  } catch (error) {
    console.error('Auth error:', error);
    res.send(ERROR_CODES.INVALID_KEY);
  }
});

// Customer registration
app.post('/customer/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.json({ success: false, message: 'All fields required' });
  }
  
  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationToken = generateSecureToken();
    
    await pool.execute(`
      INSERT INTO users (username, email, password_hash, email_verification_token)
      VALUES (?, ?, ?, ?)
    `, [username, email, hashedPassword, verificationToken]);
    
    res.json({ success: true, message: 'Registration successful' });
    
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      res.json({ success: false, message: 'Username or email already exists' });
    } else {
      console.error('Registration error:', error);
      res.json({ success: false, message: 'Registration failed' });
    }
  }
});

// Customer login
app.post('/customer/login', loginLimiter, async (req, res) => {
  const { username, password, totp_code } = req.body;
  const ip_address = getClientIP(req);
  
  try {
    const [users] = await pool.execute(`
      SELECT * FROM users WHERE username = ? OR email = ?
    `, [username, username]);
    
    if (users.length === 0) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }
    
    const user = users[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordMatch) {
      return res.json({ success: false, message: 'Invalid credentials' });
    }
    
    // Check 2FA if enabled
    if (user.totp_enabled) {
      if (!totp_code) {
        return res.json({ success: false, message: '2FA code required', requires_2fa: true });
      }
      
      const verified = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: totp_code,
        window: 2
      });
      
      if (!verified) {
        return res.json({ success: false, message: 'Invalid 2FA code' });
      }
    }
    
    // Update last login
    await pool.execute(`
      UPDATE users SET last_login_ip = ?, last_login_at = NOW() WHERE id = ?
    `, [ip_address, user.id]);
    
    req.session.customer_id = user.id;
    req.session.customer_username = user.username;
    
    res.json({ success: true, message: 'Login successful' });
    
  } catch (error) {
    console.error('Login error:', error);
    res.json({ success: false, message: 'Login failed' });
  }
});

// Customer dashboard
app.get('/customer/dashboard', requireCustomerAuth, async (req, res) => {
  try {
    const userId = req.session.customer_id;
    
    // Get user licenses with product info
    const [licenses] = await pool.execute(`
      SELECT ul.*, p.name as product_name, p.slug as product_slug
      FROM user_licenses ul
      JOIN products p ON ul.product_id = p.id
      WHERE ul.user_id = ? AND ul.is_active = 1
    `, [userId]);
    
    // Get recent auth logs
    const [authLogs] = await pool.execute(`
      SELECT * FROM auth_logs 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 10
    `, [userId]);
    
    // Get HWID change history
    const [hwidChanges] = await pool.execute(`
      SELECT hc.*, ul.license_key, p.name as product_name
      FROM hwid_changes hc
      JOIN user_licenses ul ON hc.license_id = ul.id
      JOIN products p ON ul.product_id = p.id
      WHERE ul.user_id = ?
      ORDER BY hc.created_at DESC
      LIMIT 5
    `, [userId]);
    
    res.send(generateCustomerDashboard(licenses, authLogs, hwidChanges));
    
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).send('Dashboard error');
  }
});

// HWID reset endpoint
app.post('/customer/reset-hwid', requireCustomerAuth, async (req, res) => {
  const { license_id } = req.body;
  const userId = req.session.customer_id;
  const ip_address = getClientIP(req);
  
  try {
    // Check if license belongs to user
    const [licenses] = await pool.execute(`
      SELECT ul.*, p.hwid_reset_interval_days, p.max_hwid_changes
      FROM user_licenses ul
      JOIN products p ON ul.product_id = p.id
      WHERE ul.id = ? AND ul.user_id = ?
    `, [license_id, userId]);
    
    if (licenses.length === 0) {
      return res.json({ success: false, message: 'License not found' });
    }
    
    const license = licenses[0];
    
    // Check cooldown period
    if (license.last_hwid_reset) {
      const cooldownHours = 24; // Configurable
      const timeSinceReset = (new Date() - new Date(license.last_hwid_reset)) / (1000 * 60 * 60);
      
      if (timeSinceReset < cooldownHours) {
        return res.json({ 
          success: false, 
          message: `HWID reset available in ${Math.ceil(cooldownHours - timeSinceReset)} hours` 
        });
      }
    }
    
    // Reset HWID
    await pool.execute(`
      UPDATE user_licenses 
      SET hwid = NULL, hwid_locked_at = NULL, last_hwid_reset = NOW(), hwid_changes_count = hwid_changes_count + 1
      WHERE id = ?
    `, [license_id]);
    
    // Log the change
    await pool.execute(`
      INSERT INTO hwid_changes (license_id, old_hwid, new_hwid, ip_address, change_reason)
      VALUES (?, ?, 'RESET', ?, 'user_request')
    `, [license_id, license.hwid, ip_address]);
    
    res.json({ success: true, message: 'HWID reset successful' });
    
  } catch (error) {
    console.error('HWID reset error:', error);
    res.json({ success: false, message: 'Reset failed' });
  }
});

// Enable 2FA
app.post('/customer/enable-2fa', requireCustomerAuth, async (req, res) => {
  const userId = req.session.customer_id;
  
  try {
    const secret = speakeasy.generateSecret({
      name: `Auth System (${req.session.customer_username})`,
      length: 20
    });
    
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    
    // Temporarily store secret (not yet activated)
    req.session.pending_totp_secret = secret.base32;
    
    res.json({
      success: true,
      secret: secret.base32,
      qrCode: qrCodeUrl
    });
    
  } catch (error) {
    console.error('2FA setup error:', error);
    res.json({ success: false, message: '2FA setup failed' });
  }
});

// Confirm 2FA setup
app.post('/customer/confirm-2fa', requireCustomerAuth, async (req, res) => {
  const { totp_code } = req.body;
  const userId = req.session.customer_id;
  const secret = req.session.pending_totp_secret;
  
  if (!secret) {
    return res.json({ success: false, message: 'No pending 2FA setup' });
  }
  
  try {
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: totp_code,
      window: 2
    });
    
    if (!verified) {
      return res.json({ success: false, message: 'Invalid 2FA code' });
    }
    
    // Enable 2FA for user
    await pool.execute(`
      UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?
    `, [secret, userId]);
    
    delete req.session.pending_totp_secret;
    
    res.json({ success: true, message: '2FA enabled successfully' });
    
  } catch (error) {
    console.error('2FA confirmation error:', error);
    res.json({ success: false, message: '2FA confirmation failed' });
  }
});

// Admin dashboard with real-time monitoring
app.get('/admin/dashboard', requireAdminAuth(), async (req, res) => {
  try {
    // Get dashboard statistics
    const [stats] = await pool.execute(`
      SELECT 
        (SELECT COUNT(*) FROM users WHERE is_banned = 0) as active_users,
        (SELECT COUNT(*) FROM user_licenses WHERE is_active = 1) as active_licenses,
        (SELECT COUNT(*) FROM auth_logs WHERE created_at >= CURDATE()) as today_auths,
        (SELECT COUNT(*) FROM fraud_alerts WHERE is_resolved = 0) as pending_alerts
    `);
    
    // Get recent activity
    const [recentAuth] = await pool.execute(`
      SELECT al.*, u.username, p.name as product_name
      FROM auth_logs al
      LEFT JOIN users u ON al.user_id = u.id
      LEFT JOIN products p ON al.product_id = p.id
      ORDER BY al.created_at DESC
      LIMIT 20
    `);
    
    // Get fraud alerts
    const [fraudAlerts] = await pool.execute(`
      SELECT * FROM fraud_dashboard_view
      ORDER BY created_at DESC
      LIMIT 10
    `);
    
    res.send(generateAdminDashboard(stats[0], recentAuth, fraudAlerts));
    
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).send('Dashboard error');
  }
});

// Bulk operations endpoint
app.post('/admin/bulk-action', requireAdminAuth('admin'), async (req, res) => {
  const { action, criteria, value } = req.body;
  const adminId = req.session.admin_id;
  
  try {
    let query = '';
    let params = [];
    
    switch (action) {
      case 'ban_users':
        if (criteria === 'country') {
          query = `
            UPDATE users u 
            JOIN auth_logs al ON u.id = al.user_id 
            SET u.is_banned = 1, u.ban_reason = ? 
            WHERE al.geo_country = ? AND u.is_banned = 0
          `;
          params = [`Bulk ban: ${value}`, value];
        }
        break;
        
      case 'extend_licenses':
        if (criteria === 'product') {
          query = `
            UPDATE user_licenses ul
            JOIN products p ON ul.product_id = p.id
            SET ul.expires_at = DATE_ADD(COALESCE(ul.expires_at, NOW()), INTERVAL ? DAY)
            WHERE p.slug = ? AND ul.is_lifetime = 0
          `;
          params = [parseInt(value), criteria];
        }
        break;
    }
    
    if (query) {
      const [result] = await pool.execute(query, params);
      
      // Log admin action
      await pool.execute(`
        INSERT INTO admin_audit_log (admin_id, action, target_type, old_values, new_values, ip_address)
        VALUES (?, ?, 'bulk', ?, ?, ?)
      `, [adminId, action, JSON.stringify(criteria), JSON.stringify({ affected: result.affectedRows }), getClientIP(req)]);
      
      res.json({ success: true, affected: result.affectedRows });
    } else {
      res.json({ success: false, message: 'Invalid bulk action' });
    }
    
  } catch (error) {
    console.error('Bulk action error:', error);
    res.json({ success: false, message: 'Bulk action failed' });
  }
});

// WebSocket connection for real-time monitoring
io.on('connection', (socket) => {
  socket.on('join-admin', (data) => {
    // Verify admin session
    if (data.adminId) {
      socket.join('admin-room');
      socket.emit('connected', { message: 'Connected to admin monitoring' });
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Admin disconnected from monitoring');
  });
});

// Download center
app.get('/customer/downloads', requireCustomerAuth, async (req, res) => {
  const userId = req.session.customer_id;
  
  try {
    const [downloads] = await pool.execute(`
      SELECT d.*, p.name as product_name
      FROM downloads d
      JOIN products p ON d.product_id = p.id
      JOIN user_licenses ul ON ul.product_id = p.id
      WHERE ul.user_id = ? AND d.is_active = 1 AND ul.is_active = 1
      GROUP BY d.id
    `, [userId]);
    
    res.json({ success: true, downloads });
    
  } catch (error) {
    console.error('Downloads error:', error);
    res.json({ success: false, message: 'Failed to fetch downloads' });
  }
});

// Generate download token
app.post('/customer/generate-download-token', requireCustomerAuth, async (req, res) => {
  const { download_id } = req.body;
  const userId = req.session.customer_id;
  
  try {
    // Verify user has access to this download
    const [access] = await pool.execute(`
      SELECT d.* FROM downloads d
      JOIN products p ON d.product_id = p.id
      JOIN user_licenses ul ON ul.product_id = p.id
      WHERE d.id = ? AND ul.user_id = ? AND d.is_active = 1 AND ul.is_active = 1
    `, [download_id, userId]);
    
    if (access.length === 0) {
      return res.json({ success: false, message: 'Access denied' });
    }
    
    const token = generateSecureToken();
    const expiresAt = new Date(Date.now() + (2 * 60 * 60 * 1000)); // 2 hours
    
    await pool.execute(`
      INSERT INTO download_tokens (user_id, download_id, token, expires_at, ip_address)
      VALUES (?, ?, ?, ?, ?)
    `, [userId, download_id, token, expiresAt, getClientIP(req)]);
    
    res.json({ 
      success: true, 
      token, 
      download_url: `/download/${token}`,
      expires_at: expiresAt
    });
    
  } catch (error) {
    console.error('Token generation error:', error);
    res.json({ success: false, message: 'Token generation failed' });
  }
});

// Secure download endpoint
app.get('/download/:token', async (req, res) => {
  const { token } = req.params;
  
  try {
    const [tokens] = await pool.execute(`
      SELECT dt.*, d.file_path, d.filename, d.display_name
      FROM download_tokens dt
      JOIN downloads d ON dt.download_id = d.id
      WHERE dt.token = ? AND dt.expires_at > NOW() AND dt.download_count < dt.max_downloads
    `, [token]);
    
    if (tokens.length === 0) {
      return res.status(404).send('Download token invalid or expired');
    }
    
    const tokenData = tokens[0];
    
    // Update download count
    await pool.execute(`
      UPDATE download_tokens SET download_count = download_count + 1 WHERE token = ?
    `, [token]);
    
    // Serve file
    res.download(tokenData.file_path, tokenData.display_name);
    
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).send('Download failed');
  }
});

// Helper function to generate customer dashboard HTML
function generateCustomerDashboard(licenses, authLogs, hwidChanges) {
  const licensesHTML = licenses.map(license => {
    const status = license.is_lifetime ? 'LIFETIME' : 
                  (!license.expires_at || new Date(license.expires_at) > new Date()) ? 'ACTIVE' : 'EXPIRED';
    const expiryText = license.is_lifetime ? 'Never' : 
                      license.expires_at ? new Date(license.expires_at).toLocaleDateString() : 'N/A';
    
    return `
      <div class="license-card">
        <h3>${license.product_name}</h3>
        <p><strong>License Key:</strong> ${license.license_key}</p>
        <p><strong>Status:</strong> <span class="status-${status.toLowerCase()}">${status}</span></p>
        <p><strong>Expires:</strong> ${expiryText}</p>
        <p><strong>HWID:</strong> ${license.hwid || 'Not set'}</p>
        <p><strong>Total Auths:</strong> ${license.total_auth_count}</p>
        <div class="license-actions">
          <button onclick="resetHwid(${license.id})" class="btn-secondary">Reset HWID</button>
          <button onclick="viewAnalytics(${license.id})" class="btn-primary">View Analytics</button>
        </div>
      </div>
    `;
  }).join('');
  
  return `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Customer Dashboard</title>
        <link href="/customer-style.css" rel="stylesheet">
        <script src="/socket.io/socket.io.js"></script>
    </head>
    <body>
        <div class="dashboard">
            <nav class="navbar">
                <h1>Customer Portal</h1>
                <div class="nav-links">
                    <a href="/customer/downloads">Downloads</a>
                    <a href="/customer/settings">Settings</a>
                    <a href="/customer/logout">Logout</a>
                </div>
            </nav>
            
            <div class="content">
                <section class="licenses-section">
                    <h2>Your Licenses</h2>
                    <div class="licenses-grid">
                        ${licensesHTML}
                    </div>
                </section>
                
                <section class="activity-section">
                    <h2>Recent Activity</h2>
                    <div class="activity-log">
                        ${authLogs.map(log => `
                            <div class="activity-item ${log.success ? 'success' : 'failed'}">
                                <span class="timestamp">${new Date(log.created_at).toLocaleString()}</span>
                                <span class="ip">${log.ip_address}</span>
                                <span class="status">${log.success ? 'Success' : 'Failed'}</span>
                                ${log.failure_reason ? `<span class="reason">${log.failure_reason}</span>` : ''}
                            </div>
                        `).join('')}
                    </div>
                </section>
            </div>
        </div>
        
        <script>
            function resetHwid(licenseId) {
                fetch('/customer/reset-hwid', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ license_id: licenseId })
                })
                .then(r => r.json())
                .then(data => {
                    alert(data.message);
                    if (data.success) location.reload();
                });
            }
        </script>
    </body>
    </html>
  `;
}

// Helper function to generate admin dashboard HTML
function generateAdminDashboard(stats, recentAuth, fraudAlerts) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Dashboard</title>
        <link href="/admin-style.css" rel="stylesheet">
        <script src="/socket.io/socket.io.js"></script>
    </head>
    <body>
        <div class="admin-dashboard">
            <nav class="admin-navbar">
                <h1>Admin Dashboard</h1>
                <div class="nav-links">
                    <a href="/admin/users">Users</a>
                    <a href="/admin/fraud">Fraud Detection</a>
                    <a href="/admin/bulk">Bulk Operations</a>
                    <a href="/admin/audit">Audit Log</a>
                    <a href="/admin/logout">Logout</a>
                </div>
            </nav>
            
            <div class="dashboard-content">
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Active Users</h3>
                        <div class="stat-value">${stats.active_users}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Active Licenses</h3>
                        <div class="stat-value">${stats.active_licenses}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Today's Auths</h3>
                        <div class="stat-value">${stats.today_auths}</div>
                    </div>
                    <div class="stat-card alert">
                        <h3>Fraud Alerts</h3>
                        <div class="stat-value">${stats.pending_alerts}</div>
                    </div>
                </div>
                
                <div class="monitoring-section">
                    <h2>Real-time Monitoring</h2>
                    <div id="live-feed" class="live-feed"></div>
                </div>
            </div>
        </div>
        
        <script>
            const socket = io();
            socket.emit('join-admin', { adminId: '${true}' });
            
            socket.on('activity', (data) => {
                const feed = document.getElementById('live-feed');
                const item = document.createElement('div');
                item.className = 'feed-item';
                item.innerHTML = \`
                    <span class="timestamp">\${new Date(data.timestamp).toLocaleTimeString()}</span>
                    <span class="type \${data.type}">\${data.type}</span>
                    <span class="message">\${data.message}</span>
                \`;
                feed.insertBefore(item, feed.firstChild);
                
                // Keep only last 50 items
                while (feed.children.length > 50) {
                    feed.removeChild(feed.lastChild);
                }
            });
            
            socket.on('fraud-alert', (data) => {
                const notification = document.createElement('div');
                notification.className = 'fraud-notification';
                notification.innerHTML = \`
                    <strong>Fraud Alert (\${data.severity})</strong><br>
                    \${data.description}
                \`;
                document.body.appendChild(notification);
                
                setTimeout(() => notification.remove(), 10000);
            });
        </script>
    </body>
    </html>
  `;
}

// Cleanup expired sessions periodically
setInterval(async () => {
  try {
    await pool.execute('DELETE FROM active_sessions WHERE expires_at < NOW()');
    await pool.execute('DELETE FROM download_tokens WHERE expires_at < NOW()');
    await pool.execute('CALL DetectRapidHwidChanges()');
  } catch (error) {
    console.error('Cleanup error:', error);
  }
}, 5 * 60 * 1000); // Every 5 minutes

// Start server
server.listen(PORT, () => {
  console.log(`Enhanced Authentication Server running on port ${PORT}`);
});

module.exports = app;