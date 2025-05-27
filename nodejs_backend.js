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
const AWS = require('aws-sdk');
const sharp = require('sharp');
const archiver = require('archiver');
const { v4: uuidv4 } = require('uuid');
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

// Cloudflare R2 Configuration
const r2 = new AWS.S3({
  endpoint: process.env.R2_ENDPOINT || 'https://account-id.r2.cloudflarestorage.com',
  accessKeyId: process.env.R2_ACCESS_KEY_ID,
  secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  region: 'auto',
  signatureVersion: 'v4'
});

const R2_BUCKET = process.env.R2_BUCKET_NAME || 'auth-downloads';

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
  contentSecurityPolicy: false
}));
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// File upload configuration
const upload = multer({
  dest: 'temp/',
  limits: { fileSize: 500 * 1024 * 1024 }, // 500MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /\.(exe|zip|rar|7z|tar|gz|dll|sys|bin)$/i;
    if (allowedTypes.test(file.originalname)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Rate limiting configurations
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many authentication attempts'
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: 'Upload limit exceeded'
});

// Session configuration
app.use(session({
  key: process.env.SESSION_NAME || 'auth_session',
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// Auth middleware
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

const requireCustomerAuth = (req, res, next) => {
  if (!req.session.customer_id) {
    return res.redirect('/customer/login');
  }
  next();
};

// Constants
const ERROR_CODES = {
  INVALID_KEY: 'jEL8q7ack',
  INVALID_HWID: 'byYkP36DrwwJ',
  SUB_EXPIRED: '6n9prTpS538B',
  IS_BANNED: '4e9mMzxqfRA4',
  SESSION_LIMIT: '8xPqM2nR5vB9',
  HWID_LOCKED: 'kT9mN4xZ8qR2',
  ANALYSIS_DETECTED: 'xR3mK9pL4vQ8',
  VM_DETECTED: 'nY7wE2tU6sA1',
  DEBUGGER_DETECTED: 'mP5cV8bN3xK0',
  HOOK_DETECTED: 'qL9gH4jF7eR6'
};

// Anti-Reversing Detection Signatures
const ANALYSIS_SIGNATURES = {
  // Process names commonly used for analysis
  ANALYSIS_PROCESSES: [
    'ollydbg.exe', 'windbg.exe', 'x64dbg.exe', 'x32dbg.exe', 
    'ida.exe', 'ida64.exe', 'idaq.exe', 'idaq64.exe',
    'ghidra.exe', 'radare2.exe', 'dnspy.exe', 'ilspy.exe',
    'process hacker.exe', 'processhacker.exe', 'procmon.exe',
    'wireshark.exe', 'fiddler.exe', 'cheat engine.exe', 'artisanssystem.exe',
    'ollyice.exe', 'lordpe.exe', 'importrec.exe', 'petools.exe',
    'peid.exe', 'protection_id.exe', 'vmware.exe', 'virtualbox.exe',
    'vboxservice.exe', 'vboxtray.exe', 'sandboxie.exe', 'sbiesvc.exe'
  ],
  
  // VM detection indicators
  VM_INDICATORS: [
    'vmware', 'virtualbox', 'vbox', 'qemu', 'kvm', 'xen',
    'parallels', 'hyper-v', 'vmtoolsd', 'vmwaretray',
    'vmwareuser', 'vboxservice', 'vboxtray', 'xenservice'
  ],
  
  // Suspicious modules/DLLs
  HOOK_MODULES: [
    'api-ms-win-core', 'easyhook', 'detours', 'minhook',
    'microsoft.detours', 'apihook', 'winhook', 'injectdll'
  ],
  
  // Sandbox detection
  SANDBOX_INDICATORS: [
    'sandboxie', 'cuckoo', 'anubis', 'joebox', 'threatanalyzer',
    'gfi', 'comodo', 'sunbelt', 'cwsandbox', 'buster_sandbox'
  ]
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

// Advanced Anti-Reversing Detection System
class AntiReversingDetector {
  constructor() {
    this.suspicionScore = 0;
    this.detectionFlags = [];
  }

  async analyzeSystemFingerprint(systemData) {
    let flags = [];
    let suspicionScore = 0;

    // Process Analysis
    if (systemData.processes) {
      const processes = systemData.processes.map(p => p.toLowerCase());
      
      for (const suspiciousProcess of ANALYSIS_SIGNATURES.ANALYSIS_PROCESSES) {
        if (processes.some(p => p.includes(suspiciousProcess.toLowerCase()))) {
          flags.push({
            type: 'ANALYSIS_TOOL',
            severity: 'HIGH',
            details: `Detected analysis tool: ${suspiciousProcess}`,
            process: suspiciousProcess
          });
          suspicionScore += 15;
        }
      }
    }

    // VM Detection
    if (systemData.system_info) {
      const systemInfo = JSON.stringify(systemData.system_info).toLowerCase();
      
      for (const vmIndicator of ANALYSIS_SIGNATURES.VM_INDICATORS) {
        if (systemInfo.includes(vmIndicator)) {
          flags.push({
            type: 'VM_DETECTED',
            severity: 'MEDIUM',
            details: `Virtual machine indicator: ${vmIndicator}`,
            indicator: vmIndicator
          });
          suspicionScore += 10;
        }
      }
    }

    // Timing Analysis Detection
    if (systemData.timing_data) {
      const { auth_start, auth_end, process_scan_time } = systemData.timing_data;
      const authDuration = auth_end - auth_start;
      
      // Suspicious if auth takes too long (potential debugging)
      if (authDuration > 5000) { // 5 seconds
        flags.push({
          type: 'TIMING_ANOMALY',
          severity: 'MEDIUM',
          details: `Authentication took ${authDuration}ms (suspicious delay)`,
          duration: authDuration
        });
        suspicionScore += 8;
      }
      
      // Process scanning taking too long indicates analysis
      if (process_scan_time > 1000) {
        flags.push({
          type: 'SCAN_DELAY',
          severity: 'LOW',
          details: `Process scan took ${process_scan_time}ms`,
          scan_time: process_scan_time
        });
        suspicionScore += 5;
      }
    }

    // Hardware Fingerprint Analysis
    if (systemData.hardware) {
      // Check for VM-specific hardware
      const hardware = JSON.stringify(systemData.hardware).toLowerCase();
      
      if (hardware.includes('vmware') || hardware.includes('virtualbox') || 
          hardware.includes('qemu') || hardware.includes('bochs')) {
        flags.push({
          type: 'VM_HARDWARE',
          severity: 'HIGH',
          details: 'VM-specific hardware detected',
          hardware_info: systemData.hardware
        });
        suspicionScore += 12;
      }
    }

    // Memory Analysis
    if (systemData.memory_info) {
      const { total_memory, available_memory, memory_pressure } = systemData.memory_info;
      
      // Unusual memory configurations often indicate VMs or sandboxes
      if (total_memory < 2 * 1024 * 1024 * 1024) { // Less than 2GB
        flags.push({
          type: 'LOW_MEMORY',
          severity: 'LOW',
          details: `Suspiciously low memory: ${Math.round(total_memory / 1024 / 1024 / 1024)}GB`,
          memory: total_memory
        });
        suspicionScore += 3;
      }
    }

    // DLL/Module Analysis
    if (systemData.loaded_modules) {
      const modules = systemData.loaded_modules.map(m => m.toLowerCase());
      
      for (const hookModule of ANALYSIS_SIGNATURES.HOOK_MODULES) {
        if (modules.some(m => m.includes(hookModule))) {
          flags.push({
            type: 'HOOK_DETECTED',
            severity: 'HIGH',
            details: `Hooking library detected: ${hookModule}`,
            module: hookModule
          });
          suspicionScore += 20;
        }
      }
    }

    // Registry Analysis (Windows-specific)
    if (systemData.registry_keys) {
      const regKeys = systemData.registry_keys.map(k => k.toLowerCase());
      
      // Common VM registry keys
      const vmRegKeys = [
        'vmware', 'virtualbox', 'vbox', 'qemu', 'parallels',
        'sandboxie', 'cuckoo', 'anubis'
      ];
      
      for (const vmKey of vmRegKeys) {
        if (regKeys.some(k => k.includes(vmKey))) {
          flags.push({
            type: 'VM_REGISTRY',
            severity: 'MEDIUM',
            details: `VM registry key detected: ${vmKey}`,
            registry_key: vmKey
          });
          suspicionScore += 7;
        }
      }
    }

    return { flags, suspicionScore };
  }

  async checkBehavioralPatterns(licenseId, authData) {
    try {
      // Check authentication frequency
      const [authHistory] = await pool.execute(`
        SELECT COUNT(*) as count, 
               MIN(created_at) as first_auth,
               MAX(created_at) as last_auth
        FROM auth_logs 
        WHERE license_key = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
      `, [authData.license_key]);

      if (authHistory[0].count > 50) { // More than 50 auths per hour
        return {
          type: 'RAPID_AUTH',
          severity: 'HIGH',
          details: `${authHistory[0].count} authentications in 1 hour`,
          count: authHistory[0].count
        };
      }

      // Check for pattern recognition
      const [patternCheck] = await pool.execute(`
        SELECT 
          ip_address,
          COUNT(*) as count,
          COUNT(DISTINCT hwid) as unique_hwids
        FROM auth_logs 
        WHERE license_key = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        GROUP BY ip_address
        HAVING count > 20
      `, [authData.license_key]);

      if (patternCheck.length > 0) {
        return {
          type: 'PATTERN_ABUSE',
          severity: 'MEDIUM',
          details: 'Suspicious authentication patterns detected',
          patterns: patternCheck
        };
      }

      return null;
    } catch (error) {
      console.error('Behavioral pattern check error:', error);
      return null;
    }
  }
}

// Enhanced Authentication with Anti-Reversing
app.get('/auth.php', authLimiter, async (req, res) => {
  const { 
    product_key: licenseKey, 
    hwid, 
    product,
    system_data: systemDataRaw
  } = req.query;
  
  const ip_address = getClientIP(req);
  const user_agent = req.get('User-Agent') || '';
  let systemData = null;
  
  // Parse system data if provided
  try {
    if (systemDataRaw) {
      systemData = JSON.parse(Buffer.from(systemDataRaw, 'base64').toString());
    }
  } catch (error) {
    console.error('System data parsing error:', error);
  }
  
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
      SELECT ul.*, u.username, u.is_banned, u.banned_until, u.analysis_flags,
             p.name as product_name, p.max_concurrent_sessions, p.anti_analysis_enabled
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
    
    // Anti-Reversing Detection
    if (license.anti_analysis_enabled && systemData) {
      const detector = new AntiReversingDetector();
      const analysisResult = await detector.analyzeSystemFingerprint(systemData);
      const behavioralFlag = await detector.checkBehavioralPatterns(license.id, { license_key: licenseKey });
      
      if (behavioralFlag) {
        analysisResult.flags.push(behavioralFlag);
        analysisResult.suspicionScore += 10;
      }
      
      // Store analysis results
      await pool.execute(`
        INSERT INTO analysis_detections (license_id, detection_flags, suspicion_score, system_fingerprint, ip_address)
        VALUES (?, ?, ?, ?, ?)
      `, [license.id, JSON.stringify(analysisResult.flags), analysisResult.suspicionScore, JSON.stringify(systemData), ip_address]);
      
      // Take action based on suspicion score
      if (analysisResult.suspicionScore >= 30) {
        // Immediate ban for high suspicion
        await pool.execute(`
          UPDATE users SET is_banned = 1, banned_until = DATE_ADD(NOW(), INTERVAL 24 HOUR),
                          ban_reason = 'Anti-analysis detection', analysis_flags = ?
          WHERE id = ?
        `, [JSON.stringify(analysisResult.flags), license.user_id]);
        
        await logActivity(`HIGH SUSPICION BAN: ${license.username} (${licenseKey}) - Score: ${analysisResult.suspicionScore}`, 'security');
        
        return res.send(ERROR_CODES.ANALYSIS_DETECTED);
      } else if (analysisResult.suspicionScore >= 15) {
        // Flag for review
        await pool.execute(`
          UPDATE users SET analysis_flags = ? WHERE id = ?
        `, [JSON.stringify(analysisResult.flags), license.user_id]);
        
        await createFraudAlert(license.id, 'analysis_detected', 'high', 
          `Analysis tools detected - Score: ${analysisResult.suspicionScore}`, 
          { flags: analysisResult.flags, score: analysisResult.suspicionScore });
      }
      
      // Return specific error codes for different detection types
      for (const flag of analysisResult.flags) {
        switch (flag.type) {
          case 'VM_DETECTED':
          case 'VM_HARDWARE':
          case 'VM_REGISTRY':
            if (flag.severity === 'HIGH') {
              return res.send(ERROR_CODES.VM_DETECTED);
            }
            break;
          case 'ANALYSIS_TOOL':
            return res.send(ERROR_CODES.DEBUGGER_DETECTED);
          case 'HOOK_DETECTED':
            return res.send(ERROR_CODES.HOOK_DETECTED);
        }
      }
    }
    
    // Standard authentication checks...
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
    
    // Continue with normal authentication flow...
    // [Rest of authentication logic from previous version]
    
    // HWID management
    if (!license.hwid) {
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
    
    // Create session and continue...
    const sessionToken = generateSecureToken();
    const expiresAt = new Date(Date.now() + (60 * 60 * 1000));
    
    await pool.execute(`
      INSERT INTO active_sessions (license_id, session_token, ip_address, hwid, user_agent, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [license.id, sessionToken, ip_address, hwid, user_agent, expiresAt]);
    
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
    
    let timeResponse = 'LIFETIME:0:0';
    if (!license.is_lifetime && license.expires_at) {
      const timeLeft = new Date(license.expires_at) - new Date();
      const daysLeft = Math.floor(timeLeft / (1000 * 60 * 60 * 24));
      const hoursLeft = Math.floor((timeLeft % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      timeResponse = `${Math.max(0, daysLeft)}:${Math.max(0, hoursLeft)}:0`;
    }
    
    res.send(`${timeResponse}:${sessionToken}`);
    
  } catch (error) {
    console.error('Auth error:', error);
    res.send(ERROR_CODES.INVALID_KEY);
  }
});

// Cloudflare R2 File Upload Handler
app.post('/admin/upload-file', requireAdminAuth('admin'), uploadLimiter, upload.fields([
  { name: 'file', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), async (req, res) => {
  try {
    const { product_id, version, description, is_update, changelog } = req.body;
    const file = req.files.file?.[0];
    const thumbnail = req.files.thumbnail?.[0];
    
    if (!file) {
      return res.json({ success: false, message: 'No file uploaded' });
    }
    
    const fileId = uuidv4();
    const fileExtension = path.extname(file.originalname);
    const fileKey = `downloads/${product_id}/${fileId}${fileExtension}`;
    
    // Read file data
    const fileData = await fs.readFile(file.path);
    
    // Upload to R2
    const uploadParams = {
      Bucket: R2_BUCKET,
      Key: fileKey,
      Body: fileData,
      ContentType: file.mimetype,
      Metadata: {
        'original-name': file.originalname,
        'product-id': product_id,
        'version': version || '1.0.0',
        'upload-date': new Date().toISOString()
      }
    };
    
    const uploadResult = await r2.upload(uploadParams).promise();
    
    // Handle thumbnail if provided
    let thumbnailKey = null;
    if (thumbnail) {
      const thumbnailId = uuidv4();
      thumbnailKey = `thumbnails/${product_id}/${thumbnailId}.webp`;
      
      // Process thumbnail with Sharp
      const thumbnailData = await sharp(thumbnail.path)
        .resize(300, 200, { fit: 'cover' })
        .webp({ quality: 80 })
        .toBuffer();
      
      await r2.upload({
        Bucket: R2_BUCKET,
        Key: thumbnailKey,
        Body: thumbnailData,
        ContentType: 'image/webp'
      }).promise();
    }
    
    // Store in database
    const [result] = await pool.execute(`
      INSERT INTO downloads (id, product_id, filename, display_name, file_key, thumbnail_key, 
                           file_size, version, description, changelog, is_update, upload_admin_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      fileId, product_id, file.originalname, file.originalname, fileKey, thumbnailKey,
      file.size, version || '1.0.0', description, changelog, is_update || 0, req.session.admin_id
    ]);
    
    // Cleanup temp files
    await fs.unlink(file.path);
    if (thumbnail) await fs.unlink(thumbnail.path);
    
    // If this is an update, optionally disable previous versions
    if (is_update) {
      await pool.execute(`
        UPDATE downloads SET is_active = 0 
        WHERE product_id = ? AND id != ? AND is_update = 0
      `, [product_id, fileId]);
    }
    
    await logActivity(`File uploaded: ${file.originalname} for product ${product_id}`, 'admin');
    
    res.json({ 
      success: true, 
      message: 'File uploaded successfully',
      fileId,
      downloadUrl: `/download/${fileId}`,
      fileKey
    });
    
  } catch (error) {
    console.error('Upload error:', error);
    res.json({ success: false, message: 'Upload failed: ' + error.message });
  }
});

// Generate Secure Download URL
app.post('/customer/get-download-url', requireCustomerAuth, async (req, res) => {
  const { download_id } = req.body;
  const userId = req.session.customer_id;
  
  try {
    // Verify access
    const [access] = await pool.execute(`
      SELECT d.*, p.name as product_name
      FROM downloads d
      JOIN products p ON d.product_id = p.id
      JOIN user_licenses ul ON ul.product_id = p.id
      WHERE d.id = ? AND ul.user_id = ? AND d.is_active = 1 AND ul.is_active = 1
    `, [download_id, userId]);
    
    if (access.length === 0) {
      return res.json({ success: false, message: 'Access denied' });
    }
    
    const download = access[0];
    
    // Generate presigned URL for R2
    const signedUrl = r2.getSignedUrl('getObject', {
      Bucket: R2_BUCKET,
      Key: download.file_key,
      Expires: 3600, // 1 hour
      ResponseContentDisposition: `attachment; filename="${download.display_name}"`
    });
    
    // Log download request
    await pool.execute(`
      INSERT INTO download_logs (user_id, download_id, ip_address, user_agent)
      VALUES (?, ?, ?, ?)
    `, [userId, download_id, getClientIP(req), req.get('User-Agent')]);
    
    res.json({ 
      success: true, 
      download_url: signedUrl,
      filename: download.display_name,
      file_size: download.file_size,
      expires_in: 3600
    });
    
  } catch (error) {
    console.error('Download URL generation error:', error);
    res.json({ success: false, message: 'Failed to generate download URL' });
  }
});

// Product Management Endpoints
app.get('/admin/products', requireAdminAuth('moderator'), async (req, res) => {
  try {
    const [products] = await pool.execute(`
      SELECT p.*, 
             COUNT(DISTINCT ul.id) as license_count,
             COUNT(DISTINCT d.id) as download_count,
             MAX(d.created_at) as latest_update
      FROM products p
      LEFT JOIN user_licenses ul ON p.id = ul.product_id AND ul.is_active = 1
      LEFT JOIN downloads d ON p.id = d.product_id AND d.is_active = 1
      GROUP BY p.id
      ORDER BY p.created_at DESC
    `);
    
    res.json({ success: true, products });
  } catch (error) {
    console.error('Products fetch error:', error);
    res.json({ success: false, message: 'Failed to fetch products' });
  }
});

app.post('/admin/products', requireAdminAuth('admin'), async (req, res) => {
  const {
    name, slug, description, price, max_concurrent_sessions,
    hwid_reset_interval_days, max_hwid_changes, anti_analysis_enabled,
    features, category
  } = req.body;
  
  try {
    const productId = uuidv4();
    
    await pool.execute(`
      INSERT INTO products (id, name, slug, description, price, max_concurrent_sessions,
                          hwid_reset_interval_days, max_hwid_changes, anti_analysis_enabled,
                          features, category, created_by_admin_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      productId, name, slug, description, price || 0, max_concurrent_sessions || 1,
      hwid_reset_interval_days || 24, max_hwid_changes || 3, anti_analysis_enabled || 0,
      JSON.stringify(features || []), category || 'software', req.session.admin_id
    ]);
    
    await logActivity(`Product created: ${name} (${slug})`, 'admin');
    
    res.json({ success: true, message: 'Product created successfully', productId });
  } catch (error) {
    console.error('Product creation error:', error);
    res.json({ success: false, message: 'Failed to create product' });
  }
});

app.put('/admin/products/:id', requireAdminAuth('admin'), async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;
  
  try {
    const setClause = Object.keys(updateData)
      .filter(key => key !== 'id')
      .map(key => `${key} = ?`)
      .join(', ');
    
    const values = Object.keys(updateData)
      .filter(key => key !== 'id')
      .map(key => updateData[key]);
    
    await pool.execute(`
      UPDATE products SET ${setClause}, updated_at = NOW() WHERE id = ?
    `, [...values, id]);
    
    res.json({ success: true, message: 'Product updated successfully' });
  } catch (error) {
    console.error('Product update error:', error);
    res.json({ success: false, message: 'Failed to update product' });
  }
});

// Bulk Operations Completion
app.post('/admin/bulk-operations', requireAdminAuth('admin'), async (req, res) => {
  const { operation, criteria, targets, action_data } = req.body;
  const adminId = req.session.admin_id;
  
  try {
    let results = { success: 0, failed: 0, details: [] };
    
    switch (operation) {
      case 'bulk_license_management':
        results = await handleBulkLicenseOperation(criteria, targets, action_data, adminId);
        break;
        
      case 'bulk_user_actions':
        results = await handleBulkUserOperation(criteria, targets, action_data, adminId);
        break;
        
      case 'bulk_product_assignment':
        results = await handleBulkProductAssignment(criteria, targets, action_data, adminId);
        break;
        
      case 'bulk_fraud_actions':
        results = await handleBulkFraudActions(criteria, targets, action_data, adminId);
        break;
        
      default:
        return res.json({ success: false, message: 'Unknown bulk operation' });
    }
    
    // Log bulk operation
    await pool.execute(`
      INSERT INTO admin_audit_log (admin_id, action, target_type, target_count, operation_data, ip_address)
      VALUES (?, ?, 'bulk', ?, ?, ?)
    `, [adminId, operation, results.success + results.failed, JSON.stringify(action_data), getClientIP(req)]);
    
    res.json({ success: true, results });
    
  } catch (error) {
    console.error('Bulk operation error:', error);
    res.json({ success: false, message: 'Bulk operation failed' });
  }
});

// Bulk Operation Handlers
async function handleBulkLicenseOperation(criteria, targets, actionData, adminId) {
  const results = { success: 0, failed: 0, details: [] };
  
  for (const target of targets) {
    try {
      switch (actionData.action) {
        case 'extend_time':
          await pool.execute(`
            UPDATE user_licenses 
            SET expires_at = DATE_ADD(COALESCE(expires_at, NOW()), INTERVAL ? DAY)
            WHERE id = ? AND is_lifetime = 0
          `, [actionData.days, target]);
          break;
          
        case 'set_lifetime':
          await pool.execute(`
            UPDATE user_licenses SET is_lifetime = 1, expires_at = NULL WHERE id = ?
          `, [target]);
          break;
          
        case 'reset_hwid':
          await pool.execute(`
            UPDATE user_licenses 
            SET hwid = NULL, hwid_locked_at = NULL, last_hwid_reset = NOW()
            WHERE id = ?
          `, [target]);
          break;
          
        case 'disable_license':
          await pool.execute(`
            UPDATE user_licenses SET is_active = 0 WHERE id = ?
          `, [target]);
          break;
      }
      
      results.success++;
    } catch (error) {
      results.failed++;
      results.details.push({ target, error: error.message });
    }
  }
  
  return results;
}

async function handleBulkUserOperation(criteria, targets, actionData, adminId) {
  const results = { success: 0, failed: 0, details: [] };
  
  for (const target of targets) {
    try {
      switch (actionData.action) {
        case 'ban_user':
          await pool.execute(`
            UPDATE users 
            SET is_banned = 1, banned_until = ?, ban_reason = ?
            WHERE id = ?
          `, [actionData.ban_until, actionData.reason, target]);
          break;
          
        case 'unban_user':
          await pool.execute(`
            UPDATE users 
            SET is_banned = 0, banned_until = NULL, ban_reason = NULL
            WHERE id = ?
          `, [target]);
          break;
          
        case 'flag_suspicious':
          await pool.execute(`
            UPDATE users 
            SET analysis_flags = JSON_ARRAY_APPEND(COALESCE(analysis_flags, '[]'), '$', ?)
            WHERE id = ?
          `, [JSON.stringify({ flag: actionData.flag, timestamp: new Date() }), target]);
          break;
      }
      
      results.success++;
    } catch (error) {
      results.failed++;
      results.details.push({ target, error: error.message });
    }
  }
  
  return results;
}

async function handleBulkProductAssignment(criteria, targets, actionData, adminId) {
  const results = { success: 0, failed: 0, details: [] };
  
  for (const target of targets) {
    try {
      const licenseKey = generateProductKey();
      
      await pool.execute(`
        INSERT INTO user_licenses (user_id, product_id, license_key, expires_at, is_lifetime, created_by_admin_id)
        VALUES (?, ?, ?, ?, ?, ?)
      `, [
        target, 
        actionData.product_id, 
        licenseKey,
        actionData.is_lifetime ? null : actionData.expires_at,
        actionData.is_lifetime || 0,
        adminId
      ]);
      
      results.success++;
    } catch (error) {
      results.failed++;
      results.details.push({ target, error: error.message });
    }
  }
  
  return results;
}

async function handleBulkFraudActions(criteria, targets, actionData, adminId) {
  const results = { success: 0, failed: 0, details: [] };
  
  for (const target of targets) {
    try {
      switch (actionData.action) {
        case 'resolve_alert':
          await pool.execute(`
            UPDATE fraud_alerts 
            SET is_resolved = 1, resolved_by_admin_id = ?, resolved_at = NOW()
            WHERE id = ?
          `, [adminId, target]);
          break;
          
        case 'escalate_alert':
          await pool.execute(`
            UPDATE fraud_alerts 
            SET severity = 'critical', escalated_by_admin_id = ?, escalated_at = NOW()
            WHERE id = ?
          `, [adminId, target]);
          break;
      }
      
      results.success++;
    } catch (error) {
      results.failed++;
      results.details.push({ target, error: error.message });
    }
  }
  
  return results;
}

// Helper Functions
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

const createFraudAlert = async (licenseId, alertType, severity, description, metadata = {}) => {
  try {
    const [license] = await pool.execute('SELECT user_id FROM user_licenses WHERE id = ?', [licenseId]);
    const userId = license[0]?.user_id;
    
    await pool.execute(`
      INSERT INTO fraud_alerts (user_id, license_id, alert_type, severity, description, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [userId, licenseId, alertType, severity, description, JSON.stringify(metadata)]);
    
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

// Cleanup expired data periodically
setInterval(async () => {
  try {
    await pool.execute('DELETE FROM active_sessions WHERE expires_at < NOW()');
    await pool.execute('DELETE FROM download_tokens WHERE expires_at < NOW()');
    await pool.execute('CALL DetectRapidHwidChanges()');
    
    // Cleanup temporary analysis flags older than 7 days
    await pool.execute(`
      UPDATE users 
      SET analysis_flags = NULL 
      WHERE analysis_flags IS NOT NULL 
      AND JSON_EXTRACT(analysis_flags, '$[0].timestamp') < DATE_SUB(NOW(), INTERVAL 7 DAY)
    `);
  } catch (error) {
    console.error('Cleanup error:', error);
  }
}, 5 * 60 * 1000); // Every 5 minutes

// WebSocket for real-time admin monitoring
io.on('connection', (socket) => {
  socket.on('join-admin', (data) => {
    if (data.adminId) {
      socket.join('admin-room');
      socket.emit('connected', { message: 'Connected to security monitoring' });
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Admin disconnected from monitoring');
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Enhanced Security Authentication Server running on port ${PORT}`);
  console.log('Anti-reversing detection enabled');
  console.log('Cloudflare R2 integration active');
});

module.exports = app;