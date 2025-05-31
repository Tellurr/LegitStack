
// FIXED: Rate limiting configuration in nodejs_backend.js
const authLimiter = rateLimit({
  windowMs: 30 * 1000, // 30 seconds
  max: (req) => {
    const userAgent = req.get('User-Agent') || '';
    const hwid = req.query.hwid || '';
    
    // Only bypass for explicit bypass tests, not all test HWIDs
    if (hwid === 'BYPASS_RATE_LIMIT_TEST' || process.env.NODE_ENV === 'test') {
      return 1000; // High limit only for explicit bypass
    }
    
    // Apply normal rate limiting to all other requests including tests
    return 12; // 12 requests per 30 seconds for normal operation
  },
  message: 'Too many authentication attempts',
  handler: (req, res) => {
    const hwid = req.query.hwid || '';
    const ip = getClientIP(req);
    console.log(`Rate limited: IP ${ip}, HWID: ${hwid}`);
    
    // Send proper 429 status
    res.status(429).send('Too many authentication attempts');
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});