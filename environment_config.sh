# Enhanced Authentication System Environment Configuration
# Copy this file to .env and configure with your actual values

# Server Configuration
NODE_ENV=production
PORT=3000

# Database Configuration
DB_HOST=localhost
DB_USER=auth_user
DB_PASSWORD=your_secure_database_password_here
DB_NAME=advanced_auth

# Session Configuration
SESSION_NAME=auth_session_secure
SESSION_SECRET=your_super_secure_session_secret_change_this_in_production

# Admin Authentication (Default - Change Immediately)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change_this_secure_password

# Cloudflare R2 Configuration
# Get these from your Cloudflare R2 dashboard
R2_ENDPOINT=https://your-account-id.r2.cloudflarestorage.com
R2_ACCESS_KEY_ID=your_r2_access_key_id
R2_SECRET_ACCESS_KEY=your_r2_secret_access_key
R2_BUCKET_NAME=auth-system-downloads

# API Configuration
API_KEY=your_secure_api_key_for_external_integrations

# Security Configuration
# Rate limiting
AUTH_RATE_LIMIT_WINDOW_MS=900000
AUTH_RATE_LIMIT_MAX_ATTEMPTS=100
LOGIN_RATE_LIMIT_MAX_ATTEMPTS=5

# Anti-Analysis Detection Settings
ANTI_ANALYSIS_ENABLED=true
MAX_SUSPICION_SCORE=30
AUTO_BAN_THRESHOLD=25
BEHAVIORAL_ANALYSIS_ENABLED=true

# HWID Management
HWID_RESET_COOLDOWN_HOURS=24
MAX_HWID_CHANGES_PER_DAY=3
HWID_LOCK_AFTER_FIRST_AUTH=true

# Download Security
DOWNLOAD_TOKEN_EXPIRY_HOURS=2
MAX_DOWNLOAD_ATTEMPTS=3
DOWNLOAD_RATE_LIMIT_PER_HOUR=10

# Fraud Detection Thresholds
RAPID_AUTH_THRESHOLD=50
UNIQUE_IP_THRESHOLD=10
GEO_IMPOSSIBILITY_MINUTES=60
CONCURRENT_SESSION_LIMIT=3

# File Upload Limits
MAX_FILE_SIZE_MB=500
ALLOWED_FILE_TYPES=exe,zip,rar,7z,tar,gz,dll,sys,bin

# Logging Configuration
LOG_LEVEL=info
LOG_FILE_PATH=/var/log/auth-system/app.log
AUDIT_LOG_RETENTION_DAYS=180
AUTH_LOG_RETENTION_DAYS=90

# Email Configuration (for notifications)
SMTP_HOST=smtp.your-provider.com
SMTP_PORT=587
SMTP_USER=your_email@domain.com
SMTP_PASS=your_email_password
NOTIFICATION_EMAIL=admin@yourdomain.com

# Webhook Configuration (for external integrations)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your/webhook
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your/slack/webhook

# Redis Configuration (for caching and sessions)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password
REDIS_DB=0

# SSL/TLS Configuration
SSL_CERT_PATH=/path/to/your/certificate.crt
SSL_KEY_PATH=/path/to/your/private.key
FORCE_HTTPS=true

# Performance Configuration
CONNECTION_POOL_LIMIT=20
CONNECTION_QUEUE_LIMIT=0
CLEANUP_INTERVAL_MINUTES=5

# Development/Debug Settings (disable in production)
DEBUG_MODE=false
VERBOSE_LOGGING=false
ENABLE_CORS=false
ALLOW_INSECURE_ORIGINS=false

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_INTERVAL_HOURS=6
BACKUP_RETENTION_DAYS=30
BACKUP_LOCATION=/var/backups/auth-system/

# Monitoring Configuration
ENABLE_METRICS=true
METRICS_PORT=9090
HEALTH_CHECK_ENDPOINT=/health

# Feature Flags
FEATURE_2FA_REQUIRED=false
FEATURE_IP_WHITELISTING=false
FEATURE_DEVICE_FINGERPRINTING=true
FEATURE_MACHINE_LEARNING_DETECTION=false

# Advanced Security Features
ENABLE_HONEYPOT_DETECTION=true
ENABLE_TOR_DETECTION=true
ENABLE_VPN_DETECTION=true
ENABLE_PROXY_DETECTION=true

# License Management
DEFAULT_LICENSE_DURATION_DAYS=30
MAX_LICENSE_EXTENSIONS=5
ALLOW_TRIAL_LICENSES=true
TRIAL_DURATION_DAYS=7

# Product Management
DEFAULT_MAX_CONCURRENT_SESSIONS=1
ALLOW_PRODUCT_UPDATES=true
AUTO_ASSIGN_DOWNLOADS=true

# Compliance and Privacy
GDPR_COMPLIANCE_MODE=true
DATA_RETENTION_POLICY_DAYS=365
ANONYMOUS_ANALYTICS=true
COOKIE_CONSENT_REQUIRED=true

# Integration with External Services
VIRUSTOTAL_API_KEY=your_virustotal_api_key
THREAT_INTEL_API_KEY=your_threat_intel_api_key
GEO_IP_API_KEY=your_geo_ip_api_key

# Clustering Configuration (for load balancing)
CLUSTER_MODE=false
CLUSTER_NODES=node1:3000,node2:3000
LOAD_BALANCER_IP=your_load_balancer_ip

# Maintenance Mode
MAINTENANCE_MODE=false
MAINTENANCE_MESSAGE="System is under maintenance. Please try again later."
MAINTENANCE_WHITELIST_IPS=127.0.0.1,your_admin_ip

# Analytics and Reporting
ANALYTICS_ENABLED=true
DAILY_REPORTS=true
WEEKLY_REPORTS=true
MONTHLY_REPORTS=true
REPORT_EMAIL_RECIPIENTS=admin@yourdomain.com,security@yourdomain.com