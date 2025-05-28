#!/bin/bash

# Authentication System Cleanup Script
# This script will organize your files and remove duplicates
  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🧹 Authentication System Cleanup${NC}"
echo "This script will organize your files and remove duplicates."
echo -e "${YELLOW}⚠️  Make sure to backup your files before running this!${NC}"
echo ""

read -p "Continue with cleanup? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled."
    exit 1
fi

echo -e "${GREEN}Starting cleanup...${NC}"

# 1. Remove duplicate and unnecessary files
echo -e "${YELLOW}🗑️  Removing duplicates and empty files...${NC}"

# Remove duplicates
rm -f enhanced-auth-system/database/01-init-schema.sql 2>/dev/null || true
rm -f public/enhanced_backend.js 2>/dev/null || true
rm -f public/admin_styles.css 2>/dev/null || true
rm -f public/customer_styles.css 2>/dev/null || true
rm -f public/style.css 2>/dev/null || true
rm -f package.json.save 2>/dev/null || true
rm -f style.css 2>/dev/null || true
rm -f database_schema.sql 2>/dev/null || true

# Remove empty HTML files
rm -f admin-login.html 2>/dev/null || true
rm -f customer-login.html 2>/dev/null || true
rm -f login.html 2>/dev/null || true
rm -f public/admin-login.html 2>/dev/null || true
rm -f public/customer-login.html 2>/dev/null || true
rm -f public/login.html 2>/dev/null || true

# Remove empty directories
rmdir enhanced-auth-system/database 2>/dev/null || true
rmdir enhanced-auth-system 2>/dev/null || true

echo -e "${GREEN}✅ Removed duplicate files${NC}"

# 2. Create proper directory structure
echo -e "${YELLOW}📁 Creating directory structure...${NC}"

mkdir -p src/{controllers,middleware,routes,utils}
mkdir -p public/{css,js,views}
mkdir -p scripts
mkdir -p config
mkdir -p database/migrations
mkdir -p temp

echo -e "${GREEN}✅ Directory structure created${NC}"

# 3. Move files to correct locations
echo -e "${YELLOW}📦 Reorganizing files...${NC}"

# Move main backend file
if [ -f "enhanced_backend.js" ]; then
    mv enhanced_backend.js server.js
    echo "✅ Moved enhanced_backend.js → server.js"
elif [ -f "nodejs_backend.js" ]; then
    mv nodejs_backend.js server.js
    echo "✅ Moved nodejs_backend.js → server.js"
fi

# Move database files
if [ -f "enhanced_database_schema.sql" ]; then
    mv enhanced_database_schema.sql database/schema.sql
    echo "✅ Moved enhanced_database_schema.sql → database/schema.sql"
elif [ -f "database/01-init-schema.sql" ]; then
    mv database/01-init-schema.sql database/schema.sql
    echo "✅ Moved database/01-init-schema.sql → database/schema.sql"
fi

# Move CSS files
if [ -f "admin_styles.css" ]; then
    mv admin_styles.css public/css/admin.css
    echo "✅ Moved admin_styles.css → public/css/admin.css"
fi

if [ -f "customer_styles.css" ]; then
    mv customer_styles.css public/css/customer.css
    echo "✅ Moved customer_styles.css → public/css/customer.css"
fi

# Move scripts
if [ -f "mysql_quick_setup.sh" ]; then
    mv mysql_quick_setup.sh scripts/setup-database.sh
    chmod +x scripts/setup-database.sh
    echo "✅ Moved mysql_quick_setup.sh → scripts/setup-database.sh"
fi

if [ -f "test-db.js" ]; then
    mv test-db.js scripts/test-connection.js
    echo "✅ Moved test-db.js → scripts/test-connection.js"
fi

# Create .env.example from environment config
if [ -f "environment_config.sh" ]; then
    mv environment_config.sh .env.example
    echo "✅ Moved environment_config.sh → .env.example"
fi

echo -e "${GREEN}✅ Files reorganized${NC}"

# 4. Create essential missing files
echo -e "${YELLOW}📄 Creating missing files...${NC}"

# Create .gitignore
cat > .gitignore << 'EOF'
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment files
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Logs
logs/
*.log

# Runtime files
pids/
*.pid
*.seed
*.pid.lock

# Uploads and temporary files
uploads/
temp/
tmp/

# Database
*.sqlite
*.db

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDE files
.vscode/
.idea/
*.swp
*.swo

# Build outputs
dist/
build/

# MySQL credentials (if generated)
mysql_credentials.txt
EOF

echo "✅ Created .gitignore"

# Create README.md
cat > README.md << 'EOF'
# Advanced Authentication System

A comprehensive authentication system with anti-cheat detection, fraud monitoring, and real-time admin dashboard.

## Features

- 🔐 Multi-product license management
- 🛡️ Advanced anti-reversing detection
- 🚫 Real-time fraud detection
- 📊 Admin dashboard with live monitoring
- 👥 Customer portal with HWID management
- 🌐 Geographic IP tracking
- 📁 Secure file downloads with Cloudflare R2
- 🔔 WebSocket real-time notifications

## Quick Setup

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Setup Database**
   ```bash
   chmod +x scripts/setup-database.sh
   ./scripts/setup-database.sh
   ```

3. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your actual values
   ```

4. **Start the Server**
   ```bash
   npm start
   ```

## Project Structure

```
├── config/          # Configuration files
├── database/        # Database schemas and migrations
├── src/             # Source code
│   ├── controllers/ # Request handlers
│   ├── middleware/  # Express middleware
│   ├── routes/      # API routes
│   └── utils/       # Utility functions
├── public/          # Static files
│   ├── css/         # Stylesheets
│   ├── js/          # Client-side JavaScript
│   └── views/       # HTML templates
├── scripts/         # Setup and utility scripts
└── logs/            # Application logs
```

## API Endpoints

### Authentication
- `GET /auth.php` - License authentication endpoint
- `POST /customer/login` - Customer login
- `POST /admin/login` - Admin login

### Customer Portal
- `GET /customer/dashboard` - Customer dashboard
- `POST /customer/reset-hwid` - Reset HWID
- `GET /customer/downloads` - Available downloads

### Admin Panel
- `GET /admin/dashboard` - Admin dashboard
- `POST /admin/bulk-action` - Bulk operations
- `POST /admin/upload-file` - File upload

## Security Features

- Rate limiting on all endpoints
- HWID binding and tracking
- Geographic impossibility detection
- VM/Analysis tool detection
- Session management
- 2FA support

## License

MIT License - See LICENSE file for details
EOF

echo "✅ Created README.md"

# Create basic HTML templates
mkdir -p public/views

cat > public/views/admin-login.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Auth System</title>
    <link href="/css/admin.css" rel="stylesheet">
</head>
<body>
    <div class="login-container">
        <div class="login-form">
            <h1>Admin Login</h1>
            <form id="loginForm">
                <div class="form-group">
                    <input type="text" id="username" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" id="password" placeholder="Password" required>
                </div>
                <button type="submit" class="btn-primary">Login</button>
            </form>
        </div>
    </div>
</body>
</html>
EOF

echo "✅ Created admin-login.html template"

# 5. Final cleanup
echo -e "${YELLOW}🧹 Final cleanup...${NC}"

# Remove any remaining empty directories
find . -type d -empty -delete 2>/dev/null || true

echo -e "${GREEN}✅ Cleanup completed successfully!${NC}"
echo ""
echo -e "${BLUE}📋 Summary:${NC}"
echo "✅ Removed duplicate and empty files"
echo "✅ Created organized directory structure"
echo "✅ Moved files to appropriate locations"
echo "✅ Created essential configuration files"
echo "✅ Added proper .gitignore"
echo "✅ Created README.md with documentation"
echo ""
echo -e "${YELLOW}⚠️  Next Steps:${NC}"
echo "1. Review your .env file configuration"
echo "2. Test database connection: node scripts/test-connection.js"
echo "3. Install dependencies: npm install"
echo "4. Start the server: npm start"
echo ""
echo -e "${GREEN}🎉 Your authentication system is now organized!${NC}"