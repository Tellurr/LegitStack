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
