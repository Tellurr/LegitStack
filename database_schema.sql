{
  "name": "advanced-auth-system",
  "version": "2.0.0",
  "description": "Advanced Authentication System with Multi-Product Support, Fraud Detection, and Real-time Monitoring",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "setup": "node setup/database-setup.js",
    "test": "jest",
    "lint": "eslint .",
    "build": "webpack --mode production",
    "migrate": "node migrations/migrate.js"
  },
  "keywords": [
    "authentication",
    "security",
    "nodejs",
    "mysql",
    "anti-cheat",
    "fraud-detection",
    "real-time",
    "websocket"
  ],
  "author": "Security Research Team",
  "license": "MIT",
  "dependencies": {
    "express": "^4.18.2",
    "mysql2": "^3.6.3",
    "express-session": "^1.17.3",
    "express-mysql-session": "^3.0.0",
    "bcrypt": "^5.1.1",
    "speakeasy": "^2.0.0",
    "qrcode": "^1.5.3",
    "geoip-lite": "^1.4.7",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "multer": "^1.4.5-lts.1",
    "socket.io": "^4.7.4",
    "dotenv": "^16.3.1",
    "crypto": "^1.0.1",
    "jsonwebtoken": "^9.0.2",
    "nodemailer": "^6.9.7",
    "sharp": "^0.33.0",
    "archiver": "^6.0.1",
    "moment": "^2.29.4",
    "lodash": "^4.17.21",
    "validator": "^13.11.0",
    "express-validator": "^7.0.1",
    "winston": "^3.11.0",
    "morgan": "^1.10.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "supertest": "^6.3.3",
    "eslint": "^8.54.0",
    "eslint-config-standard": "^17.1.0",
    "webpack": "^5.89.0",
    "webpack-cli": "^5.1.4",
    "@babel/core": "^7.23.3",
    "@babel/preset-env": "^7.23.3",
    "babel-loader": "^9.1.3"
  },
  "engines": {
    "node": ">=16.0.0",
    "npm": ">=8.0.0"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/your-org/advanced-auth-system.git"
  },
  "bugs": {
    "url": "https://github.com/your-org/advanced-auth-system/issues"
  },
  "homepage": "https://github.com/your-org/advanced-auth-system#readme"
}