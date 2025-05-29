#!/bin/bash

# Quick MySQL Setup Script for Authentication System
# This script automates the MySQL setup process

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
DB_NAME="legit_auth"
DB_USER="auth_user"
DB_ROOT_PASSWORD="p6qr9a2GDma"
DB_USER_PASSWORD="LQv3c1yqBWVHxkd0"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Function to check if MySQL is installed and running
check_mysql() {
    print_step "Checking MySQL installation..."
    
    if ! command -v mysql &> /dev/null; then
        print_error "MySQL is not installed. Please install MySQL first."
        echo "Installation commands:"
        echo "Ubuntu/Debian: sudo apt install mysql-server"
        echo "CentOS/RHEL: sudo dnf install mysql-server"
        echo "macOS: brew install mysql"
        exit 1
    fi
    
    # Check if MySQL service is running
    if ! systemctl is-active --quiet mysqld 2>/dev/null && ! systemctl is-active --quiet mysql 2>/dev/null; then
        print_warning "MySQL service is not running. Attempting to start..."
        
        # Try different service names
        if systemctl list-unit-files | grep -q mysqld; then
            sudo systemctl start mysqld
            sudo systemctl enable mysqld
        elif systemctl list-unit-files | grep -q mysql; then
            sudo systemctl start mysql
            sudo systemctl enable mysql
        else
            print_error "Could not start MySQL service. Please start it manually."
            exit 1
        fi
    fi
    
    print_status "MySQL is installed and running."
}

# Function to get MySQL root password
get_root_password() {
    print_step "MySQL root password required..."
    
    # First, try to connect without password (fresh installation)
    if mysql -u root -e "SELECT 1;" &>/dev/null; then
        print_status "MySQL root has no password set."
        DB_ROOT_PASSWORD=""
        return
    fi
    
    # Try to get temporary password from log (CentOS/RHEL)
    if [ -f /var/log/mysqld.log ]; then
        TEMP_PASS=$(sudo grep 'temporary password' /var/log/mysqld.log 2>/dev/null | tail -1 | awk '{print $NF}')
        if [ ! -z "$TEMP_PASS" ]; then
            print_status "Found temporary password in MySQL log."
            DB_ROOT_PASSWORD="$TEMP_PASS"
            return
        fi
    fi
    
    # Ask user for password
    echo -n "Enter MySQL root password: "
    read -s DB_ROOT_PASSWORD
    echo
    
    # Test the password
    if ! mysql -u root -p"$DB_ROOT_PASSWORD" -e "SELECT 1;" &>/dev/null; then
        print_error "Invalid MySQL root password."
        exit 1
    fi
    
    print_status "MySQL root password verified."
}

# Function to generate secure random password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-16
}

# Function to create database and user
setup_database() {
    print_step "Setting up database and user..."
    
    # Generate secure password for auth_user
    DB_USER_PASSWORD=$(generate_password)
    
    # Create SQL commands
    SQL_COMMANDS="
    -- Create database
    CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    
    -- Create user (drop if exists first)
    DROP USER IF EXISTS '${DB_USER}'@'localhost';
    CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_USER_PASSWORD}';
    
    -- Grant privileges
    GRANT SELECT, INSERT, UPDATE, DELETE ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
    GRANT CREATE, ALTER, INDEX, REFERENCES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
    
    -- Apply changes
    FLUSH PRIVILEGES;
    
    -- Select database
    USE ${DB_NAME};
    
    -- Create consumers table
    CREATE TABLE IF NOT EXISTS \`consumers\` (
      \`id\` int(11) NOT NULL AUTO_INCREMENT,
      \`hwid\` varchar(255) DEFAULT '0',
      \`start_date\` varchar(50) DEFAULT '0',
      \`product_key\` varchar(50) NOT NULL UNIQUE,
      \`script_public\` varchar(100) DEFAULT '0',
      \`script_private\` varchar(100) DEFAULT '0',
      \`is_banned\` tinyint(1) DEFAULT 0,
      \`ip\` varchar(45) DEFAULT '0',
      \`created_at\` timestamp DEFAULT CURRENT_TIMESTAMP,
      \`updated_at\` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (\`id\`),
      KEY \`idx_product_key\` (\`product_key\`),
      KEY \`idx_hwid\` (\`hwid\`),
      KEY \`idx_ip\` (\`ip\`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    
    -- Create admin_users table
    CREATE TABLE IF NOT EXISTS \`admin_users\` (
      \`id\` int(11) NOT NULL AUTO_INCREMENT,
      \`username\` varchar(50) NOT NULL UNIQUE,
      \`password_hash\` varchar(255) NOT NULL,
      \`created_at\` timestamp DEFAULT CURRENT_TIMESTAMP,
      \`last_login\` timestamp NULL DEFAULT NULL,
      PRIMARY KEY (\`id\`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    
    -- Insert test data
    INSERT IGNORE INTO \`consumers\` (\`hwid\`, \`start_date\`, \`product_key\`, \`script_public\`, \`script_private\`, \`is_banned\`, \`ip\`) VALUES
    ('0', '0', 'TEST1-ABCD-1234', '7 Days', '0', 0, '0'),
    ('0', '0', 'TEST2-EFGH-5678', '0', '30 Days', 0, '0'),
    ('0', '0', 'TEST3-IJKL-9012', 'LIFETIME', 'LIFETIME', 0, '0');
    "
    
    # Execute SQL commands
    if [ -z "$DB_ROOT_PASSWORD" ]; then
        echo "$SQL_COMMANDS" | mysql -u root
    else
        echo "$SQL_COMMANDS" | mysql -u root -p"$DB_ROOT_PASSWORD"
    fi
    
    print_status "Database and user created successfully."
    print_status "Database: $DB_NAME"
    print_status "User: $DB_USER"
    print_status "Password: $DB_USER_PASSWORD"
}

# Function to test the connection
test_connection() {
    print_step "Testing database connection..."
    
    # Test connection with new user
    if mysql -u "$DB_USER" -p"$DB_USER_PASSWORD" -e "USE $DB_NAME; SELECT COUNT(*) as consumer_count FROM consumers;" 2>/dev/null; then
        print_status "Database connection test successful!"
    else
        print_error "Database connection test failed!"
        exit 1
    fi
}

# Function to create .env file
create_env_file() {
    print_step "Creating .env configuration file..."
    
    # Generate secure session secret
    SESSION_SECRET=$(openssl rand -base64 32)
    API_KEY=$(openssl rand -hex 16)
    
    cat > .env << EOF
# Database Configuration
DB_HOST=localhost
DB_USER=${DB_USER}
DB_PASSWORD=${DB_USER_PASSWORD}
DB_NAME=${DB_NAME}
DB_PORT=3306

# Server Configuration
PORT=3000
NODE_ENV=development

# Session Configuration
SESSION_SECRET=${SESSION_SECRET}
SESSION_NAME=auth_session

# Admin Configuration
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123

# API Configuration
API_KEY=${API_KEY}

# Logging
LOG_FILE_PATH=./logs/app.log

# Application
APP_NAME=Security Research Auth Panel
APP_VERSION=1.0.0
EOF
    
    print_status ".env file created successfully."
    print_warning "Please change the ADMIN_PASSWORD in .env file!"
}

# Function to create log directory
setup_logging() {
    print_step "Setting up logging directory..."
    
    # Create logs directory
    mkdir -p logs
    touch logs/app.log
    chmod 666 logs/app.log
    
    print_status "Logging directory created: ./logs/"
}

# Function to display final instructions
show_final_instructions() {
    print_status "Setup completed successfully!"
    echo
    echo -e "${BLUE}Database Configuration:${NC}"
    echo "  Database: $DB_NAME"
    echo "  User: $DB_USER"
    echo "  Password: $DB_USER_PASSWORD"
    echo
    echo -e "${BLUE}Next Steps:${NC}"
    echo "1. Install Node.js dependencies:"
    echo "   npm install"
    echo
    echo "2. Update admin password in .env file:"
    echo "   nano .env"
    echo
    echo "3. Start the application:"
    echo "   npm run dev"
    echo
    echo "4. Test the setup:"
    echo "   curl \"http://localhost:3000/auth.php?product_key=TEST1-ABCD-1234&hwid=test123&module=script_public&id=12345\""
    echo
    echo -e "${YELLOW}Security Notes:${NC}"
    echo "- Change the default admin password"
    echo "- Keep the .env file secure (it contains sensitive credentials)"
    echo "- Consider enabling MySQL SSL for production"
    echo "- Regularly backup your database"
}

# Function to cleanup on error
cleanup() {
    print_error "Setup failed. Cleaning up..."
    # Add any cleanup logic here if needed
}

# Set trap for cleanup on error
trap cleanup ERR

# Main execution
main() {
    echo -e "${GREEN}=== MySQL Authentication System Setup ===${NC}"
    echo
    
    check_mysql
    get_root_password
    setup_database
    test_connection
    create_env_file
    setup_logging
    show_final_instructions
}

# Check if running as root (not recommended)
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root is not recommended for security reasons."
    echo -n "Continue anyway? (y/N): "
    read -r REPLY
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Run main function
main

# Save credentials to a secure file
{
    echo "# MySQL Credentials - Keep this file secure!"
    echo "Database: $DB_NAME"
    echo "Username: $DB_USER"
    echo "Password: $DB_USER_PASSWORD"
    echo "Generated: $(date)"
} > mysql_credentials.txt

chmod 600 mysql_credentials.txt
print_status "Credentials saved to mysql_credentials.txt (secure file permissions set)"

print_status "Setup script completed successfully!"
