-- Quick fix to add email column to users table
-- Use this for immediate fix of the login error

USE legitdb;

-- Add email column (ignore error if it already exists)
ALTER TABLE users ADD COLUMN email VARCHAR(255) NULL;

-- Give existing users email addresses based on their username
UPDATE users SET email = CONCAT(username, '@example.com') WHERE email IS NULL;

-- Add unique constraint to email
ALTER TABLE users ADD UNIQUE KEY unique_email (email);

-- Test that the fix worked
SELECT username, email FROM users LIMIT 5;
SELECT 'Email column added successfully!' as status;