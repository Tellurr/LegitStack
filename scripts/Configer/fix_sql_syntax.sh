#!/bin/bash

# Fix SQL Syntax Error in nodejs_backend.js

echo "🔧 Fixing SQL syntax error in nodejs_backend.js..."

# Check if the file exists
if [ ! -f "nodejs_backend.js" ]; then
    echo "❌ nodejs_backend.js not found!"
    exit 1
fi

# Create backup
cp nodejs_backend.js nodejs_backend.js.backup.$(date +%Y%m%d_%H%M%S)
echo "💾 Backup created"

# Fix common SQL syntax issues
echo "🔍 Checking for malformed SQL queries..."

# Check around line 1071 for the specific error
grep -n "SELECT COUNT" nodejs_backend.js | head -5

echo ""
echo "📝 Most likely issues:"
echo "1. Missing backticks around SQL query"
echo "2. Unclosed template literal"
echo "3. Missing quotes around SQL string"

# Try to automatically fix common patterns
echo ""
echo "🔧 Attempting automatic fixes..."

# Fix pattern 1: SQL query not in backticks
sed -i.tmp 's/pool\.execute(\s*SELECT/pool.execute(`SELECT/g' nodejs_backend.js
sed -i.tmp 's/WHERE id = ?)/WHERE id = ?`)/g' nodejs_backend.js

# Fix pattern 2: Missing backticks around multiline SQL
perl -i -pe 'BEGIN{undef $/;} s/pool\.execute\(\s*\n\s*SELECT(.*?)\n\s*\]/pool.execute(`\n      SELECT$1\n    `]/smg' nodejs_backend.js

# Fix pattern 3: Common malformed queries
sed -i.tmp 's/pool\.execute(\s*"/pool.execute(`/g' nodejs_backend.js
sed -i.tmp 's/", \[/\`, [/g' nodejs_backend.js

echo "✅ Basic fixes applied"

# Clean up temp files
rm -f nodejs_backend.js.tmp

echo ""
echo "🎯 Next steps:"
echo "1. Check if 'node nodejs_backend.js' now works"
echo "2. If not, manually check around line 1071 for SQL syntax"
echo "3. Look for queries missing backticks or quotes"