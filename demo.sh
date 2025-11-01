#!/bin/bash

echo "🎬 Adapt Security Demo"
echo "====================="
echo ""

# Check if GROQ_API_KEY is set
if [ -z "$GROQ_API_KEY" ]; then
    echo "❌ GROQ_API_KEY not set!"
    echo ""
    echo "Get your key from: https://console.groq.com"
    echo "Then run: export GROQ_API_KEY='your-key'"
    exit 1
fi

echo "✅ GROQ_API_KEY is set"
echo ""

# Create a test file with vulnerabilities
echo "📝 Creating test file with intentional vulnerabilities..."

cat > test_vulnerable.py << 'EOF'
import sqlite3
import os

# VULNERABILITY 1: Hardcoded password
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def get_user(username):
    # VULNERABILITY 2: SQL Injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input):
    # VULNERABILITY 3: Command Injection
    os.system(f"echo {user_input}")

def render_html(user_data):
    # VULNERABILITY 4: XSS
    html = f"<div>{user_data}</div>"
    return html

# GOOD PRACTICE: Using environment variable
SAFE_API_KEY = os.environ.get('API_KEY')
EOF

echo "✅ Test file created: test_vulnerable.py"
echo ""

# Stage the file
git add test_vulnerable.py

echo "📊 Running Adapt Security Review..."
echo ""

# Run the CLI review
python adapt_cli.py review --no-save

echo ""
echo "🎉 Demo complete!"
echo ""
echo "What just happened:"
echo "  1. Created a Python file with 4 intentional vulnerabilities"
echo "  2. Staged it with git add"
echo "  3. Ran 'adapt review' which:"
echo "     - Detected SQL injection"
echo "     - Found hardcoded secrets"
echo "     - Identified command injection risk"
echo "     - Caught XSS vulnerability"
echo "     - Acknowledged the good practice (env var)"
echo ""
echo "Try it with your own code:"
echo "  1. Make changes to your code"
echo "  2. git add your-files"
echo "  3. adapt review"
echo ""

# Clean up
read -p "Clean up test file? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    git reset test_vulnerable.py
    rm test_vulnerable.py
    echo "✅ Cleaned up"
fi