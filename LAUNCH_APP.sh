#!/bin/bash
# Launch script for Forgotten-E2EE Web Application

cd "$(dirname "$0")"

echo "🔐 Forgotten-E2EE Web Application Launcher"
echo "=========================================="
echo ""

# Check if port is in use
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
    echo "⚠️  Port 8080 is already in use"
    echo "   Killing existing process..."
    lsof -ti:8080 | xargs kill -9 2>/dev/null
    sleep 1
fi

# Verify tests pass
echo "🧪 Verifying tests..."
python -m pytest testing/test_suites/test_user_errors.py -q --tb=no > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "   ✅ All 50 user error tests passing"
else
    echo "   ⚠️  Some tests failed (continuing anyway)"
fi

echo ""
echo "🚀 Starting Flask application..."
echo ""
echo "📋 Application will be available at:"
echo "   Main Interface: http://127.0.0.1:8080/"
echo "   Embed Version:  http://127.0.0.1:8080/embed"
echo "   Health Check:   http://127.0.0.1:8080/health"
echo ""
echo "⏹️  Press Ctrl+C to stop the server"
echo ""
echo "=========================================="
echo ""

# Start the application
export PORT=8080
export FLASK_DEBUG=False
python web_app/app.py

