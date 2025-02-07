#!/usr/bin/env bash
set -euo pipefail

echo "=== CyberShield AI Setup ==="

python3 -c "import sys; assert sys.version_info >= (3,11), 'Python 3.11+ required'" || {
    echo "ERROR: Python 3.11+ required"
    exit 1
}

if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env"
fi

mkdir -p reports

cd backend
pip install -r requirements.txt

echo ""
echo "Optional: Install gitleaks, trufflehog, bearer for extended scanning"
echo "Start with: docker-compose up --build"
