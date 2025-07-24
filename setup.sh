#!/bin/bash

# CertNode Local Development Setup Script

set -e

echo "🚀 CertNode Development Setup"
echo "=============================="

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
echo "❌ Python $REQUIRED_VERSION or higher required. Found: $PYTHON_VERSION"
exit 1
fi

echo "✅ Python version: $PYTHON_VERSION"

# Create project directory structure
echo "📁 Creating directory structure…"
mkdir -p certnode/{vault,certified_outputs,logs,trust_badges,config,tests,docs}

# Create virtual environment
echo "🐍 Creating virtual environment…"
python3 -m venv certnode/venv

# Activate virtual environment
echo "⚡ Activating virtual environment…"
source certnode/venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip…"
pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies…"
pip install -r requirements.txt

# Copy CertNode modules
echo "📋 Setting up CertNode modules…"
cp *.py certnode/
cp *.json certnode/

# Set up configuration
echo "⚙️  Creating configuration…"
cat > certnode/config/certnode.conf << EOF
[certnode]
operator = SRB Creative Holdings LLC
environment = development
debug = true
log_level = INFO

[database]
vault_path = vault/certnode_vault.db
backup_retention = 30

[api]
host = 127.0.0.1
port = 8000
rate_limit = 100
enable_cors = true

[security]
require_https = false
api_key_required = false
max_content_size = 1048576

[processing]
max_workers = 4
timeout = 30
cache_results = true
EOF

# Create development environment file
cat > certnode/.env << EOF
CERTNODE_ENV=development
CERTNODE_DEBUG=true
CERTNODE_LOG_LEVEL=INFO
CERTNODE_API_HOST=127.0.0.1
CERTNODE_API_PORT=8000
EOF

# Set executable permissions
chmod +x certnode/certnode_main.py
chmod +x certnode/certnode_cli.py
chmod +x certnode/certnode_api.py

# Initialize vault database
echo "🗄️  Initializing vault database…"
cd certnode
python3 -c "
from vault_manager import VaultManager
vm = VaultManager()
print('✅ Vault database initialized')
"

# Test system status
echo "🧪 Testing system status…"
python3 certnode_main.py --system-info

echo ""
echo "✅ CertNode development setup complete!"
echo ""
echo "🚀 Quick Start Commands:"
echo "  cd certnode"
echo "  source venv/bin/activate"
echo "  python3 certnode_main.py --interactive"
echo ""
echo "🌐 Start API server:"
echo "  python3 certnode_api.py --debug"
echo ""
echo "📖 Run tests:"
echo "  python3 -m pytest tests/"
echo ""

