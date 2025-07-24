#!/bin/bash

# CertNode Production Deployment Script

set -e

DEPLOYMENT_TYPE=${1:-"single-server"}
DOMAIN=${2:-"certnode.example.com"}
EMAIL=${3:-"admin@example.com"}

echo "🚀 CertNode Production Deployment"
echo "=================================="
echo "Deployment Type: $DEPLOYMENT_TYPE"
echo "Domain: $DOMAIN"
echo "Admin Email: $EMAIL"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    log_error "This script should not be run as root for security reasons"
    exit 1
fi

# Check system requirements
check_requirements() {
    log_info "Checking system requirements…"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3.8+ is required"
        exit 1
    fi

    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
    if [ "$(printf '%s\n' "3.8" "$PYTHON_VERSION" | sort -V | head -n1)" != "3.8" ]; then
        log_error "Python 3.8+ required. Found: $PYTHON_VERSION"
        exit 1
    fi

    # Check Docker if needed
    if [[ "$DEPLOYMENT_TYPE" == "docker" || "$DEPLOYMENT_TYPE" == "kubernetes" ]]; then
        if ! command -v docker &> /dev/null; then
            log_error "Docker is required for this deployment type"
            exit 1
        fi
    fi

    log_success "System requirements met"
}

# Create production user and directories
setup_user_and_directories() {
    log_info "Setting up production user and directories…"
    
    # Create certnode user if doesn't exist
    if ! id "certnode" &>/dev/null; then
        sudo useradd -m -s /bin/bash certnode
        sudo usermod -aG sudo certnode
        log_success "Created certnode user"
    fi

    # Create application directories
    sudo mkdir -p /opt/certnode/{app,vault,logs,certs,badges,backups,config}
    sudo chown -R certnode:certnode /opt/certnode
    sudo chmod 750 /opt/certnode

    # Create systemd directories
    sudo mkdir -p /etc/systemd/system

    log_success "Directories created"
}

# Install system dependencies
install_system_dependencies() {
    log_info "Installing system dependencies…"
    
    sudo apt-get update
    sudo apt-get install -y \
        python3-pip \
        python3-venv \
        sqlite3 \
        nginx \
        supervisor \
        certbot \
        python3-certbot-nginx \
        htop \
        curl \
        wget \
        unzip \
        git

    log_success "System dependencies installed"
}

# Deploy Single Server
deploy_single_server() {
    log_info "Deploying CertNode as single server…"
    
    # Copy application files
    sudo cp -r *.py /opt/certnode/app/
    sudo cp -r *.json /opt/certnode/app/
    sudo cp requirements.txt /opt/certnode/app/
    sudo chown -R certnode:certnode /opt/certnode/app

    # Create virtual environment
    sudo -u certnode python3 -m venv /opt/certnode/app/venv
    sudo -u certnode /opt/certnode/app/venv/bin/pip install --upgrade pip
    sudo -u certnode /opt/certnode/app/venv/bin/pip install -r /opt/certnode/app/requirements.txt
    sudo -u certnode /opt/certnode/app/venv/bin/pip install gunicorn

    # Create production configuration
    create_production_config

    # Create systemd service
    create_systemd_service

    # Configure nginx
    configure_nginx

    # Setup SSL
    setup_ssl

    # Start services
    sudo systemctl daemon-reload
    sudo systemctl enable certnode
    sudo systemctl start certnode
    sudo systemctl enable nginx
    sudo systemctl restart nginx

    log_success "Single server deployment complete"
}

# Deploy with Docker
deploy_docker() {
    log_info "Deploying CertNode with Docker…"
    
    # Install Docker if not present
    if ! command -v docker &> /dev/null; then
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker $USER
        log_warning "Please log out and back in for Docker permissions to take effect"
    fi

    # Install Docker Compose
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose

    # Create Docker environment
    mkdir -p certnode-docker
    cp docker-compose.yml certnode-docker/
    cp Dockerfile certnode-docker/
    cp -r *.py *.json requirements.txt certnode-docker/

    # Create nginx configuration
    mkdir -p certnode-docker/nginx
    create_nginx_docker_config

    # Build and start containers
    cd certnode-docker
    docker-compose build
    docker-compose up -d

    log_success "Docker deployment complete"
}

# Create production configuration
create_production_config() {
    log_info "Creating production configuration…"
    
    cat > /opt/certnode/config/production.conf << EOF
[certnode]
operator = SRB Creative Holdings LLC
environment = production
debug = false
log_level = INFO

[database]
vault_path = /opt/certnode/vault/certnode_vault.db
backup_retention = 90

[api]
host = 127.0.0.1
port = 8000
rate_limit = 1000
enable_cors = true
workers = 4

[security]
require_https = true
api_key_required = true
max_content_size = 2097152
session_timeout = 3600

[processing]
max_workers = 8
timeout = 60
cache_results = true

[monitoring]
log_file = /opt/certnode/logs/certnode.log
metrics_enabled = true
health_check_interval = 30
EOF

    sudo chown certnode:certnode /opt/certnode/config/production.conf
    sudo chmod 640 /opt/certnode/config/production.conf

    log_success "Production configuration created"
}

# Create systemd service
create_systemd_service() {
    log_info "Creating systemd service…"
    
    cat << EOF | sudo tee /etc/systemd/system/certnode.service
[Unit]
Description=CertNode API Server
After=network.target

[Service]
Type=exec
User=certnode
Group=certnode
WorkingDirectory=/opt/certnode/app
Environment=PATH=/opt/certnode/app/venv/bin
Environment=CERTNODE_CONFIG=/opt/certnode/config/production.conf
ExecStart=/opt/certnode/app/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 4 --timeout 60 --access-logfile /opt/certnode/logs/access.log --error-logfile /opt/certnode/logs/error.log certnode_api:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    log_success "Systemd service created"
}

# Configure nginx
configure_nginx() {
    log_info "Configuring nginx…"
    
    cat << EOF | sudo tee /etc/nginx/sites-available/certnode
server {
    listen 80;
    server_name $DOMAIN;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    # API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health check
    location /health {
        proxy_pass http://127.0.0.1:8000;
        access_log off;
    }

    # Static files
    location /static/ {
        alias /opt/certnode/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Main site
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}
EOF

    sudo ln -sf /etc/nginx/sites-available/certnode /etc/nginx/sites-enabled/
    sudo rm -f /etc/nginx/sites-enabled/default
    sudo nginx -t

    log_success "Nginx configured"
}

# Setup SSL with Let's Encrypt
setup_ssl() {
    log_info "Setting up SSL certificate…"
    
    sudo certbot --nginx -d $DOMAIN --email $EMAIL --agree-tos --non-interactive --redirect

    # Setup auto-renewal
    echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -

    log_success "SSL certificate configured"
}

# Create nginx Docker configuration
create_nginx_docker_config() {
    cat << EOF > nginx/certnode.conf
upstream certnode_api {
    server certnode-api:8000;
}

server {
    listen 80;
    server_name localhost;

    location /api/ {
        proxy_pass http://certnode_api;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /health {
        proxy_pass http://certnode_api;
        access_log off;
    }

    location / {
        root /var/www/static;
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
}

# Setup monitoring
setup_monitoring() {
    log_info "Setting up monitoring…"
    
    # Create log rotation
    cat << EOF | sudo tee /etc/logrotate.d/certnode
/opt/certnode/logs/*.log {
    daily
    missingok
    rotate 90
    compress
    delaycompress
    notifempty
    create 0644 certnode certnode
    postrotate
        sudo systemctl reload certnode
    endscript
}
EOF

    # Create monitoring script
    cat << 'EOF' | sudo tee /opt/certnode/scripts/monitor.sh
#!/bin/bash

# CertNode monitoring script
LOG_FILE="/opt/certnode/logs/monitor.log"
API_URL="http://localhost:8000/health"

check_api() {
    if curl -f -s "$API_URL" > /dev/null; then
        echo "$(date): API is healthy" >> "$LOG_FILE"
        return 0
    else
        echo "$(date): API is down" >> "$LOG_FILE"
        sudo systemctl restart certnode
        return 1
    fi
}

check_vault() {
    if [ -f "/opt/certnode/vault/certnode_vault.db" ]; then
        echo "$(date): Vault database exists" >> "$LOG_FILE"
        return 0
    else
        echo "$(date): Vault database missing" >> "$LOG_FILE"
        return 1
    fi
}

check_api
check_vault
EOF

    sudo chmod +x /opt/certnode/scripts/monitor.sh
    sudo chown certnode:certnode /opt/certnode/scripts/monitor.sh

    # Add to crontab
    echo "*/5 * * * * /opt/certnode/scripts/monitor.sh" | sudo -u certnode crontab -

    log_success "Monitoring configured"
}

# Main deployment logic
main() {
    check_requirements
    
    case $DEPLOYMENT_TYPE in
        "single-server")
            setup_user_and_directories
            install_system_dependencies
            deploy_single_server
            setup_monitoring
            ;;
        "docker")
            deploy_docker
            ;;
        "kubernetes")
            log_warning "Kubernetes deployment requires additional configuration"
            log_info "Please refer to the kubernetes/ directory for manifests"
            ;;
        *)
            log_error "Invalid deployment type: $DEPLOYMENT_TYPE"
            echo "Valid options: single-server, docker, kubernetes"
            exit 1
            ;;
    esac

    log_success "Deployment completed successfully!"
    echo ""
    echo "🌐 Access your CertNode instance at: https://$DOMAIN"
    echo "📊 API Health Check: https://$DOMAIN/health"
    echo "📖 API Documentation: https://$DOMAIN/api/v1/status"
    echo ""
    echo "🔐 Next Steps:"
    echo "1. Configure API keys for production use"
    echo "2. Set up backup procedures"
    echo "3. Configure monitoring alerts"
    echo "4. Review security settings"
}

# Run main function
main

