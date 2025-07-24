#!/bin/bash

# CertNode Backup Script

set -e

# Configuration
BACKUP_DIR="/opt/certnode/backups"
VAULT_DIR="/opt/certnode/vault"
LOGS_DIR="/opt/certnode/logs"
CERTS_DIR="/opt/certnode/certs"
CONFIG_DIR="/opt/certnode/config"
RETENTION_DAYS=30
DATE_FORMAT=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="certnode_backup_$DATE_FORMAT"

# S3 Configuration (optional)
S3_BUCKET="${CERTNODE_S3_BUCKET:-}"
AWS_REGION="${AWS_REGION:-us-east-1}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}ℹ️  $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $(date '+%Y-%m-%d %H:%M:%S') - $1${NC}"
}

# Create backup directory
create_backup_dir() {
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        log_info "Created backup directory: $BACKUP_DIR"
    fi

    CURRENT_BACKUP_DIR="$BACKUP_DIR/$BACKUP_NAME"
    mkdir -p "$CURRENT_BACKUP_DIR"
    log_info "Created backup directory: $CURRENT_BACKUP_DIR"
}

# Backup vault database
backup_vault() {
    log_info "Backing up vault database…"

    if [ -f "$VAULT_DIR/certnode_vault.db" ]; then
        # Create vault backup directory
        mkdir -p "$CURRENT_BACKUP_DIR/vault"
        
        # SQLite backup (hot backup)
        sqlite3 "$VAULT_DIR/certnode_vault.db" ".backup '$CURRENT_BACKUP_DIR/vault/certnode_vault.db'"
        
        # Export vault to JSON
        python3 -c "
import sys
sys.path.append('/opt/certnode/app')
from vault_manager import VaultManager
vm = VaultManager()
vm.export_vault('$CURRENT_BACKUP_DIR/vault/vault_export.json')
print('Vault exported to JSON')
" 2>/dev/null || log_warning "JSON export failed"

        # Calculate checksums
        cd "$CURRENT_BACKUP_DIR/vault"
        sha256sum *.* > checksums.sha256
        cd - > /dev/null
        
        log_success "Vault backup completed"
    else
        log_warning "Vault database not found at $VAULT_DIR/certnode_vault.db"
    fi
}

# Backup configuration
backup_config() {
    log_info "Backing up configuration…"

    if [ -d "$CONFIG_DIR" ]; then
        cp -r "$CONFIG_DIR" "$CURRENT_BACKUP_DIR/"
        log_success "Configuration backup completed"
    else
        log_warning "Configuration directory not found"
    fi
}

# Backup certificates and badges
backup_outputs() {
    log_info "Backing up certificates and badges…"

    # Backup certificates
    if [ -d "$CERTS_DIR" ]; then
        mkdir -p "$CURRENT_BACKUP_DIR/certified_outputs"
        cp -r "$CERTS_DIR"/* "$CURRENT_BACKUP_DIR/certified_outputs/" 2>/dev/null || true
        log_success "Certificates backup completed"
    fi

    # Backup badges
    BADGES_DIR="/opt/certnode/badges"
    if [ -d "$BADGES_DIR" ]; then
        mkdir -p "$CURRENT_BACKUP_DIR/trust_badges"
        cp -r "$BADGES_DIR"/* "$CURRENT_BACKUP_DIR/trust_badges/" 2>/dev/null || true
        log_success "Badges backup completed"
    fi
}

# Backup recent logs
backup_logs() {
    log_info "Backing up recent logs…"

    if [ -d "$LOGS_DIR" ]; then
        mkdir -p "$CURRENT_BACKUP_DIR/logs"
        
        # Backup logs from last 7 days
        find "$LOGS_DIR" -name "*.log" -mtime -7 -exec cp {} "$CURRENT_BACKUP_DIR/logs/" \;
        
        log_success "Logs backup completed"
    else
        log_warning "Logs directory not found"
    fi
}

# Create backup metadata
create_metadata() {
    log_info "Creating backup metadata…"

    cat > "$CURRENT_BACKUP_DIR/backup_metadata.json" << EOF
{
    "backup_name": "$BACKUP_NAME",
    "backup_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "backup_type": "full",
    "hostname": "$(hostname)",
    "certnode_version": "$(python3 -c 'import sys; sys.path.append("/opt/certnode/app"); from certnode_config import CertNodeConfig; print(CertNodeConfig.CERTNODE_VERSION)' 2>/dev/null || echo 'unknown')",
    "backup_size": "$(du -sh $CURRENT_BACKUP_DIR | cut -f1)",
    "components": {
        "vault": $([ -f "$CURRENT_BACKUP_DIR/vault/certnode_vault.db" ] && echo true || echo false),
        "config": $([ -d "$CURRENT_BACKUP_DIR/config" ] && echo true || echo false),
        "certificates": $([ -d "$CURRENT_BACKUP_DIR/certified_outputs" ] && echo true || echo false),
        "badges": $([ -d "$CURRENT_BACKUP_DIR/trust_badges" ] && echo true || echo false),
        "logs": $([ -d "$CURRENT_BACKUP_DIR/logs" ] && echo true || echo false)
    }
}
EOF

    log_success "Backup metadata created"
}

# Compress backup
compress_backup() {
    log_info "Compressing backup…"

    cd "$BACKUP_DIR"
    tar -czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"

    # Remove uncompressed directory
    rm -rf "$BACKUP_NAME"

    BACKUP_FILE="$BACKUP_DIR/${BACKUP_NAME}.tar.gz"
    BACKUP_SIZE=$(du -sh "$BACKUP_FILE" | cut -f1)

    log_success "Backup compressed: $BACKUP_FILE ($BACKUP_SIZE)"
}

# Upload to S3 (if configured)
upload_to_s3() {
    if [ -n "$S3_BUCKET" ]; then
        log_info "Uploading backup to S3…"

        if command -v aws &> /dev/null; then
            aws s3 cp "$BACKUP_FILE" "s3://$S3_BUCKET/certnode-backups/" --region "$AWS_REGION"
            log_success "Backup uploaded to S3: s3://$S3_BUCKET/certnode-backups/${BACKUP_NAME}.tar.gz"
        else
            log_warning "AWS CLI not found, skipping S3 upload"
        fi
    fi
}

# Clean old backups
cleanup_old_backups() {
    log_info "Cleaning up old backups…"

    # Remove local backups older than retention period
    find "$BACKUP_DIR" -name "certnode_backup_*.tar.gz" -mtime +$RETENTION_DAYS -delete

    # Clean S3 backups (if configured)
    if [ -n "$S3_BUCKET" ] && command -v aws &> /dev/null; then
        CUTOFF_DATE=$(date -d "$RETENTION_DAYS days ago" '+%Y-%m-%d')
        aws s3 ls "s3://$S3_BUCKET/certnode-backups/" --region "$AWS_REGION" | while read -r line; do
            BACKUP_DATE=$(echo "$line" | awk '{print $1}')
            BACKUP_FILE=$(echo "$line" | awk '{print $4}')
            
            if [[ "$BACKUP_DATE" < "$CUTOFF_DATE" ]]; then
                aws s3 rm "s3://$S3_BUCKET/certnode-backups/$BACKUP_FILE" --region "$AWS_REGION"
                log_info "Removed old S3 backup: $BACKUP_FILE"
            fi
        done
    fi

    log_success "Cleanup completed"
}

# Verify backup integrity
verify_backup() {
    log_info "Verifying backup integrity…"

    if [ -f "$BACKUP_FILE" ]; then
        # Test archive integrity
        if tar -tzf "$BACKUP_FILE" > /dev/null 2>&1; then
            log_success "Backup archive integrity verified"
        else
            log_error "Backup archive is corrupted!"
            exit 1
        fi
        
        # Verify vault backup if present
        if tar -tzf "$BACKUP_FILE" | grep -q "vault/certnode_vault.db"; then
            log_success "Vault database backup verified"
        else
            log_warning "Vault database backup not found in archive"
        fi
    else
        log_error "Backup file not found: $BACKUP_FILE"
        exit 1
    fi
}

# Send notification (optional)
send_notification() {
    local status=$1
    local message=$2

    # Email notification (if sendmail is configured)
    if command -v sendmail &> /dev/null && [ -n "$BACKUP_EMAIL" ]; then
        echo "Subject: CertNode Backup $status - $(hostname)" | sendmail "$BACKUP_EMAIL" << EOF
CertNode Backup Report

Status: $status
Date: $(date)
Hostname: $(hostname)
Backup File: $BACKUP_FILE
Backup Size: $([ -f "$BACKUP_FILE" ] && du -sh "$BACKUP_FILE" | cut -f1 || echo "N/A")

$message
EOF
    fi

    # Webhook notification (if configured)
    if [ -n "$BACKUP_WEBHOOK_URL" ]; then
        curl -X POST "$BACKUP_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"status\":\"$status\",\"message\":\"$message\",\"hostname\":\"$(hostname)\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            2>/dev/null || true
    fi
}

# Restore function
restore_backup() {
    local backup_file=$1

    if [ -z "$backup_file" ]; then
        log_error "Usage: $0 restore <backup_file>"
        exit 1
    fi

    if [ ! -f "$backup_file" ]; then
        log_error "Backup file not found: $backup_file"
        exit 1
    fi

    log_warning "This will restore CertNode from backup and overwrite current data!"
    read -p "Are you sure? (yes/no): " confirm

    if [ "$confirm" != "yes" ]; then
        log_info "Restore cancelled"
        exit 0
    fi

    log_info "Stopping CertNode service..."
    sudo systemctl stop certnode 2>/dev/null || true

    log_info "Restoring from backup: $backup_file"

    # Create restore directory
    RESTORE_DIR="/tmp/certnode_restore_$(date +%s)"
    mkdir -p "$RESTORE_DIR"

    # Extract backup
    tar -xzf "$backup_file" -C "$RESTORE_DIR"

    # Find backup directory
    BACKUP_EXTRACT_DIR=$(find "$RESTORE_DIR" -name "certnode_backup_*" -type d | head -1)

    if [ -z "$BACKUP_EXTRACT_DIR" ]; then
        log_error "Invalid backup format"
        rm -rf "$RESTORE_DIR"
        exit 1
    fi

    # Restore vault
    if [ -f "$BACKUP_EXTRACT_DIR/vault/certnode_vault.db" ]; then
        log_info "Restoring vault database..."
        cp "$BACKUP_EXTRACT_DIR/vault/certnode_vault.db" "$VAULT_DIR/"
        chown certnode:certnode "$VAULT_DIR/certnode_vault.db"
        log_success "Vault database restored"
    fi

    # Restore configuration
    if [ -d "$BACKUP_EXTRACT_DIR/config" ]; then
        log_info "Restoring configuration..."
        cp -r "$BACKUP_EXTRACT_DIR/config"/* "$CONFIG_DIR/"
        chown -R certnode:certnode "$CONFIG_DIR"
        log_success "Configuration restored"
    fi

    # Restore certificates and badges
    if [ -d "$BACKUP_EXTRACT_DIR/certified_outputs" ]; then
        log_info "Restoring certificates..."
        cp -r "$BACKUP_EXTRACT_DIR/certified_outputs"/* "$CERTS_DIR/" 2>/dev/null || true
        chown -R certnode:certnode "$CERTS_DIR"
        log_success "Certificates restored"
    fi

    if [ -d "$BACKUP_EXTRACT_DIR/trust_badges" ]; then
        log_info "Restoring badges..."
        BADGES_DIR="/opt/certnode/badges"
        mkdir -p "$BADGES_DIR"
        cp -r "$BACKUP_EXTRACT_DIR/trust_badges"/* "$BADGES_DIR/" 2>/dev/null || true
        chown -R certnode:certnode "$BADGES_DIR"
        log_success "Badges restored"
    fi

    # Cleanup
    rm -rf "$RESTORE_DIR"

    log_info "Starting CertNode service..."
    sudo systemctl start certnode

    log_success "Restore completed successfully!"
    send_notification "SUCCESS" "CertNode restored from backup: $backup_file"
}

# Main function
main() {
    local action=${1:-backup}

    case $action in
        "backup")
            log_info "Starting CertNode backup..."
            
            create_backup_dir
            backup_vault
            backup_config
            backup_outputs
            backup_logs
            create_metadata
            compress_backup
            verify_backup
            upload_to_s3
            cleanup_old_backups
            
            log_success "Backup completed successfully!"
            log_info "Backup location: $BACKUP_FILE"
            
            send_notification "SUCCESS" "Backup completed successfully: $BACKUP_FILE"
            ;;
        "restore")
            restore_backup "$2"
            ;;
        "list")
            log_info "Available backups:"
            ls -la "$BACKUP_DIR"/certnode_backup_*.tar.gz 2>/dev/null || log_info "No backups found"
            
            if [ -n "$S3_BUCKET" ] && command -v aws &> /dev/null; then
                log_info "S3 backups:"
                aws s3 ls "s3://$S3_BUCKET/certnode-backups/" --region "$AWS_REGION" 2>/dev/null || log_info "No S3 backups found"
            fi
            ;;
        *)
            echo "Usage: $0 {backup|restore <file>|list}"
            echo ""
            echo "Commands:"
            echo "  backup          - Create a full backup"
            echo "  restore <file>  - Restore from backup file"
            echo "  list            - List available backups"
            echo ""
            echo "Environment variables:"
            echo "  CERTNODE_S3_BUCKET    - S3 bucket for remote backups"
            echo "  AWS_REGION            - AWS region (default: us-east-1)"
            echo "  BACKUP_EMAIL          - Email for notifications"
            echo "  BACKUP_WEBHOOK_URL    - Webhook URL for notifications"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"

