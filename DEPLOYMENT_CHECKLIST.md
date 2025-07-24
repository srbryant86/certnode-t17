# CertNode Deployment Checklist

## Pre-Deployment Checklist

### ✅ **System Requirements**

- [ ] Python 3.8+ installed
- [ ] 4GB+ RAM available
- [ ] 50GB+ disk space (SSD recommended)
- [ ] Static IP address (for production)
- [ ] Domain name configured
- [ ] SSL certificate ready (or Let's Encrypt setup)

### ✅ **Files Prepared**

- [ ] All 12 CertNode modules extracted
- [ ] `requirements.txt` from artifacts
- [ ] `setup.sh` from artifacts
- [ ] `test_certnode.py` from artifacts
- [ ] `production_deploy.sh` from artifacts
- [ ] `backup.sh` from artifacts
- [ ] `Dockerfile` and `docker-compose.yml` (if using Docker)

## Development Setup Checklist

### ✅ **Local Environment**

- [ ] Virtual environment created
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Directory structure created
- [ ] Configuration files in place
- [ ] Vault database initialized

### ✅ **Basic Testing**

- [ ] System status check: `python3 certnode_main.py --system-info`
- [ ] Quick certification test: `python3 certnode_main.py --quick-certify test.txt`
- [ ] API server test: `python3 certnode_api.py --debug`
- [ ] Health endpoint: `curl http://localhost:8000/health`

### ✅ **Test Suite**

- [ ] All tests passing: `python3 test_certnode.py`
- [ ] Performance benchmarks acceptable
- [ ] Memory usage under 512MB
- [ ] Certification time under 3 seconds

## Production Deployment Checklist

### ✅ **Server Preparation**

- [ ] Server provisioned (VPS/Cloud/Dedicated)
- [ ] Operating system updated
- [ ] Firewall configured (ports 22, 80, 443)
- [ ] SSH key authentication enabled
- [ ] Non-root user created

### ✅ **Single Server Deployment**

- [ ] System dependencies installed
- [ ] CertNode user created
- [ ] Application directories created (`/opt/certnode/...`)
- [ ] Virtual environment setup
- [ ] CertNode modules copied
- [ ] Production configuration created
- [ ] Systemd service configured
- [ ] Nginx configured as reverse proxy
- [ ] SSL certificate installed
- [ ] Services started and enabled

### ✅ **Docker Deployment** (Alternative)

- [ ] Docker and Docker Compose installed
- [ ] Container images built
- [ ] Volumes configured for persistence
- [ ] Network configuration verified
- [ ] Containers running and healthy

### ✅ **Post-Deployment Verification**

- [ ] Health check passing: `curl https://yourdomain.com/health`
- [ ] API endpoints responding
- [ ] SSL certificate valid
- [ ] Rate limiting working
- [ ] Logs being written correctly

## Security Configuration Checklist

### ✅ **Basic Security**

- [ ] Firewall rules configured
- [ ] SSH password authentication disabled
- [ ] Root login disabled
- [ ] Fail2ban installed (optional but recommended)
- [ ] System packages updated

### ✅ **Application Security**

- [ ] API keys configured (if required)
- [ ] Rate limiting enabled
- [ ] HTTPS enforced
- [ ] Security headers configured
- [ ] File permissions set correctly

### ✅ **Vault Security**

- [ ] Vault database permissions: `640`
- [ ] Vault directory permissions: `750`
- [ ] Backup encryption enabled (optional)
- [ ] Access logging enabled

## Monitoring & Maintenance Checklist

### ✅ **Backup Configuration**

- [ ] Backup script installed
- [ ] Daily backup cron job configured
- [ ] Backup retention policy set (30+ days)
- [ ] S3 backup configured (optional)
- [ ] Backup restoration tested

### ✅ **Monitoring Setup**

- [ ] Log rotation configured
- [ ] Health check script installed
- [ ] Monitoring cron jobs active
- [ ] Disk space alerts configured
- [ ] Email notifications setup (optional)

### ✅ **Performance Optimization**

- [ ] Nginx configuration optimized
- [ ] Gunicorn worker count set appropriately
- [ ] System limits increased
- [ ] Caching enabled where appropriate

## Go-Live Checklist

### ✅ **Final Verification**

- [ ] Full certification flow tested end-to-end
- [ ] Verification process tested
- [ ] Badge generation working
- [ ] Vault storage confirmed
- [ ] Performance metrics acceptable

### ✅ **Documentation**

- [ ] API documentation accessible
- [ ] User guides prepared
- [ ] Admin procedures documented
- [ ] Emergency contacts listed

### ✅ **Launch Preparation**

- [ ] DNS records updated
- [ ] Load balancer configured (if applicable)
- [ ] CDN setup (if applicable)
- [ ] Analytics configured (if applicable)

## Maintenance Schedule

### 📅 **Daily**

- [ ] Check system health
- [ ] Review error logs
- [ ] Verify backup completion

### 📅 **Weekly**

- [ ] Review performance metrics
- [ ] Check disk space usage
- [ ] Update security patches

### 📅 **Monthly**

- [ ] Test backup restoration
- [ ] Review access logs
- [ ] Update dependencies
- [ ] Performance optimization review

### 📅 **Quarterly**

- [ ] Security audit
- [ ] Disaster recovery test
- [ ] Capacity planning review
- [ ] Documentation updates

## Emergency Procedures

### 🚨 **System Down**

1. Check service status: `sudo systemctl status certnode nginx`
1. Review logs: `sudo journalctl -u certnode -n 50`
1. Restart services: `sudo systemctl restart certnode nginx`
1. Verify health: `curl https://yourdomain.com/health`

### 🚨 **Data Corruption**

1. Stop services: `sudo systemctl stop certnode`
1. Restore from backup: `sudo /opt/certnode/scripts/backup.sh restore [backup-file]`
1. Verify vault integrity
1. Restart services

### 🚨 **High Load**

1. Check resource usage: `htop`, `iotop`
1. Review nginx access logs for unusual traffic
1. Scale workers: Update gunicorn configuration
1. Enable additional rate limiting

## Quick Commands Reference

```bash
# System Status
sudo systemctl status certnode nginx
curl https://yourdomain.com/health

# View Logs
sudo tail -f /opt/certnode/logs/certnode.log
sudo journalctl -u certnode -f

# Backup Operations
sudo -u certnode /opt/certnode/scripts/backup.sh backup
sudo -u certnode /opt/certnode/scripts/backup.sh list

# Service Management
sudo systemctl restart certnode
sudo systemctl reload nginx
sudo systemctl daemon-reload

# Testing
cd /opt/certnode/app && source venv/bin/activate
python3 certnode_main.py --system-info
python3 test_certnode.py
```

-----

## Support Information

**CertNode Version:** v1.0.0  
**Operator:** SRB Creative Holdings LLC  
**Documentation:** See `DEPLOYMENT_GUIDE.md` for detailed instructions  
**Emergency Contact:** [Your emergency contact information]

**Log Locations:**

- Application: `/opt/certnode/logs/`
- System: `/var/log/`
- Nginx: `/var/log/nginx/`

**Key Directories:**

- Application: `/opt/certnode/app/`
- Vault: `/opt/certnode/vault/`
- Backups: `/opt/certnode/backups/`
- Configuration: `/opt/certnode/config/`

-----

**🎯 Complete this checklist before going live to ensure a successful CertNode deployment!**

