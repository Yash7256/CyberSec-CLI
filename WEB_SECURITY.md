# Web Security & Access Control Guide

> Secure your public CyberSec-CLI deployment

---

## 🔒 Security Layers

### Layer 1: Network Security

#### Firewall Rules
```bash
# Allow HTTPS (port 443)
sudo ufw allow 443

# Allow HTTP (port 80) - redirects to HTTPS
sudo ufw allow 80

# Allow SSH from specific IP only
sudo ufw allow from 192.168.1.100 to any port 22

# Block direct port 8000 access
sudo ufw deny 8000

# Enable firewall
sudo ufw enable
```

#### IP Whitelisting (Optional)
```nginx
# In nginx.conf - restrict to specific IPs
location /api/ {
    allow 192.168.1.0/24;  # Your network
    allow 10.0.0.0/8;      # VPN network
    deny all;              # Block everything else
    
    proxy_pass http://127.0.0.1:8000;
}
```

### Layer 2: Rate Limiting

#### Nginx Rate Limiting
```nginx
# Define rate limit zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=scan_limit:10m rate=1r/s;

# Apply to API endpoints
location /api/scan {
    limit_req zone=scan_limit burst=3 nodelay;
    proxy_pass http://127.0.0.1:8000;
}

location /api/ {
    limit_req zone=api_limit burst=20 nodelay;
    proxy_pass http://127.0.0.1:8000;
}
```

#### Application Rate Limiting (.env)
```bash
RATE_LIMIT=100              # 100 requests per minute per IP
MAX_CONCURRENT_SCANS=10     # Limit simultaneous scans
SCAN_TIMEOUT=300            # 5 minute limit per scan
MAX_PORTS_PER_SCAN=5000     # Prevent excessive scans
MAX_TARGETS_PER_HOUR=1000   # Hourly limit
```

#### Python Implementation
```python
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.util import get_ipaddr

@app.post("/api/scan")
@limiter.limit("1/second")  # 1 scan per second per IP
async def create_scan(request: Request, scan_request: ScanRequest):
    # Check rate limit
    ip = get_ipaddr(request)
    scans_today = db.get_scans_by_ip(ip, hours=24)
    
    if len(scans_today) >= 100:
        raise HTTPException(status_code=429, detail="Too many scans today")
    
    # Execute scan...
```

### Layer 3: Authentication

#### Option A: Simple Token Auth
```python
# In web/main.py
from fastapi.security import HTTPBearer, HTTPAuthCredentials

security = HTTPBearer()

def verify_token(credentials: HTTPAuthCredentials):
    if credentials.credentials != os.getenv("API_TOKEN"):
        raise HTTPException(status_code=401)
    return credentials.credentials

@app.post("/api/scan")
async def create_scan(
    token: str = Depends(verify_token),
    scan_request: ScanRequest = Body(...)
):
    # Execute scan...
```

**Usage**:
```bash
curl -H "Authorization: Bearer your-secret-token" \
  -X POST http://localhost:8000/api/scan \
  -d '{"target": "example.com"}'
```

#### Option B: API Key Auth
```python
from fastapi.security import APIKeyHeader

api_key_header = APIKeyHeader(name="X-API-Key")

async def verify_api_key(api_key: str = Depends(api_key_header)):
    if api_key != os.getenv("API_KEY"):
        raise HTTPException(status_code=401)
    return api_key

@app.post("/api/scan")
async def create_scan(
    api_key: str = Depends(verify_api_key),
    scan_request: ScanRequest = Body(...)
):
    # Execute scan...
```

**Usage**:
```bash
curl -H "X-API-Key: your-api-key" \
  -X POST http://localhost:8000/api/scan \
  -d '{"target": "example.com"}'
```

#### Option C: Username/Password Auth
```python
from fastapi import Form, Depends
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    user = db.get_user(username)
    if not user or not pwd_context.verify(password, user.password_hash):
        raise HTTPException(status_code=401)
    
    # Generate JWT token
    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/scan")
async def create_scan(
    current_user: User = Depends(get_current_user),
    scan_request: ScanRequest = Body(...)
):
    # Execute scan...
```

### Layer 4: HTTPS/TLS

#### Auto-SSL with Let's Encrypt
```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Generate certificate
sudo certbot certonly --nginx \
  -d cybersec.example.com \
  -m admin@example.com \
  --agree-tos \
  --non-interactive

# Auto-renew (runs daily)
sudo certbot renew --quiet
```

#### Nginx SSL Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name cybersec.example.com;

    ssl_certificate /etc/letsencrypt/live/cybersec.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cybersec.example.com/privkey.pem;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # HSTS - force HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name cybersec.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Layer 5: DDoS Protection

#### Using Cloudflare (Recommended)
1. Sign up at cloudflare.com
2. Add your domain
3. Update DNS to point to Cloudflare
4. Enable:
   - DDoS protection (default)
   - Rate limiting
   - Web application firewall
   - Caching

#### Using fail2ban (Self-hosted)
```bash
# Install fail2ban
sudo apt-get install fail2ban

# Create jail configuration
sudo tee /etc/fail2ban/jail.d/cybersec-api.conf << EOF
[cybersec-api]
enabled = true
port = http,https
filter = cybersec-api
logpath = /var/log/nginx/access.log
maxretry = 5           # Ban after 5 failed attempts
findtime = 600         # In 10 minutes
bantime = 3600         # Ban for 1 hour
EOF

# Create filter
sudo tee /etc/fail2ban/filter.d/cybersec-api.conf << EOF
[Definition]
failregex = ^<HOST> .* "POST /api/scan.*" [4|5]\d{2}
ignoreregex =
EOF

# Restart fail2ban
sudo systemctl restart fail2ban
sudo systemctl enable fail2ban
```

### Layer 6: Input Validation

```python
from pydantic import BaseModel, validator, HttpUrl

class ScanRequest(BaseModel):
    target: str
    scan_type: str
    
    @validator('target')
    def validate_target(cls, v):
        # Must be valid IP or domain
        import ipaddress
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        
        # Validate domain
        if not isinstance(v, str) or len(v) > 253:
            raise ValueError('Invalid target')
        
        return v
    
    @validator('scan_type')
    def validate_scan_type(cls, v):
        allowed = ['basic', 'full', 'custom']
        if v not in allowed:
            raise ValueError(f'Invalid scan type: {v}')
        return v
```

### Layer 7: Logging & Monitoring

#### Application Logging
```bash
# In .env
LOG_LEVEL=INFO
LOG_FILE=/var/log/cybersec/app.log

# View logs
tail -f /var/log/cybersec/app.log | grep ERROR
```

#### Access Logging
```nginx
# In nginx.conf
access_log /var/log/nginx/cybersec-access.log;
error_log /var/log/nginx/cybersec-error.log;

# Custom log format
log_format cybersec '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

#### Security Alerts
```bash
#!/bin/bash
# Monitor for suspicious activity

# High error rate
if grep -c "ERROR" /var/log/cybersec/app.log > 100; then
    mail -s "High error rate" admin@example.com
fi

# Failed authentications
if grep -c "401" /var/log/nginx/cybersec-access.log > 50; then
    mail -s "Multiple failed logins" admin@example.com
fi

# Rate limit exceeded
if grep -c "429" /var/log/nginx/cybersec-access.log > 100; then
    mail -s "Rate limit abuse" admin@example.com
fi
```

---

## 🔐 Access Control Strategies

### Public Access (No Auth)
```
For: Testing, demos, educational purposes
Risks: Abuse, resource exhaustion
Mitigation: Aggressive rate limiting, scanning restrictions
```

```bash
# Recommended settings for public access
RATE_LIMIT=50               # 50 req/min per IP
MAX_CONCURRENT_SCANS=5      # Max 5 simultaneous
SCAN_TIMEOUT=60             # 1 minute limit
MAX_PORTS_PER_SCAN=1000     # Limit port range
```

### Restricted Access (API Key)
```
For: Trusted users, developers, API consumers
Risks: Key compromise, unauthorized use
Mitigation: Key rotation, audit logging
```

```python
# Implement API key management
class APIKey(Base):
    id: int
    key: str  # Hashed
    user_id: int
    created_at: datetime
    last_used: datetime
    is_active: bool

# Key rotation policy: Expire keys every 90 days
```

### Private Access (VPN/IP Whitelist)
```
For: Internal team only, high security
Risks: Inconvenience, access management
Mitigation: Proper access controls, audit logs
```

```nginx
location /api/ {
    allow 10.0.0.0/8;      # Only VPN network
    allow 192.168.1.0/24;  # Only internal network
    deny all;
    
    proxy_pass http://127.0.0.1:8000;
}
```

### Password Protected (Username/Password)
```
For: Multiple users, fine-grained control
Risks: Weak passwords, credential theft
Mitigation: Strong password policy, 2FA
```

```python
# Implement strong password policy
PASSWORD_MIN_LENGTH = 12
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_NUMBERS = True
PASSWORD_REQUIRE_SYMBOLS = True

# Implement 2FA
from pyotp import TOTP
totp = TOTP(secret_key)
if totp.verify(user_token):
    # Grant access
```

---

## 📋 Security Checklist

### Before Going Public
- [ ] SSL/TLS enabled (HTTPS only)
- [ ] Rate limiting configured
- [ ] Authentication enabled
- [ ] Input validation in place
- [ ] Logging configured
- [ ] Firewall rules set
- [ ] DDoS protection enabled
- [ ] Backup strategy in place
- [ ] Monitoring setup
- [ ] Security headers added
- [ ] Regular updates scheduled
- [ ] Incident response plan ready

### Regular Maintenance
- [ ] Review logs weekly
- [ ] Update dependencies monthly
- [ ] Rotate API keys quarterly
- [ ] Review access controls quarterly
- [ ] Security audit annually
- [ ] Penetration testing annually

---

## 🆘 Security Incidents

### If Compromised

1. **Immediate Actions**:
   ```bash
   # Stop the application
   docker-compose down
   
   # Backup logs for forensics
   cp -r /var/log/cybersec /backup/incident-logs-$(date +%Y%m%d)
   
   # Rotate all credentials
   # Change API keys, passwords, secrets
   
   # Review access logs
   grep "401\|403\|429" /var/log/nginx/cybersec-access.log
   ```

2. **Investigation**:
   - Review logs for unauthorized access
   - Identify affected data
   - Check system for malware
   - Verify no backdoors installed

3. **Recovery**:
   - Patch vulnerabilities
   - Update credentials
   - Restore from backup
   - Gradually resume service
   - Monitor closely

---

## 📊 Recommended Configuration by Use Case

### Internal Tool
```
Rate Limit: Unlimited
Max Concurrent: Unlimited
Auth: Username/Password
Access: VPN only
Logging: Detailed
```

### Public Demo
```
Rate Limit: 50 req/min
Max Concurrent: 5
Auth: None
Access: Public
Logging: Summary
Restrictions: 100 ports max
```

### Production SaaS
```
Rate Limit: 100 req/min (tiered)
Max Concurrent: 50
Auth: API Key + 2FA
Access: Registered users
Logging: Comprehensive
DDoS: Cloudflare
Backup: Hourly
```

---

## ✨ Summary

Secure your public deployment with:
1. ✅ HTTPS/TLS
2. ✅ Rate limiting
3. ✅ Authentication
4. ✅ Input validation
5. ✅ Logging & monitoring
6. ✅ DDoS protection
7. ✅ Regular updates

Choose the security level matching your use case!

