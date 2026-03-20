#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Bài 8: Setup HTTPS với Certbot + Let's Encrypt
# Chạy SAU KHI deploy_aws.sh thành công
# Yêu cầu: domain đã trỏ A record về IP của EC2
# ═══════════════════════════════════════════════════════════════

set -e

if [ -z "$1" ]; then
    echo "Usage: bash setup_https.sh your-domain.com your@email.com"
    exit 1
fi

DOMAIN="$1"
EMAIL="${2:-admin@${DOMAIN}}"
APP_DIR="/home/ubuntu/easm"

echo "Setting up HTTPS for: $DOMAIN"
echo "Contact email: $EMAIL"

# ── 1. Install Certbot ───────────────────────────────────────────
echo "[1/4] Installing Certbot..."
sudo apt-get install -y certbot

# ── 2. Stop nginx/frontend temporarily for standalone challenge ──
echo "[2/4] Pausing frontend for certificate challenge..."
cd "$APP_DIR"
docker compose stop frontend 2>/dev/null || true

# ── 3. Get certificate ───────────────────────────────────────────
echo "[3/4] Getting Let's Encrypt certificate..."
sudo certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    -d "$DOMAIN" \
    -d "www.$DOMAIN" 2>/dev/null || \
sudo certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    -d "$DOMAIN"

# ── 4. Configure Nginx ───────────────────────────────────────────
echo "[4/4] Configuring Nginx with HTTPS..."
# Replace placeholder in nginx config
mkdir -p "$APP_DIR/nginx/ssl"
sed "s/YOUR_DOMAIN/$DOMAIN/g" "$APP_DIR/nginx/nginx.conf" > /tmp/nginx_domain.conf
sudo cp /tmp/nginx_domain.conf "$APP_DIR/nginx/nginx.conf"

# Copy certs to app dir
sudo cp -r /etc/letsencrypt "$APP_DIR/nginx/ssl/"
sudo chown -R ubuntu:ubuntu "$APP_DIR/nginx/ssl/"

# Uncomment nginx service in docker-compose.yml
cd "$APP_DIR"
sed -i 's/^  # nginx:/  nginx:/' docker-compose.yml
sed -i 's/^  #   image: nginx/    image: nginx/' docker-compose.yml
sed -i 's/^  #   container_name/    container_name/' docker-compose.yml
sed -i 's/^  #   restart/    restart/' docker-compose.yml
sed -i 's/^  #   ports:/    ports:/' docker-compose.yml
sed -i 's/^  #     - "80:80"/      - "80:80"/' docker-compose.yml
sed -i 's/^  #     - "443:443"/      - "443:443"/' docker-compose.yml
sed -i 's/^  #   volumes:/    volumes:/' docker-compose.yml
sed -i 's|^  #     - ./nginx/nginx.conf|      - ./nginx/nginx.conf|' docker-compose.yml
sed -i 's|^  #     - ./nginx/ssl|      - ./nginx/ssl|' docker-compose.yml
sed -i 's|^  #     - certbot-data|      - certbot-data|' docker-compose.yml
sed -i 's/^  #   depends_on:/    depends_on:/' docker-compose.yml
sed -i 's/^  #     - backend/      - backend/' docker-compose.yml
sed -i 's/^  #     - frontend/      - frontend/' docker-compose.yml

docker compose up -d

# Auto-renewal cron job
(crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet && docker compose -f $APP_DIR/docker-compose.yml restart nginx") | crontab -

echo ""
echo "✅ HTTPS configured!"
echo "   https://$DOMAIN"
echo "   https://www.$DOMAIN"
echo ""
echo "Certificate auto-renews via cron at 3am daily."
