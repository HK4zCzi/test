#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Bài 7: Deploy EASM lên AWS EC2 (Ubuntu 22.04)
# Chạy script này trên EC2 instance sau khi SSH vào
# ═══════════════════════════════════════════════════════════════

set -e   # exit on any error

REPO_URL="https://github.com/HK4zCzi/dev.git"
APP_DIR="/home/ubuntu/easm"
BRANCH="homework"

echo "════════════════════════════════════════════"
echo "  EASM — AWS EC2 Setup Script"
echo "════════════════════════════════════════════"

# ── 1. System update ────────────────────────────────────────────
echo "[1/6] Updating system..."
sudo apt-get update -y
sudo apt-get upgrade -y

# ── 2. Install Docker ───────────────────────────────────────────
echo "[2/6] Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker ubuntu
    rm get-docker.sh
    echo "✅ Docker installed"
else
    echo "✅ Docker already installed: $(docker --version)"
fi

# ── 3. Install Docker Compose ────────────────────────────────────
echo "[3/6] Installing Docker Compose..."
if ! command -v docker compose &> /dev/null; then
    sudo apt-get install -y docker-compose-plugin
    echo "✅ Docker Compose installed"
else
    echo "✅ Docker Compose already installed"
fi

# ── 4. Configure firewall ────────────────────────────────────────
echo "[4/6] Configuring firewall..."
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 8080/tcp  # Backend API (dev access)
sudo ufw allow 3000/tcp  # Frontend (dev access)
sudo ufw --force enable
echo "✅ Firewall configured"

# ── 5. Clone / update repository ────────────────────────────────
echo "[5/6] Cloning repository..."
if [ -d "$APP_DIR" ]; then
    echo "Repo exists, pulling latest..."
    cd "$APP_DIR"
    git fetch origin
    git checkout "$BRANCH"
    git pull origin "$BRANCH"
else
    git clone -b "$BRANCH" "$REPO_URL" "$APP_DIR"
    cd "$APP_DIR"
fi

# ── 6. Start application ─────────────────────────────────────────
echo "[6/6] Starting EASM stack..."
cd "$APP_DIR"

# Force rebuild to pick up latest code
docker compose down --remove-orphans 2>/dev/null || true
docker compose build --no-cache
docker compose up -d

echo ""
echo "════════════════════════════════════════════"
echo "  ✅ EASM deployed successfully!"
echo ""
echo "  Frontend : http://$(curl -s ifconfig.me):3000"
echo "  Backend  : http://$(curl -s ifconfig.me):8080"
echo "  API Docs : http://$(curl -s ifconfig.me):8080/docs"
echo "  Health   : http://$(curl -s ifconfig.me):8080/health"
echo "════════════════════════════════════════════"

# Show running containers
docker compose ps
