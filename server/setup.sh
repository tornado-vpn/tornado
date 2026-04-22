#!/bin/bash

set -e


echo -e "$(cat << "EOF"

\033[1;37m██████ ▄▄▄  ▄▄▄▄  ▄▄  ▄▄  ▄▄▄  ▄▄▄▄   ▄▄▄  \033[0m  \033[38;5;208m██  ██ █████▄ ███  ██\033[0m 
\033[1;37m  ██  ██▀██ ██▄█▄ ███▄██ ██▀██ ██▀██ ██▀██ \033[0m  \033[38;5;208m██▄▄██ ██▄▄█▀ ██ ▀▄██\033[0m 
\033[1;37m  ██  ▀███▀ ██ ██ ██ ▀██ ██▀██ ████▀ ▀███▀ \033[0m  \033[38;5;208m ▀██▀  ██     ██   ██\033[0m v1.0.0

            developed by @Sridharanivel
EOF
)"

echo "🔧 Starting Tornado Infrastructure Setup..."

# ─────────────────────────────────────────────
# DISTRO DETECTION
# ─────────────────────────────────────────────
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="${ID,,}"       # lowercase: ubuntu, debian, fedora, arch, opensuse-tumbleweed …
        DISTRO_LIKE="${ID_LIKE,,}" # e.g. "debian", "rhel fedora", "suse"
    else
        echo "❌ Cannot detect distro – /etc/os-release not found."
        exit 1
    fi

    # Normalise into four families
    if [[ "$DISTRO_ID" =~ ^(ubuntu|debian|linuxmint|pop|elementary|kali)$ ]] || \
       [[ "$DISTRO_LIKE" =~ debian ]]; then
        PKG_FAMILY="debian"
    elif [[ "$DISTRO_ID" =~ ^(fedora|rhel|centos|almalinux|rocky|ol)$ ]] || \
         [[ "$DISTRO_LIKE" =~ (rhel|fedora) ]]; then
        PKG_FAMILY="rhel"
    elif [[ "$DISTRO_ID" =~ ^(arch|manjaro|endeavouros|garuda)$ ]] || \
         [[ "$DISTRO_LIKE" =~ arch ]]; then
        PKG_FAMILY="arch"
    elif [[ "$DISTRO_ID" =~ ^(opensuse|sles)$ ]] || \
         [[ "$DISTRO_LIKE" =~ suse ]]; then
        PKG_FAMILY="suse"
    else
        echo "⚠️  Unrecognised distro '$DISTRO_ID'. Attempting Debian-style fallback."
        PKG_FAMILY="debian"
    fi

    echo "✅ Detected distro: $DISTRO_ID  (family: $PKG_FAMILY)"
}

detect_distro


# ─────────────────────────────────────────────
# DETECT DEFAULT NETWORK INTERFACE
# ─────────────────────────────────────────────
DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
if [ -z "$DEFAULT_IFACE" ]; then
    echo "❌ Could not detect default network interface. Exiting."
    exit 1
fi
echo "✅ Detected default network interface: $DEFAULT_IFACE"


# ─────────────────────────────────────────────
# PACKAGE MANAGER HELPERS
# ─────────────────────────────────────────────
pkg_update() {
    case "$PKG_FAMILY" in
        debian) sudo apt-get update -y && sudo apt-get upgrade -y ;;
        rhel)   sudo dnf update -y ;;
        arch)   sudo pacman -Syu --noconfirm ;;
        suse)   sudo zypper refresh && sudo zypper update -y ;;
    esac
}

pkg_install() {
    case "$PKG_FAMILY" in
        debian) sudo apt-get install -y "$@" ;;
        rhel)   sudo dnf install -y "$@" ;;
        arch)   sudo pacman -S --noconfirm --needed "$@" ;;
        suse)   sudo zypper install -y "$@" ;;
    esac
}

# Resolve distro-specific package names into a common variable set
resolve_packages() {
    case "$PKG_FAMILY" in
        debian)
            PKG_PYTHON="python3 python3-pip python3-venv"
            PKG_POSTGRES="postgresql postgresql-contrib"
            PKG_REDIS="redis-server"
            PKG_REDIS_SVC="redis-server"
            PKG_TOR="tor"
            PKG_NGINX="nginx"
            PKG_WIREGUARD="wireguard"
            PKG_NET="iptables socat"
            NOLOGIN_SHELL="/usr/sbin/nologin"
            PKG_IPTABLES_PERSIST="iptables-persistent"
            ;;
        rhel)
            PKG_PYTHON="python3 python3-pip"
            PKG_POSTGRES="postgresql postgresql-server postgresql-contrib"
            PKG_REDIS="redis"
            PKG_REDIS_SVC="redis"
            PKG_TOR="tor"
            PKG_NGINX="nginx"
            PKG_WIREGUARD="wireguard-tools"
            PKG_NET="iptables socat"
            NOLOGIN_SHELL="/sbin/nologin"
            PKG_IPTABLES_PERSIST="iptables-services"
            ;;
        arch)
            PKG_PYTHON="python python-pip"
            PKG_POSTGRES="postgresql"
            PKG_REDIS="redis"
            PKG_REDIS_SVC="redis"
            PKG_TOR="tor"
            PKG_NGINX="nginx"
            PKG_WIREGUARD="wireguard-tools"
            PKG_NET="iptables socat"
            NOLOGIN_SHELL="/usr/bin/nologin"
            PKG_IPTABLES_PERSIST=""   # arch uses iptables-save natively, no extra package
            ;;
        suse)
            PKG_PYTHON="python3 python3-pip python3-venv"
            PKG_POSTGRES="postgresql postgresql-server postgresql-contrib"
            PKG_REDIS="redis"
            PKG_REDIS_SVC="redis"
            PKG_TOR="tor"
            PKG_NGINX="nginx"
            PKG_WIREGUARD="wireguard-tools"
            PKG_NET="iptables socat"
            NOLOGIN_SHELL="/usr/sbin/nologin"
            PKG_IPTABLES_PERSIST=""   # suse uses iptables-save natively, no extra package
            ;;
    esac
}

resolve_packages

# ─────────────────────────────────────────────
# IPTABLES PERSISTENCE
# ─────────────────────────────────────────────
persist_iptables() {
    echo "💾 Persisting iptables rules across reboots..."
    case "$PKG_FAMILY" in
        debian)
            # iptables-persistent saves rules at install time via debconf;
            # pre-answer the prompt so it's non-interactive
            echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | \
                sudo debconf-set-selections
            echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | \
                sudo debconf-set-selections
            pkg_install iptables-persistent
            sudo netfilter-persistent save
            sudo systemctl enable netfilter-persistent
            ;;
        rhel)
            pkg_install iptables-services
            sudo systemctl enable  iptables
            sudo systemctl start   iptables
            sudo service iptables save
            ;;
        arch)
            # iptables package already present; just save and enable the service
            sudo mkdir -p /etc/iptables
            sudo iptables-save | sudo tee /etc/iptables/iptables.rules > /dev/null
            sudo systemctl enable iptables
            sudo systemctl start  iptables
            ;;
        suse)
            sudo mkdir -p /etc/sysconfig
            sudo iptables-save | sudo tee /etc/sysconfig/iptables > /dev/null
            # openSUSE ships iptables.service in the iptables package
            sudo systemctl enable iptables 2>/dev/null || true
            sudo systemctl start  iptables 2>/dev/null || true
            ;;
    esac
    echo "✅ iptables rules persisted."
}

# ─────────────────────────────────────────────
# SYSTEM UPDATE
# ─────────────────────────────────────────────
echo "📦 Updating system..."
pkg_update

# ─────────────────────────────────────────────
# USER & GROUP SETUP
# ─────────────────────────────────────────────
echo "👤 Creating service user..."
sudo groupadd -f tornado-services

if ! id "tornado-runner" &>/dev/null; then
    sudo useradd \
      --system \
      --gid tornado-services \
      --home /home/tornado-runner \
      --create-home \
      --shell "$NOLOGIN_SHELL" \
      tornado-runner
fi

# ─────────────────────────────────────────────
# PYTHON SETUP
# ─────────────────────────────────────────────
echo "🐍 Installing Python..."
pkg_install $PKG_PYTHON

# On RHEL/Arch, python3-venv is part of the main python3 package;
# the module is always available after installing python3.
# On Debian/Ubuntu it ships separately – already in PKG_PYTHON above.

echo "🐍 Setting up virtual environment..."
sudo mkdir -p /opt/tornado
sudo python3 -m venv /opt/tornado/venv

echo "📥 Installing Python dependencies..."
sudo /opt/tornado/venv/bin/pip install --upgrade pip
sudo /opt/tornado/venv/bin/pip install -r requirements.txt

# ─────────────────────────────────────────────
# COPY PROJECT FILES
# ─────────────────────────────────────────────
echo "📁 Copying project files..."
sudo cp -r microservices /opt/tornado/
sudo cp -r web-interfaces /opt/tornado/
sudo cp -r tornadoutils /opt/tornado/  
sudo cp pyproject.toml /opt/tornado/ 


echo "📦 Installing internal packages..."
sudo /opt/tornado/venv/bin/pip install -e /opt/tornado/
# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────
echo "📝 Configuring logs..."
sudo mkdir -p /var/log/tornado
sudo chown -R tornado-runner:tornado-services /var/log/tornado
sudo chmod 2775 /var/log/tornado

# ─────────────────────────────────────────────
# POSTGRESQL SETUP
# ─────────────────────────────────────────────
echo "🗄 Installing PostgreSQL..."
pkg_install $PKG_POSTGRES

# RHEL/SUSE/Arch require manual cluster initialisation before first start
case "$PKG_FAMILY" in
    rhel)
        # Determine the installed major version for the correct initdb path
        PG_SETUP=$(command -v postgresql-setup 2>/dev/null || true)
        if [ -n "$PG_SETUP" ]; then
            sudo "$PG_SETUP" --initdb || true   # no-op if already initialised
        else
            # Fallback: locate initdb and run it directly
            PG_INITDB=$(find /usr -name initdb 2>/dev/null | head -1)
            PG_DATA=$(find /var/lib/pgsql -name PG_VERSION 2>/dev/null | head -1 | xargs dirname 2>/dev/null || echo "/var/lib/pgsql/data")
            [ ! -f "$PG_DATA/PG_VERSION" ] && sudo -u postgres "$PG_INITDB" -D "$PG_DATA"
        fi
        ;;
    arch)
        # Arch stores data in /var/lib/postgres/data
        PG_DATA="/var/lib/postgres/data"
        if [ ! -f "$PG_DATA/PG_VERSION" ]; then
            sudo -u postgres initdb -D "$PG_DATA"
        fi
        ;;
    suse)
        PG_DATA="/var/lib/pgsql/data"
        if [ ! -f "$PG_DATA/PG_VERSION" ]; then
            sudo -u postgres initdb -D "$PG_DATA"
        fi
        ;;
esac

sudo systemctl enable postgresql
sudo systemctl start postgresql

# Fixed values
DB_USER="tornado_db_user"
DB_NAME="tornadodb"

echo "🔐 Enter password for database user '$DB_USER':"
read -s DB_PASS
echo ""

echo "⚙️ Creating database and user..."


sudo -u postgres psql <<EOF
CREATE DATABASE ${DB_NAME};
CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';

ALTER ROLE ${DB_USER} SET client_encoding TO 'utf8';
ALTER ROLE ${DB_USER} SET default_transaction_isolation TO 'read committed';
ALTER ROLE ${DB_USER} SET timezone TO 'UTC';

GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};

-- 🔥 IMPORTANT FIX
\c ${DB_NAME}

GRANT USAGE ON SCHEMA public TO ${DB_USER};
GRANT CREATE ON SCHEMA public TO ${DB_USER};
ALTER SCHEMA public OWNER TO ${DB_USER};

EOF

# ─────────────────────────────────────────────
# POSTGRESQL: allow md5 auth for localhost (RHEL/Arch default is ident/peer)
# ─────────────────────────────────────────────
fix_pg_hba() {
    # Find the pg_hba.conf regardless of version/distro
    PG_HBA=$(sudo -u postgres psql -t -c "SHOW hba_file;" 2>/dev/null | tr -d ' ')
    if [ -n "$PG_HBA" ] && [ -f "$PG_HBA" ]; then
        # Replace ident / peer auth for IPv4 localhost with md5
        sudo sed -i 's/^host\s\+all\s\+all\s\+127\.0\.0\.1\/32\s\+ident/host    all             all             127.0.0.1\/32            md5/' "$PG_HBA"
        sudo sed -i 's/^host\s\+all\s\+all\s\+127\.0\.0\.1\/32\s\+peer/host    all             all             127.0.0.1\/32            md5/' "$PG_HBA"
        # Add an md5 line if no host line for 127.0.0.1 exists at all
        if ! sudo grep -qE "^host\s+all\s+all\s+127\.0\.0\.1/32" "$PG_HBA"; then
            echo "host    all             all             127.0.0.1/32            md5" | sudo tee -a "$PG_HBA" > /dev/null
        fi
        sudo systemctl reload postgresql || sudo systemctl restart postgresql
    fi
}

if [[ "$PKG_FAMILY" == "rhel" || "$PKG_FAMILY" == "arch" || "$PKG_FAMILY" == "suse" ]]; then
    echo "🔧 Fixing pg_hba.conf for password authentication..."
    fix_pg_hba
fi

# ─────────────────────────────────────────────
# LOAD DATABASE SCHEMA
# ─────────────────────────────────────────────
echo "🏗️ Loading database schema into $DB_NAME..."
if [ -f "schema.sql" ]; then
    export PGPASSWORD="$DB_PASS"
    psql -U "$DB_USER" -h 127.0.0.1 -d "$DB_NAME" -v ON_ERROR_STOP=1 -f schema.sql
    echo "✅ Schema loaded successfully."
    unset PGPASSWORD
else
    echo "⚠️ Warning: schema.sql not found. Skipping schema load."
fi

# ─────────────────────────────────────────────
# CREATE .env FILE
# ─────────────────────────────────────────────
echo "🔐 Creating .env file..."

echo "👤 Enter ADMIN_USERNAME:"
read ADMIN_USERNAME

echo "🔑 Enter ADMIN_PASSWORD:"
read -s ADMIN_PASSWORD
echo ""

echo "🌐 Enter VPN_ENDPOINT_HOST (e.g. 192.168.29.175):"
read VPN_ENDPOINT_HOST

ADMIN_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "🔐 Generated ADMIN_SECRET."

sudo tee /opt/tornado/.env > /dev/null <<EOF
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}
DB_HOST=localhost
DB_NAME=${DB_NAME}

ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
ADMIN_SECRET=${ADMIN_SECRET}
ADMIN_TOKEN_TTL=28800
HTTPS=false
LOG_EXPORT_DIR=/var/log/tornado/exp/
VPN_ENDPOINT_HOST=${VPN_ENDPOINT_HOST}
VPN_ENDPOINT_PORT=51820
TOR_ENDPOINT_PORT=51821
EOF

sudo chown root:tornado-services /opt/tornado/.env
sudo chmod 640 /opt/tornado/.env
echo "✅ .env setup complete."

# ─────────────────────────────────────────────
# REDIS SETUP
# ─────────────────────────────────────────────
echo "⚡ Installing Redis..."
pkg_install $PKG_REDIS
sudo systemctl enable "$PKG_REDIS_SVC"
sudo systemctl start  "$PKG_REDIS_SVC"

# ─────────────────────────────────────────────
# TOR SETUP
# ─────────────────────────────────────────────
echo "🧅 Installing Tor..."

# Tor is not in default repos on some RHEL-based systems; add the official repo if needed
if [[ "$PKG_FAMILY" == "rhel" ]]; then
    if ! command -v tor &>/dev/null && ! rpm -q tor &>/dev/null 2>&1; then
        echo "  → Adding Tor Project repo for RHEL/Fedora..."
        # Detect major version
        OS_VERSION=$(. /etc/os-release; echo "$VERSION_ID" | cut -d. -f1)
        sudo tee /etc/yum.repos.d/tor.repo > /dev/null <<TORREPO
[tor]
name=Tor for Enterprise Linux $OS_VERSION - \$basearch
baseurl=https://rpm.torproject.org/centos/$OS_VERSION/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://rpm.torproject.org/centos/pubkey.gpg
TORREPO
    fi
fi

pkg_install $PKG_TOR
sudo systemctl restart tor
sudo systemctl enable tor

# ─────────────────────────────────────────────
# NGINX SETUP
# ─────────────────────────────────────────────
echo "🚀 Installing NGINX..."
pkg_install $PKG_NGINX
sudo systemctl enable nginx

echo "⚙️ Configuring NGINX..."

# sites-available/sites-enabled pattern exists on Debian; create it elsewhere
if [[ "$PKG_FAMILY" != "debian" ]]; then
    sudo mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
    # Ensure the main nginx.conf includes sites-enabled (idempotent)
    if ! sudo grep -q "sites-enabled" /etc/nginx/nginx.conf; then
        sudo sed -i '/http {/a \    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
    fi
fi

sudo tee /etc/nginx/sites-available/admin-dashboard > /dev/null <<'NGINXCONF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass          http://127.0.0.1:8000;
        proxy_http_version  1.1;
        proxy_set_header    Host              $host;
        proxy_set_header    X-Real-IP         $remote_addr;
        proxy_set_header    X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header    X-Forwarded-Proto $scheme;
        proxy_set_header    Upgrade           $http_upgrade;
        proxy_set_header    Connection        "upgrade";

        proxy_read_timeout  3600s;   # 1 hour — keeps WS alive
        proxy_send_timeout  3600s;
        proxy_connect_timeout 10s;

        proxy_buffering     off;     # essential for SSE (/logs/tail) + WS
        proxy_cache         off;
    }

    access_log /var/log/nginx/admin-dashboard.access.log;
    error_log  /var/log/nginx/admin-dashboard.error.log warn;
}
NGINXCONF


sudo ln -sf /etc/nginx/sites-available/admin-dashboard /etc/nginx/sites-enabled/

# Remove default vhost (path differs by distro)
for f in /etc/nginx/sites-enabled/default \
          /etc/nginx/conf.d/default.conf \
          /etc/nginx/conf.d/welcome.conf; do
    [ -f "$f" ] && sudo rm -f "$f"
done

sudo nginx -t
sudo systemctl reload nginx

# ─────────────────────────────────────────────
# NETWORKING UTILITIES
# ─────────────────────────────────────────────
echo "🌐 Installing networking utilities..."
pkg_install $PKG_NET

echo "📡 Enabling IPv4 forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
if ! grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
fi

echo "🔥 Configuring NAT masquerade on interface: $DEFAULT_IFACE..."
if ! sudo iptables -t nat -C POSTROUTING -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null; then
    sudo iptables -t nat -A POSTROUTING -o "$DEFAULT_IFACE" -j MASQUERADE
fi

# Persist rules so they survive a reboot
persist_iptables
# ─────────────────────────────────────────────
# WIREGUARD SETUP
# ─────────────────────────────────────────────
echo "🔐 Installing WireGuard..."

# On RHEL 8 WireGuard needs the EPEL + elrepo-kernel repos; warn the user
if [[ "$PKG_FAMILY" == "rhel" ]]; then
    OS_MAJOR=$(. /etc/os-release; echo "$VERSION_ID" | cut -d. -f1)
    if [[ "$OS_MAJOR" -le 8 ]] && ! rpm -q wireguard-tools &>/dev/null 2>&1; then
        echo "  ⚠️  On RHEL/CentOS 8 WireGuard requires EPEL and elrepo-kernel."
        echo "     Run the following before re-running this script:"
        echo "       sudo dnf install epel-release -y"
        echo "       sudo dnf install elrepo-release -y"
        echo "       sudo dnf install kmod-wireguard wireguard-tools -y"
        echo "     Skipping WireGuard install for now."
    else
        pkg_install $PKG_WIREGUARD
    fi
else
    pkg_install $PKG_WIREGUARD
fi

# ─────────────────────────────────────────────
# DNSMASQ SETUP
# ─────────────────────────────────────────────
echo "🌐 Installing and configuring dnsmasq..."
# Using your cross-distro package wrapper instead of hardcoded apt
pkg_install dnsmasq

echo "⚙️ Configuring dnsmasq for VPN DNS..."
sudo tee /etc/dnsmasq.d/tornado-vpn.conf > /dev/null <<'DNSCONF'
interface=wg0
listen-address=10.8.0.1
bind-interfaces
server=1.1.1.1
server=8.8.8.8
DNSCONF

# Enable and start/restart the service
sudo systemctl enable dnsmasq
sudo systemctl restart dnsmasq

# ─────────────────────────────────────────────
# PERMISSIONS
# ─────────────────────────────────────────────
echo "🔧 Applying permissions..."
sudo chown -R tornado-runner:tornado-services /opt/tornado
sudo find /opt/tornado -type d -exec chmod 755 {} +
sudo find /opt/tornado -type f -exec chmod 644 {} +
sudo chmod 640 /opt/tornado/.env

# ─────────────────────────────────────────────
# SYSTEMD SERVICE
# ─────────────────────────────────────────────
echo "⚙️ Creating systemd service..."
sudo tee /etc/systemd/system/tornado.service > /dev/null <<'SVCEOF'
[Unit]
Description=Tornado Master Service
After=network.target postgresql.service redis.service
Wants=postgresql.service redis.service

[Service]
Type=simple
EnvironmentFile=/opt/tornado/.env
User=root
Group=root
WorkingDirectory=/opt/tornado/microservices
ExecStart=/opt/tornado/venv/bin/python3 MASTER_service.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tornado-master
RuntimeDirectory=tornado
RuntimeDirectoryMode=2775

[Install]
WantedBy=multi-user.target
SVCEOF

sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable tornado
sudo systemctl start tornado

# ─────────────────────────────────────────────
# STATUS CHECK
# ─────────────────────────────────────────────
echo "📊 Checking service status..."
sudo systemctl status tornado --no-pager

echo "✅ Setup Complete! (distro: $DISTRO_ID, family: $PKG_FAMILY)"
