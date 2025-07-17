#!/bin/bash

# Import AlmaLinux GPG key
sudo rpm --import https://repo.almalinux.org/almalinux/RPM-GPG-KEY-AlmaLinux

# Install EPEL repository
echo "Installing EPEL repository..."
sudo yum install epel-release -y

# Install unzip, wget, nano, and PHP for admin panel
echo "Installing unzip wget nano php..."
sudo yum install unzip wget nano php php-cli php-common php-json php-mbstring php-curl php-xml -y

# Install OpenLiteSpeed repository
echo "Installing OpenLiteSpeed repository..."
sudo wget -O - https://repo.litespeed.sh | sudo bash
sudo yum install openlitespeed -y

# Install OpenLiteSpeed and PHP
echo "Installing OpenLiteSpeed and PHP..."
sudo yum install openlitespeed lsphp73 lsphp73-common lsphp73-opcache lsphp73-mbstring lsphp73-xml lsphp73-gd lsphp73-curl lsphp73-intl lsphp73-soap lsphp73-xmlrpc lsphp73-ldap lsphp73-bcmath lsphp73-pear lsphp73-devel lsphp73-json lsphp73-zip lsphp73-imap lsphp73-mcrypt lsphp73-iconv lsphp73-gettext lsphp73-ftp -y

yum groupinstall "Development Tools" -y
yum install libzip libzip-devel pcre2-devel -y
sudo /usr/local/lsws/lsphp73/bin/pecl install gd mbstring json curl zip
sudo pkill lsphp

# Enable and start OpenLiteSpeed
echo "Enabling and starting OpenLiteSpeed..."
sudo systemctl enable lsws
sudo systemctl start lsws

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')

ssl_dir="/usr/local/lsws/conf/vhosts/Example"
ssl_key="${ssl_dir}/localhost.key"
ssl_cert="${ssl_dir}/localhost.crt"

if [ ! -f "$ssl_key" ] || [ ! -f "$ssl_cert" ]; then
	openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
		-subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost" \
		-keyout "$ssl_key" -out "$ssl_cert" > /dev/null 2>&1
	chown -R lsadm:lsadm /usr/local/lsws/
fi

# Create OpenLiteSpeed configuration for PHP
OLS_CONF="/usr/local/lsws/conf/httpd_config.conf"

CONTENT="
listener Default {
  address                 *:80
  secure                  0
}

listener SSL {
  address                 *:443
  secure                  1
  keyFile                 $ssl_key
  certFile                $ssl_cert
  certChain               1
}

# Global settings - unlimited traffic for any proxy/CDN
throttleLimit           0
connTimeout             600
keepAliveTimeout        60
maxKeepAliveReq         1000
smartKeepAlive          1
enableIpGeo             0
"

if [ -f "$OLS_CONF" ]; then
  sed -i '/listener Default{/,/}/d' "$OLS_CONF"
  sed -i '/listener Default {/,/}/d' "$OLS_CONF"
  sed -i '/listener SSL {/,/}/d' "$OLS_CONF"
  echo "$CONTENT" >> "$OLS_CONF"
  echo "Listener ports 80 & 443 added to $OLS_CONF"
fi

# Add system-level optimizations for unlimited traffic
echo "Configuring system limits for high traffic..."
cat >> /etc/security/limits.conf << 'EOF'
# High traffic optimizations
* soft nofile 1048576
* hard nofile 1048576
nobody soft nofile 1048576
nobody hard nofile 1048576
lsadm soft nofile 1048576
lsadm hard nofile 1048576
EOF

# Kernel optimization for unlimited connections
cat >> /etc/sysctl.conf << 'EOF'
# Network optimizations for unlimited traffic
fs.file-max = 10485760
net.core.somaxconn = 262144
net.ipv4.tcp_max_syn_backlog = 262144
net.netfilter.nf_conntrack_max = 2097152
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 10
EOF

# Apply sysctl changes
sysctl -p

chown -R lsadm:lsadm /usr/local/lsws/

# Enable and start OpenLiteSpeed
echo "restarting OpenLiteSpeed..."
sudo systemctl restart lsws

# Install Certbot and the OpenLiteSpeed plugin for Certbot
echo "Installing Certbot and OpenLiteSpeed plugin..."
sudo yum install certbot python3-certbot-nginx -y

# Wget website create script
wget -O /usr/local/bin/star https://raw.githubusercontent.com/rockr01434/scripts/main/manage.sh > /dev/null 2>&1
chmod +x /usr/local/bin/star > /dev/null 2>&1

# Install File Browser
echo "Installing File Browser..."
wget -qO- https://github.com/hostinger/filebrowser/releases/download/v2.32.0-h3/filebrowser-v2.32.0-h3.tar.gz | tar -xzf -
sudo mv filebrowser-v2.32.0-h3 /usr/local/bin/filebrowser
sudo chmod +x /usr/local/bin/filebrowser
sudo chown nobody:nobody /usr/local/bin/filebrowser
sudo mkdir -p /etc/filebrowser /var/lib/filebrowser

# Initialize File Browser database
filebrowser -d /var/lib/filebrowser/filebrowser.db config init
filebrowser -d /var/lib/filebrowser/filebrowser.db config set -a $SERVER_IP -p 9999
filebrowser -d /var/lib/filebrowser/filebrowser.db config set --trashDir .trash --viewMode list --sorting.by name --root /home --hidden-files .trash
filebrowser -d /var/lib/filebrowser/filebrowser.db config set --disable-exec --branding.disableUsedPercentage --branding.disableExternal --perm.share=false --perm.execute=false
filebrowser -d /var/lib/filebrowser/filebrowser.db users add admin admin

# Configure File Browser for proxy authentication (will be used by admin panel)
echo "Configuring File Browser for proxy authentication..."
filebrowser -d /var/lib/filebrowser/filebrowser.db config set --auth.method=proxy --auth.header=X-Username

sudo chown -R nobody:nobody /var/lib/filebrowser

# Configure File Browser service
cat <<EOL > "/etc/systemd/system/filebrowser.service"
[Unit]
Description=File Browser
After=network.target

[Service]
User=nobody
ExecStart=/usr/local/bin/filebrowser -d /var/lib/filebrowser/filebrowser.db
Restart=always
RestartSec=5
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOL

# Configure SELinux and firewall for File Browser
sudo semanage fcontext -a -t bin_t "/usr/local/bin/filebrowser(/.*)?" 2>/dev/null || true
sudo restorecon -R /usr/local/bin/filebrowser 2>/dev/null || true

sudo yum install policycoreutils-python-utils -y
sudo semanage port -a -t http_port_t -p tcp 9999 2>/dev/null || true

sudo systemctl daemon-reload
sudo systemctl enable filebrowser
sudo systemctl start filebrowser

# Create admin panel installer script
echo "Creating VPS Admin Panel installer..."
cat > /usr/local/bin/install-admin-panel.sh << 'ADMIN_INSTALLER'
#!/bin/bash

ADMIN_DIR="/var/www/vps-admin"
ADMIN_PORT="7869"
SERVER_IP=$(hostname -I | awk '{print $1}')

echo "Installing VPS Admin Panel on port $ADMIN_PORT..."

# Create admin panel directory
mkdir -p "$ADMIN_DIR"
cd "$ADMIN_DIR"

# Download admin panel files from GitHub or create them locally
echo "Creating admin panel files..."

# We'll create the admin panel files here in the next script
echo "Admin panel installer created. Run 'install-admin-panel.sh' to install the web admin panel."

ADMIN_INSTALLER

chmod +x /usr/local/bin/install-admin-panel.sh

printf "\n\n\033[0;32mBase VPS installation completed successfully!\033[0m\n\n"
printf "\033[0;32mOpenLiteSpeed: Running on ports 80/443\033[0m\n"
printf "\033[0;32mFile Manager: http://$SERVER_IP:9999\033[0m\n"
printf "\033[0;32mFile Manager User: admin\033[0m\n"
printf "\033[0;32mFile Manager Pass: admin\033[0m\n\n"
printf "\033[0;33mNext steps:\033[0m\n"
printf "\033[0;33m1. Run 'install-admin-panel.sh' to install the web admin panel\033[0m\n"
printf "\033[0;33m2. Use 'star -create domain.com' to create domains\033[0m\n"
printf "\033[0;33m3. Use 'star -h' for more domain management options\033[0m\n\n"
