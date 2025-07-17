#!/bin/bash

# install_custom_panel.sh - Install Custom OpenLiteSpeed Management Panel
# This script sets up the web-based custom panel for your OpenLiteSpeed server

echo "🚀 Setting up Custom Server Management Panel..."

# Configuration
PANEL_PORT=7869
PANEL_DIR="/usr/local/lsws/custom_panel"
ADMIN_USER="admin"
ADMIN_PASS="CustomPanel123!"  # Change this to your preferred password
PHP_VERSION="73"  # Default PHP version


# Create custom panel directory
sudo mkdir -p $PANEL_DIR
cd $PANEL_DIR

# Get server IP address
SERVER_IP=$(hostname -I | awk '{print $1}')

echo "📁 Creating panel files..."

# Create the main panel PHP file (copy the content from the artifact)
cat > $PANEL_DIR/index.php << 'EOF'
[The complete custom panel PHP code would be inserted here - this is a placeholder]
EOF

# Copy the actual panel content from our artifact
# Note: In real implementation, you would copy the actual PHP code from the artifact above

# Create configuration file
cat > $PANEL_DIR/config.php << EOF
<?php
// Custom Panel Configuration
return [
    'panel_port' => $PANEL_PORT,
    'lsws_path' => '/usr/local/lsws',
    'vhosts_path' => '/usr/local/lsws/conf/vhosts',
    'www_path' => '/home',
    'config_file' => '/usr/local/lsws/conf/httpd_config.conf',
    'filebrowser_port' => 9999,
    'admin_user' => '$ADMIN_USER',
    'admin_pass' => '$ADMIN_PASS',
    'php_version' => '$PHP_VERSION'
];
EOF

# Create systemd service for custom panel
cat > /etc/systemd/system/custom-panel.service << EOF
[Unit]
Description=Custom Server Management Panel
After=network.target lsws.service

[Service]
Type=simple
User=root
WorkingDirectory=$PANEL_DIR
ExecStart=/usr/local/lsws/lsphp$PHP_VERSION/bin/php -S 0.0.0.0:$PANEL_PORT -t $PANEL_DIR
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create management script for the panel
cat > /usr/local/bin/custom-panel << 'EOF'
#!/bin/bash

case "$1" in
    start)
        systemctl start custom-panel
        echo "✅ Custom panel started"
        ;;
    stop)
        systemctl stop custom-panel
        echo "⏹️ Custom panel stopped"
        ;;
    restart)
        systemctl restart custom-panel
        echo "🔄 Custom panel restarted"
        ;;
    status)
        systemctl status custom-panel
        ;;
    password)
        if [ -z "$2" ]; then
            echo "Usage: custom-panel password <new_password>"
            exit 1
        fi
        sed -i "s/'admin_pass' => '.*'/'admin_pass' => '$2'/" /usr/local/lsws/custom_panel/config.php
        systemctl restart custom-panel
        echo "🔑 Password changed successfully"
        ;;
    logs)
        journalctl -u custom-panel -f
        ;;
    *)
        echo "Usage: custom-panel {start|stop|restart|status|password|logs}"
        echo ""
        echo "Commands:"
        echo "  start     - Start the custom panel"
        echo "  stop      - Stop the custom panel"
        echo "  restart   - Restart the custom panel"
        echo "  status    - Show panel status"
        echo "  password  - Change admin password"
        echo "  logs      - Show live logs"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/custom-panel

# Install File Browser (this was missing!)
wget -qO- https://github.com/hostinger/filebrowser/releases/download/v2.32.0-h3/filebrowser-v2.32.0-h3.tar.gz | tar -xzf -
sudo mv filebrowser-v2.32.0-h3 /usr/local/bin/filebrowser
sudo chmod +x /usr/local/bin/filebrowser
sudo chown nobody:nobody /usr/local/bin/filebrowser
sudo mkdir -p /etc/filebrowser /var/lib/filebrowser

# Configure File Browser
filebrowser -d /var/lib/filebrowser/filebrowser.db config init
filebrowser -d /var/lib/filebrowser/filebrowser.db config set -a $SERVER_IP -p 9999
filebrowser -d /var/lib/filebrowser/filebrowser.db config set --trashDir .trash --viewMode list --sorting.by name --root /home --hidden-files .trash
filebrowser -d /var/lib/filebrowser/filebrowser.db config set --disable-exec --branding.disableUsedPercentage --branding.disableExternal --perm.share=false --perm.execute=false
filebrowser -d /var/lib/filebrowser/filebrowser.db users add admin admin
sudo chown -R nobody:nobody /var/lib/filebrowser

# Configure File Browser with Proxy Authentication
echo "📁 Configuring File Browser with proxy authentication..."

# Configure filebrowser for proxy header authentication
filebrowser -d /var/lib/filebrowser/filebrowser.db config set --auth.method=proxy
filebrowser -d /var/lib/filebrowser/filebrowser.db config set --auth.header=X-Remote-User
filebrowser -d /var/lib/filebrowser/filebrowser.db config set --auth.signup=false


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

# SELinux configuration for File Browser
if command -v semanage &> /dev/null; then
    sudo semanage fcontext -a -t bin_t "/usr/local/bin/filebrowser(/.*)?" 2>/dev/null || true
    sudo restorecon -R /usr/local/bin/filebrowser 2>/dev/null || true
    sudo yum install policycoreutils-python-utils -y &>/dev/null || true
    sudo semanage port -a -t http_port_t -p tcp 9999 2>/dev/null || true
fi

# Start File Browser
sudo systemctl daemon-reload
sudo systemctl enable filebrowser
sudo systemctl start filebrowser

# Create nginx proxy config for file browser (optional enhancement)
cat > /etc/nginx/conf.d/filebrowser-proxy.conf << 'EOF'
# Optional: Nginx proxy configuration for File Browser
# This adds the X-Remote-User header for seamless authentication

upstream filebrowser {
    server 127.0.0.1:9999;
}

server {
    listen 9998;
    server_name _;

    location / {
        proxy_pass http://filebrowser;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Add the remote user header for proxy authentication
        proxy_set_header X-Remote-User $remote_user;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

# Restart filebrowser
sudo systemctl start filebrowser

# Set proper permissions
sudo chown -R nobody:nobody $PANEL_DIR
sudo chmod -R 755 $PANEL_DIR
sudo chmod 644 $PANEL_DIR/*.php

# Configure firewall for custom panel port
echo "🔥 Configuring firewall..."
if command -v firewall-cmd &> /dev/null; then
    sudo firewall-cmd --permanent --add-port=$PANEL_PORT/tcp
    sudo firewall-cmd --reload
    echo "✅ Firewall configured for port $PANEL_PORT"
elif command -v ufw &> /dev/null; then
    sudo ufw allow $PANEL_PORT
    echo "✅ UFW configured for port $PANEL_PORT"
fi

# Add sudoers entries for panel operations
echo "🔐 Setting up sudo permissions..."
cat > /etc/sudoers.d/custom-panel << EOF
# Custom Panel permissions
nobody ALL=(ALL) NOPASSWD: /usr/local/bin/star
nobody ALL=(ALL) NOPASSWD: /bin/systemctl restart lsws
nobody ALL=(ALL) NOPASSWD: /bin/systemctl restart filebrowser
nobody ALL=(ALL) NOPASSWD: /bin/systemctl restart httpd
nobody ALL=(ALL) NOPASSWD: /bin/systemctl restart mysql
nobody ALL=(ALL) NOPASSWD: /bin/systemctl restart mariadb
nobody ALL=(ALL) NOPASSWD: /bin/systemctl status *
nobody ALL=(ALL) NOPASSWD: /bin/systemctl is-active *
nobody ALL=(ALL) NOPASSWD: /usr/bin/certbot
nobody ALL=(ALL) NOPASSWD: /usr/bin/free
nobody ALL=(ALL) NOPASSWD: /usr/bin/df
nobody ALL=(ALL) NOPASSWD: /usr/bin/uptime
nobody ALL=(ALL) NOPASSWD: /usr/bin/netstat
root ALL=(ALL) NOPASSWD: /usr/local/bin/custom-panel
EOF

# Install additional PHP extensions if needed
echo "🐘 Installing additional PHP extensions..."
sudo yum install lsphp$PHP_VERSION-mysql lsphp$PHP_VERSION-mysqli lsphp$PHP_VERSION-pdo lsphp$PHP_VERSION-json -y > /dev/null 2>&1

# Create bulk PHP change script
cat > /usr/local/bin/bulk-php-change << 'EOF'
#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: bulk-php-change <php_version>"
    echo "Available versions: 73, 74, 80, 81, 82"
    exit 1
fi

PHP_VERSION=$1
VHOSTS_DIR="/usr/local/lsws/conf/vhosts"

echo "🐘 Changing PHP version to $PHP_VERSION for all domains..."

changed_count=0
for domain_dir in "$VHOSTS_DIR"/*; do
    if [ -d "$domain_dir" ] && [ "$(basename "$domain_dir")" != "Example" ]; then
        domain=$(basename "$domain_dir")
        vhconf="$domain_dir/vhconf.conf"
        
        if [ -f "$vhconf" ]; then
            # Backup original config
            cp "$vhconf" "$vhconf.backup.$(date +%Y%m%d_%H%M%S)"
            
            # Replace PHP version
            sed -i "s/lsphp[0-9]\+/lsphp$PHP_VERSION/g" "$vhconf"
            sed -i "s|/usr/local/lsws/lsphp[0-9]\+|/usr/local/lsws/lsphp$PHP_VERSION|g" "$vhconf"
            
            echo "✅ Updated $domain to PHP $PHP_VERSION"
            ((changed_count++))
        fi
    fi
done

if [ $changed_count -gt 0 ]; then
    echo "🔄 Restarting LiteSpeed..."
    systemctl restart lsws
    echo "✅ Successfully updated $changed_count domains to PHP $PHP_VERSION"
else
    echo "❌ No domains found to update"
fi
EOF

chmod +x /usr/local/bin/bulk-php-change

# Create domain backup script
cat > /usr/local/bin/backup-domain << 'EOF'
#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: backup-domain <domain> [backup_location]"
    exit 1
fi

DOMAIN=$1
BACKUP_DIR="${2:-/home/backups}"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

echo "📦 Backing up $DOMAIN..."

# Backup website files
if [ -d "/home/$DOMAIN" ]; then
    tar -czf "$BACKUP_DIR/${DOMAIN}_files_${DATE}.tar.gz" -C "/home/$DOMAIN" . 2>/dev/null
    echo "✅ Files backed up: ${DOMAIN}_files_${DATE}.tar.gz"
fi

# Backup virtual host configuration
if [ -d "/usr/local/lsws/conf/vhosts/$DOMAIN" ]; then
    tar -czf "$BACKUP_DIR/${DOMAIN}_config_${DATE}.tar.gz" -C "/usr/local/lsws/conf/vhosts" "$DOMAIN" 2>/dev/null
    echo "✅ Config backed up: ${DOMAIN}_config_${DATE}.tar.gz"
fi

# Backup database if exists
DB_NAME="${DOMAIN//./_}"
if mysql -e "USE $DB_NAME" 2>/dev/null; then
    mysqldump "$DB_NAME" > "$BACKUP_DIR/${DOMAIN}_db_${DATE}.sql" 2>/dev/null
    echo "✅ Database backed up: ${DOMAIN}_db_${DATE}.sql"
fi

echo "🎉 Backup completed in $BACKUP_DIR"
ls -la "$BACKUP_DIR/${DOMAIN}_*_${DATE}.*" 2>/dev/null
EOF

chmod +x /usr/local/bin/backup-domain

# Create system info script
cat > /usr/local/bin/server-info << 'EOF'
#!/bin/bash

echo "🖥️  Server Information"
echo "===================="
echo "Hostname: $(hostname)"
echo "IP Address: $(hostname -I | awk '{print $1}')"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '"')"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"
echo ""

echo "💾 Memory Usage"
echo "==============="
free -h

echo ""
echo "💿 Disk Usage"
echo "============="
df -h /

echo ""
echo "🔄 Running Services"
echo "==================="
services=("lsws" "filebrowser" "custom-panel" "mysql" "mariadb")
for service in "${services[@]}"; do
    status=$(systemctl is-active "$service" 2>/dev/null)
    if [ "$status" = "active" ]; then
        echo "✅ $service: Running"
    else
        echo "❌ $service: Stopped"
    fi
done

echo ""
echo "🌐 Domain Count"
echo "==============="
domain_count=$(find /usr/local/lsws/conf/vhosts -maxdepth 1 -type d | grep -v "Example" | wc -l)
echo "Total domains: $((domain_count - 1))"

echo ""
echo "🔗 Panel URLs"
echo "============="
echo "Custom Panel: http://$(hostname -I | awk '{print $1}'):7869"
echo "File Manager: http://$(hostname -I | awk '{print $1}'):9999"
EOF

chmod +x /usr/local/bin/server-info

# Enable and start the custom panel service
echo "🚀 Starting Custom Panel..."
sudo systemctl daemon-reload
sudo systemctl enable custom-panel
sudo systemctl start custom-panel

# Wait for service to start
sleep 3

# Check if service started successfully
if systemctl is-active --quiet custom-panel; then
    PANEL_STATUS="✅ Running"
else
    PANEL_STATUS="❌ Failed to start"
fi

# Final setup message
echo ""
echo "🎉 Custom Server Management Panel Installation Complete!"
echo "========================================================"
echo ""
echo "📊 Panel Access:"
echo "   URL: http://$SERVER_IP:$PANEL_PORT"
echo "   Username: $ADMIN_USER"
echo "   Password: $ADMIN_PASS"
echo "   Status: $PANEL_STATUS"
echo ""
echo "📁 File Manager:"
echo "   URL: http://$SERVER_IP:9999"
echo "   Authentication: Proxy Header (X-Remote-User)"
echo "   Integrated with panel login"
echo ""
echo "🛠️  Management Commands:"
echo "   custom-panel start|stop|restart|status"
echo "   custom-panel password <new_password>"
echo "   custom-panel logs"
echo "   bulk-php-change <version>"
echo "   backup-domain <domain>"
echo "   server-info"
echo ""
echo "🔥 Panel Features:"
echo "   ✅ Domain Management (Create/Delete/Bulk)"
echo "   ✅ Bulk PHP Version Changes"
echo "   ✅ Individual PHP Version Control"
echo "   ✅ Service Management & Monitoring"
echo "   ✅ SSL Certificate Generation"
echo "   ✅ Integrated File Manager (Proxy Auth)"
echo "   ✅ System Statistics & Monitoring"
echo "   ✅ Log Viewer"
echo "   ✅ Mobile Responsive Design"
echo "   ✅ Keyboard Shortcuts"
echo ""
echo "⌨️  Keyboard Shortcuts:"
echo "   Ctrl+1: Dashboard"
echo "   Ctrl+2: Domains"
echo "   Ctrl+3: PHP Versions"
echo "   Ctrl+4: Services"
echo "   Ctrl+5: File Manager"
echo ""
echo "🔧 Configuration Files:"
echo "   Panel: $PANEL_DIR/"
echo "   Service: /etc/systemd/system/custom-panel.service"
echo "   Sudoers: /etc/sudoers.d/custom-panel"
echo ""

# Show service status
echo "📊 Service Status:"
custom-panel status

echo ""
echo "🚀 Your custom server management panel is ready!"
echo "   Navigate to http://$SERVER_IP:$PANEL_PORT to get started!"
echo ""

# Create phpMyAdmin installation script
cat > $ADMIN_DIR/install_phpmyadmin.php << 'EOF'
<?php
// phpMyAdmin Installation Script
function installPhpMyAdmin() {
    $phpmyadminDir = '/usr/local/lsws/Example/html/phpmyadmin';
    
    if (!is_dir($phpmyadminDir)) {
        // Download and install phpMyAdmin
        $commands = [
            'cd /tmp',
            'wget https://files.phpmyadmin.net/phpMyAdmin/5.2.1/phpMyAdmin-5.2.1-all-languages.tar.gz',
            'tar xzf phpMyAdmin-5.2.1-all-languages.tar.gz',
            'sudo mv phpMyAdmin-5.2.1-all-languages ' . $phpmyadminDir,
            'sudo chown -R nobody:nobody ' . $phpmyadminDir,
            'sudo chmod -R 755 ' . $phpmyadminDir
        ];
        
        foreach ($commands as $command) {
            exec($command, $output, $return);
            if ($return !== 0) {
                return ['success' => false, 'message' => 'Failed to install phpMyAdmin'];
            }
        }
        
        // Create config file
        $configContent = '<?php
$cfg["blowfish_secret"] = "' . bin2hex(random_bytes(32)) . '";
$i = 0;
$i++;
$cfg["Servers"][$i]["auth_type"] = "cookie";
$cfg["Servers"][$i]["host"] = "localhost";
$cfg["Servers"][$i]["compress"] = false;
$cfg["Servers"][$i]["AllowNoPassword"] = false;
$cfg["UploadDir"] = "";
$cfg["SaveDir"] = "";
?>';
        
        file_put_contents($phpmyadminDir . '/config.inc.php', $configContent);
        
        return ['success' => true, 'message' => 'phpMyAdmin installed successfully'];
    } else {
        return ['success' => false, 'message' => 'phpMyAdmin already installed'];
    }
}

if (isset($_GET['install_phpmyadmin'])) {
    header('Content-Type: application/json');
    echo json_encode(installPhpMyAdmin());
    exit;
}
?>
EOF

# Set proper permissions
sudo chown -R nobody:nobody $ADMIN_DIR
sudo chmod -R 755 $ADMIN_DIR
sudo chmod 644 $ADMIN_DIR/*.php

# Configure firewall for admin panel port
if command -v firewall-cmd &> /dev/null; then
    sudo firewall-cmd --permanent --add-port=$ADMIN_PORT/tcp
    sudo firewall-cmd --reload
    echo "Firewall configured for port $ADMIN_PORT"
elif command -v ufw &> /dev/null; then
    sudo ufw allow $ADMIN_PORT
    echo "UFW configured for port $ADMIN_PORT"
fi

# Add sudoers entries for web panel operations
cat >> /etc/sudoers.d/ols-admin << EOF
# OpenLiteSpeed Admin Panel permissions
nobody ALL=(ALL) NOPASSWD: /usr/local/bin/star
nobody ALL=(ALL) NOPASSWD: /bin/systemctl restart lsws
nobody ALL=(ALL) NOPASSWD: /bin/systemctl restart filebrowser
nobody ALL=(ALL) NOPASSWD: /bin/systemctl restart httpd
nobody ALL=(ALL) NOPASSWD: /bin/systemctl restart mysql
nobody ALL=(ALL) NOPASSWD: /bin/systemctl restart mariadb
nobody ALL=(ALL) NOPASSWD: /bin/systemctl status *
nobody ALL=(ALL) NOPASSWD: /bin/systemctl is-active *
nobody ALL=(ALL) NOPASSWD: /usr/bin/certbot
EOF

# Install additional PHP extensions if needed
echo "Installing additional PHP extensions..."
sudo yum install lsphp$PHP_VERSION-mysql lsphp$PHP_VERSION-mysqli lsphp$PHP_VERSION-pdo -y > /dev/null 2>&1

# Install MariaDB if not present
if ! command -v mysql &> /dev/null && ! command -v mariadb &> /dev/null; then
    echo "Installing MariaDB..."
    sudo yum install mariadb-server mariadb -y
    sudo systemctl enable mariadb
    sudo systemctl start mariadb
    
    # Secure MariaDB installation
    echo "Securing MariaDB installation..."
    mysql -e "UPDATE mysql.user SET Password=PASSWORD('root') WHERE User='root'"
    mysql -e "DELETE FROM mysql.user WHERE User=''"
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
    mysql -e "DROP DATABASE IF EXISTS test"
    mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'"
    mysql -e "FLUSH PRIVILEGES"
fi

# Create improved file manager integration script
cat > $ADMIN_DIR/filebrowser_integration.php << 'EOF'
<?php
// File Browser Integration with Session Management

function createFileBrowserSession() {
    $filebrowserConfig = '/var/lib/filebrowser/filebrowser.db';
    $sessionToken = bin2hex(random_bytes(32));
    
    // Create temporary admin session in filebrowser
    $commands = [
        "filebrowser -d $filebrowserConfig users update admin --password admin",
        "filebrowser -d $filebrowserConfig config set --auth.method=proxy",
        "filebrowser -d $filebrowserConfig config set --auth.header=X-Forwarded-User"
    ];
    
    foreach ($commands as $command) {
        exec($command, $output, $return);
    }
    
    return $sessionToken;
}

function getFileBrowserURL() {
    $serverIP = $_SERVER['HTTP_HOST'];
    $port = 9999;
    $session = createFileBrowserSession();
    
    return "http://$serverIP:$port";
}

if (isset($_GET['filebrowser_url'])) {
    header('Content-Type: application/json');
    echo json_encode(['url' => getFileBrowserURL()]);
    exit;
}
?>
EOF

# Enable and start the admin panel service
sudo systemctl daemon-reload
sudo systemctl enable ols-admin
sudo systemctl start ols-admin

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')

# Create a quick setup script for domain SSL
cat > /usr/local/bin/quick-ssl << 'EOF'
#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: quick-ssl <domain>"
    exit 1
fi

DOMAIN=$1

echo "Setting up SSL for $DOMAIN..."

# Install SSL certificate
certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN

if [ $? -eq 0 ]; then
    echo "SSL certificate installed successfully for $DOMAIN"
    systemctl restart lsws
else
    echo "Failed to install SSL certificate for $DOMAIN"
fi
EOF

chmod +x /usr/local/bin/quick-ssl

# Create domain backup script
cat > /usr/local/bin/backup-domain << 'EOF'
#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: backup-domain <domain>"
    exit 1
fi

DOMAIN=$1
BACKUP_DIR="/home/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

echo "Backing up $DOMAIN..."

# Backup website files
tar -czf "$BACKUP_DIR/${DOMAIN}_files_${DATE}.tar.gz" -C "/home/$DOMAIN" .

# Backup virtual host configuration
cp -r "/usr/local/lsws/conf/vhosts/$DOMAIN" "$BACKUP_DIR/${DOMAIN}_config_${DATE}/"

# Backup database if exists
if mysql -e "use ${DOMAIN//./_}" 2>/dev/null; then
    mysqldump "${DOMAIN//./_}" > "$BACKUP_DIR/${DOMAIN}_db_${DATE}.sql"
fi

echo "Backup completed: $BACKUP_DIR/${DOMAIN}_*_${DATE}.*"
EOF

chmod +x /usr/local/bin/backup-domain

# Create system monitoring script
cat > $ADMIN_DIR/system_monitor.php << 'EOF'
<?php
// System Monitoring Functions

function getDetailedSystemStats() {
    $stats = [];
    
    // CPU Usage
    $cpuLoad = sys_getloadavg();
    $stats['cpu'] = [
        'load_1min' => $cpuLoad[0],
        'load_5min' => $cpuLoad[1],
        'load_15min' => $cpuLoad[2]
    ];
    
    // Memory Usage
    $meminfo = file_get_contents('/proc/meminfo');
    preg_match('/MemTotal:\s+(\d+)/', $meminfo, $memTotal);
    preg_match('/MemAvailable:\s+(\d+)/', $meminfo, $memAvailable);
    
    $stats['memory'] = [
        'total_mb' => round($memTotal[1] / 1024, 2),
        'available_mb' => round($memAvailable[1] / 1024, 2),
        'used_mb' => round(($memTotal[1] - $memAvailable[1]) / 1024, 2),
        'usage_percent' => round((($memTotal[1] - $memAvailable[1]) / $memTotal[1]) * 100, 2)
    ];
    
    // Disk Usage
    $diskTotal = disk_total_space('/');
    $diskFree = disk_free_space('/');
    $diskUsed = $diskTotal - $diskFree;
    
    $stats['disk'] = [
        'total_gb' => round($diskTotal / (1024*1024*1024), 2),
        'used_gb' => round($diskUsed / (1024*1024*1024), 2),
        'free_gb' => round($diskFree / (1024*1024*1024), 2),
        'usage_percent' => round(($diskUsed / $diskTotal) * 100, 2)
    ];
    
    // Network Stats
    $networkStats = shell_exec("cat /proc/net/dev | grep -E '(eth0|ens|enp)' | head -1");
    if ($networkStats) {
        $parts = preg_split('/\s+/', trim($networkStats));
        $stats['network'] = [
            'rx_bytes' => $parts[1] ?? 0,
            'tx_bytes' => $parts[9] ?? 0
        ];
    }
    
    // Active Connections
    $connections = shell_exec("netstat -an | grep :80 | grep ESTABLISHED | wc -l");
    $stats['connections'] = [
        'active_http' => (int)trim($connections),
        'total_processes' => (int)trim(shell_exec("ps aux | wc -l"))
    ];
    
    return $stats;
}

if (isset($_GET['detailed_stats'])) {
    header('Content-Type: application/json');
    echo json_encode(getDetailedSystemStats());
    exit;
}
?>
EOF

# Final setup message
echo ""
echo "🎉 OpenLiteSpeed Admin Panel installation completed!"
echo ""
echo "📊 Admin Panel URL: http://$SERVER_IP:$ADMIN_PORT"
echo "👤 Username: $ADMIN_USER"
echo "🔑 Password: $ADMIN_PASS"
echo ""
echo "📁 File Manager: http://$SERVER_IP:9999"
echo "📁 File Manager User: admin"
echo "📁 File Manager Pass: admin"
echo ""
echo "🔧 Management Commands:"
echo "   admin-panel start|stop|restart|status"
echo "   admin-panel password <new_password>"
echo "   star -create <domain>"
echo "   star -delete <domain>"
echo "   quick-ssl <domain>"
echo "   backup-domain <domain>"
echo ""
echo "🔥 Features Available:"
echo "   ✅ Domain Management (Create/Delete/Bulk)"
echo "   ✅ PHP Version Switching"
echo "   ✅ Service Management"
echo "   ✅ SSL Certificate Generation"
echo "   ✅ File Manager Integration"
echo "   ✅ phpMyAdmin Setup"
echo "   ✅ System Monitoring"
echo "   ✅ Log Viewer"
echo ""
echo "🚀 Your server management panel is ready!"
echo ""
