#!/bin/bash

# Configuration
LSDIR='/usr/local/lsws'
WEBCF="${LSDIR}/conf/httpd_config.conf"
VHDIR="${LSDIR}/conf/vhosts"
OLS_CONF="${LSDIR}/conf/httpd_config.conf"
USER='nobody'
GROUP='nobody'
WWW_PATH='/home'

# Update manage.sh with group permissions
cat << 'EOF' > /usr/local/bin/star
#!/bin/bash

# Configuration
LSDIR='/usr/local/lsws'
WEBCF="${LSDIR}/conf/httpd_config.conf"
VHDIR="${LSDIR}/conf/vhosts"
USER='nobody'
GROUP='nobody'
WWW_PATH='/home'

# Functions for colored output
echoR() {
    echo -e "\e[31m${1}\e[39m"
}
echoG() {
    echo -e "\e[32m${1}\e[39m"
}

# Create folder if it does not exist
create_folder() {
    local folder=$1
    mkdir -p "$folder"
}

# Change owner of the files
change_owner() {
    chown $USER:$GROUP "$1"
}

show_help() {
    echo "Usage: $0 [-create DOMAIN] [-delete DOMAIN] [-createbulk] [-h]"
    echo "-create DOMAIN    Create a new website"
    echo "-delete DOMAIN    Delete the website"
    echo "-createbulk       Create multiple websites"
    echo "-h                Show this help message"
    exit 0
}

create_website() {
    local domain=$1
    local doc_root="${WWW_PATH}/${domain}/public_html"
    local doc_logs="${WWW_PATH}/${domain}/logs"
    local vh_conf_file="${VHDIR}/${domain}/vhconf.conf"
    local ssl_dir="${VHDIR}/${domain}/ssl"
    local ssl_key="${ssl_dir}/${domain}.key"
    local ssl_cert="${ssl_dir}/${domain}.crt"

    create_folder "$doc_root"
    create_folder "$doc_logs"
    create_folder "$ssl_dir"

    # Create dummy SSL certificate
    if [ ! -f "$ssl_key" ] || [ ! -f "$ssl_cert" ]; then
        openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
            -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=${domain}" \
            -keyout "$ssl_key" -out "$ssl_cert" > /dev/null 2>&1
        change_owner "$ssl_key"
        change_owner "$ssl_cert"
    fi

    # Create Virtual Host Configuration
    cat <<EOF >> "$WEBCF"

virtualhost ${domain} {
vhRoot                  ${WWW_PATH}/${domain}/
configFile              ${VHDIR}/${domain}/vhconf.conf
allowSymbolLink         1
enableScript            1
restrained              1

ssl {
	enable              1
	certFile            $ssl_cert
	keyFile             $ssl_key
}
}

EOF

    create_folder "${doc_root}"
    create_folder "${VHDIR}/${domain}"

    # Create index.html if it doesn't exist
    if [ ! -f "${doc_root}/index.html" ]; then
        cat <<EOF > "${doc_root}/index.html"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to $domain!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
            color: #333;
        }
        h1 {
            margin-top: 50px;
            font-size: 2em;
        }
    </style>
</head>
<body>
    <h1>Success! The $domain is working!</h1>
</body>
</html>
EOF
        change_owner "${doc_root}/index.html"
    fi

    # Create Virtual Host Configuration if it doesn't exist
    if [ ! -f "${vh_conf_file}" ]; then
        cat > "${vh_conf_file}" <<EOF
docRoot                   \$VH_ROOT/public_html
vhDomain                  \$VH_NAME
vhAliases                 www.\$VH_NAME
adminEmails               nobody@gmail.com
enableGzip                1
enableIpGeo               1

# Unlimited traffic settings - no rate limiting
throttleLimit           0
perClientConnLimit      0
dynReqPerSec            0
staticReqPerSec         0
outBandwidth            0
inBandwidth             0
connTimeout             600
keepAliveTimeout        60

errorlog \$VH_ROOT/logs/\$VH_NAME.error_log {
  useServer               0
  logLevel                WARN
  rollingSize             10M
}

accesslog \$VH_ROOT/logs/\$VH_NAME.access_log {
  useServer               0
  logFormat               "%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i""
  logHeaders              5
  rollingSize             10M
  keepDays                10
  compressArchive         1
}

index  {
useServer               0
indexFiles              index.php, index.html
}

scripthandler  {
add                     lsapi:lsphp73 php
}

extprocessor lsphp73 {
type                    lsapi
address                 uds://tmp/lshttpd/\${domain}.sock
maxConns                500
env                     LSAPI_CHILDREN=200
initTimeout             600
retryTimeout            600
persistConn             1
pcKeepAliveTimeout      1
respBuffer              0
autoStart               1
path                    /usr/local/lsws/lsphp73/bin/lsphp
instances               1
extUser                 nobody
extGroup                nobody
memSoftLimit            2047M
memHardLimit            2047M
procSoftLimit           4000
procHardLimit           5000
}

rewrite  {
enable                  1
autoLoadHtaccess        1
}

context /.well-known/acme-challenge {
  location                /usr/local/lsws/Example/html/.well-known/acme-challenge
  allowBrowse             1

  rewrite  {
     enable                  0
  }
  addDefaultCharset       off

  phpIniOverride  {

  }
}

vhssl  {
  keyFile                 $ssl_key
  certFile                $ssl_cert
  certChain               1
  sslProtocol             24
  enableECDHE             1
  enableDHE               1
  sslSessionCache         1
  sslSessionTickets       1
}
EOF
        chown -R lsadm:nobody "${VHDIR}/${domain}"
        chmod -R g+w "${VHDIR}/${domain}"
    else
        echoR "Virtual host configuration file already exists, skipping!"
    fi

    if grep -q "map.*$domain" "$WEBCF"; then
        echo "Domain $domain already exists."
    else
        add_domain_mapping() {
            local port="$1"
            local temp_file=$(mktemp)
            local in_block=0

            awk -v port="$port" -v domain="$domain" '
                /address\s*\*:'"$port"'/ { in_block=1 }
                in_block && /^\s*}/ { print "  map " domain " " domain ", *." domain; in_block=0 }
                { print }
            ' "$WEBCF" > "$temp_file"

            mv "$temp_file" "$WEBCF"
        }

        add_domain_mapping 80
        add_domain_mapping 443
    fi

    chown -R $USER:$GROUP "${WWW_PATH}/${domain}/"

    echoG "Website ${domain} created successfully"
}

delete_website() {
    local domain=$1
    # Remove Virtual Host configuration
    rm -rf "${VHDIR}/${domain}"

    # Remove document root and logs
    rm -rf "${WWW_PATH}/${domain}"

    # Remove any domain mapping
    sed -i "/map.*${domain}/d" "$WEBCF"

	sed -i "/virtualhost ${domain} {/,/}/d" "$WEBCF"
	chown -R lsadm:nobody /usr/local/lsws/
    chmod -R g+w /usr/local/lsws/
    echoG "Website ${domain} deleted"
}

create_bulk_websites() {
    echo "Enter domain names, one per line (end with an empty line):"

    DOMAIN_LIST=()
    while true; do
        read -r DOMAIN
        if [ -z "$DOMAIN" ]; then
            break
        fi
        DOMAIN_LIST+=("$DOMAIN")
    done

    echo "Domains to be created:"
    for domain in "${DOMAIN_LIST[@]}"; do
        create_website "$domain"
    done

	chown -R lsadm:nobody /usr/local/lsws/
    chmod -R g+w /usr/local/lsws/
    sudo systemctl restart lsws > /dev/null 2>&1
    echoG "Bulk website creation completed and LiteSpeed service restarted."
}

# Main script
if [ $# -eq 0 ]; then
    show_help
fi

while [ "$1" != "" ]; do
    case $1 in
        -create )
            shift
            if [ "$1" != "" ]; then
                DOMAIN=$1
                create_website "$DOMAIN"
				chown -R lsadm:nobody /usr/local/lsws/
				chmod -R g+w /usr/local/lsws/
				sudo systemctl restart lsws > /dev/null 2>&1
                shift
            else
                echoR "Error: -create requires a DOMAIN argument."
                show_help
            fi
            ;;
        -delete )
            shift
            if [ "$1" != "" ]; then
                DOMAIN=$1
                delete_website "$DOMAIN"
                shift
            else
                echoR "Error: -delete requires a DOMAIN argument."
                show_help
            fi
            ;;
        -createbulk )
            create_bulk_websites
            shift
            ;;
        -h )
            show_help
            ;;
        * )
            echoR "Invalid option: $1"
            show_help
            ;;
    esac
done
EOF

chmod +x /usr/local/bin/star

# Create admin panel document root
mkdir -p /home/admin_panel/public_html
chown -R nobody:nobody /home/admin_panel

# Add listener for admin panel
CONTENT="
listener AdminPanel {
  address                 *:7869
  secure                  0
}
"

if [ -f "$OLS_CONF" ]; then
  sed -i '/listener AdminPanel{/,/}/d' "$OLS_CONF"
  sed -i '/listener AdminPanel {/,/}/d' "$OLS_CONF"
  echo "$CONTENT" >> "$OLS_CONF"
  echo "Listener port 7869 added to $OLS_CONF"
fi

# Add virtualhost for admin panel
sed -i '/virtualhost admin_panel {/,/}/d' "$WEBCF"
cat <<EOF >> "$WEBCF"

virtualhost admin_panel {
  vhRoot                  /home/admin_panel/
  configFile              ${VHDIR}/admin_panel/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
}
EOF

# Map admin_panel to listener
if ! grep -q "map admin_panel admin_panel" "$OLS_CONF"; then
  sed -i '/listener AdminPanel {/a\  map                     admin_panel admin_panel' "$OLS_CONF"
fi

# Create vhost config dir and file
create_folder "${VHDIR}/admin_panel"
cat <<EOF > "${VHDIR}/admin_panel/vhconf.conf"
docRoot                   \$VH_ROOT/public_html
enableGzip                1

index  {
  useServer               0
  indexFiles              index.php, index.html
}

scripthandler  {
  add                     lsapi:lsphp73 php
}

extprocessor lsphp73 {
  type                    lsapi
  address                 uds://tmp/lshttpd/admin_panel.sock
  maxConns                500
  env                     LSAPI_CHILDREN=200
  initTimeout             600
  retryTimeout            600
  persistConn             1
  pcKeepAliveTimeout      1
  respBuffer              0
  autoStart               1
  path                    /usr/local/lsws/lsphp73/bin/lsphp
  instances               1
  extUser                 nobody
  extGroup                nobody
  memSoftLimit            2047M
  memHardLimit            2047M
  procSoftLimit           4000
  procHardLimit           5000
}

rewrite  {
  enable                  1
  autoLoadHtaccess        1
}

extprocessor filebrowser_proxy {
  type                    proxy
  address                 127.0.0.1:9999
  maxConns                10
  initTimeout             5
  retryTimeout            0
  respBuffer              0
}

context /filemanager/ {
  type                    proxy
  handler                 filebrowser_proxy
  addDefaultCharset       off
  extraHeaders            <<<END_extraHeaders
X-Auth-User: admin
END_extraHeaders
}

context /phpmyadmin/ {
  location                /usr/share/phpMyAdmin
  allowBrowse             1

  rewrite  {
    enable                  0
  }
  addDefaultCharset       off
}
EOF

# Set permissions for conf
chown -R lsadm:nobody "${VHDIR}/admin_panel"
chmod -R g+w "${VHDIR}/admin_panel"
chown -R lsadm:nobody /usr/local/lsws/conf
chmod -R g+w /usr/local/lsws/conf

# Set sudoers for nobody to restart services
echo "nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart lsws" > /etc/sudoers.d/nobody-lsws
echo "nobody ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart mariadb" > /etc/sudoers.d/nobody-mariadb

# Create login.php
cat << 'EOF' > /home/admin_panel/public_html/login.php
<?php
session_start();
if (isset($_SESSION['loggedin'])) {
    header('Location: index.php');
    exit;
}
$error = '';
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    if ($username == 'admin' && $password == 'admin') {
        $_SESSION['loggedin'] = true;
        header('Location: index.php');
        exit;
    } else {
        $error = 'Invalid credentials';
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/@mdi/font/css/materialdesignicons.min.css" rel="stylesheet">
    <style>
        /* Custom CSS for Hostinger-like */
        body { background-color: #f8f9fc; }
        .login-card { max-width: 400px; margin: auto; margin-top: 100px; }
        .btn-primary { background-color: #673ab7; border-color: #673ab7; }
    </style>
</head>
<body>
    <div class="card login-card">
        <div class="card-body">
            <h3 class="text-center">Admin Login</h3>
            <?php if ($error) echo '<p class="text-danger">'.$error.'</p>'; ?>
            <form method="post">
                <div class="mb-3">
                    <label>Username</label>
                    <input type="text" name="username" class="form-control">
                </div>
                <div class="mb-3">
                    <label>Password</label>
                    <input type="password" name="password" class="form-control">
                </div>
                <button type="submit" class="btn btn-primary w-100">Login</button>
            </form>
        </div>
    </div>
</body>
</html>
EOF

# Create index.php
cat << 'EOF' > /home/admin_panel/public_html/index.php
<?php
session_start();
if (!isset($_SESSION['loggedin'])) {
    header('Location: login.php');
    exit;
}
$page = isset($_GET['page']) ? $_GET['page'] : 'dashboard';
$domains = array_filter(scandir('/home'), function($dir) {
    return $dir != '.' && $dir != '..' && $dir != 'admin_panel';
});
function get_php_version($domain) {
    $conf = "/usr/local/lsws/conf/vhosts/$domain/vhconf.conf";
    if (file_exists($conf)) {
        $content = file_get_contents($conf);
        if (preg_match('/lsphp(\d\d)/', $content, $matches)) {
            return $matches[1][0].'.'.$matches[1][1];
        }
    }
    return '7.3';
}
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['action'])) {
        if ($_POST['action'] == 'create_domain') {
            $domain = trim($_POST['domain']);
            if (!empty($domain)) {
                shell_exec("/usr/local/bin/star -create " . escapeshellarg($domain));
                shell_exec("sudo systemctl restart lsws");
            }
        } elseif ($_POST['action'] == 'delete_domain') {
            $domain = trim($_POST['domain']);
            if (!empty($domain)) {
                shell_exec("/usr/local/bin/star -delete " . escapeshellarg($domain));
                shell_exec("sudo systemctl restart lsws");
            }
        } elseif ($_POST['action'] == 'bulk_create') {
            $domains_list = explode("\n", trim($_POST['domains']));
            foreach ($domains_list as $domain) {
                $domain = trim($domain);
                if (!empty($domain)) {
                    shell_exec("/usr/local/bin/star -create " . escapeshellarg($domain));
                }
            }
            shell_exec("sudo systemctl restart lsws");
        } elseif ($_POST['action'] == 'change_php') {
            $domain = $_POST['domain'];
            $ver = str_replace('.', '', $_POST['version']);
            $conf = "/usr/local/lsws/conf/vhosts/$domain/vhconf.conf";
            if (file_exists($conf)) {
                $content = file_get_contents($conf);
                $content = preg_replace('/lsphp\d\d/', "lsphp$ver", $content);
                $content = preg_replace('/lsphp\d\d\/bin/', "lsphp$ver/bin", $content);
                file_put_contents($conf, $content);
                shell_exec("sudo systemctl restart lsws");
            }
        } elseif ($_POST['action'] == 'restart_service') {
            $service = $_POST['service'];
            shell_exec("sudo systemctl restart $service");
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/@mdi/font/css/materialdesignicons.min.css" rel="stylesheet">
    <style>
        /* Custom CSS to mimic Hostinger dashboard */
        body { font-family: 'Arial', sans-serif; background-color: #f4f6f9; }
        .sidebar { background-color: #4527a0; color: white; height: 100vh; position: fixed; width: 250px; }
        .sidebar a { color: white; }
        .sidebar .nav-link.active { background-color: #673ab7; }
        .content { margin-left: 250px; padding: 20px; }
        .card { border: none; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="p-3">
            <h4>Server Admin</h4>
        </div>
        <nav class="nav flex-column">
            <a class="nav-link <?php if($page=='dashboard') echo 'active'; ?>" href="?page=dashboard"><span class="mdi mdi-view-dashboard"></span> Dashboard</a>
            <a class="nav-link <?php if($page=='domains') echo 'active'; ?>" href="?page=domains"><span class="mdi mdi-domain"></span> Domains</a>
            <a class="nav-link <?php if($page=='php') echo 'active'; ?>" href="?page=php"><span class="mdi mdi-language-php"></span> PHP Settings</a>
            <a class="nav-link <?php if($page=='database') echo 'active'; ?>" href="?page=database"><span class="mdi mdi-database"></span> Database</a>
            <a class="nav-link <?php if($page=='filemanager') echo 'active'; ?>" href="?page=filemanager"><span class="mdi mdi-file-tree"></span> File Manager</a>
            <a class="nav-link <?php if($page=='server') echo 'active'; ?>" href="?page=server"><span class="mdi mdi-server"></span> Server Control</a>
            <a class="nav-link" href="logout.php"><span class="mdi mdi-logout"></span> Logout</a>
        </nav>
    </div>
    <div class="content">
        <?php if ($page == 'dashboard') { ?>
            <h2>Dashboard</h2>
            <p>Welcome to your server admin panel.</p>
        <?php } elseif ($page == 'domains') { ?>
            <h2>Domain Management</h2>
            <div class="row">
                <div class="col-md-6">
                    <h4>Add Domain</h4>
                    <form method="post">
                        <input type="hidden" name="action" value="create_domain">
                        <div class="mb-3">
                            <input type="text" name="domain" class="form-control" placeholder="example.com">
                        </div>
                        <button type="submit" class="btn btn-primary">Add</button>
                    </form>
                </div>
                <div class="col-md-6">
                    <h4>Bulk Add</h4>
                    <form method="post">
                        <input type="hidden" name="action" value="bulk_create">
                        <div class="mb-3">
                            <textarea name="domains" class="form-control" rows="5" placeholder="One domain per line"></textarea>
                        </div>
                        <button type="submit" class="btn btn-primary">Add Bulk</button>
                    </form>
                </div>
            </div>
            <h4>Existing Domains</h4>
            <table class="table">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($domains as $domain) { ?>
                        <tr>
                            <td><?php echo $domain; ?></td>
                            <td>
                                <form method="post" style="display:inline;">
                                    <input type="hidden" name="action" value="delete_domain">
                                    <input type="hidden" name="domain" value="<?php echo $domain; ?>">
                                    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                                </form>
                            </td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
        <?php } elseif ($page == 'php') { ?>
            <h2>PHP Settings</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>PHP Version</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($domains as $domain) { ?>
                        <tr>
                            <td><?php echo $domain; ?></td>
                            <td>
                                <form method="post">
                                    <input type="hidden" name="action" value="change_php">
                                    <input type="hidden" name="domain" value="<?php echo $domain; ?>">
                                    <select name="version" onchange="this.form.submit()">
                                        <option <?php if(get_php_version($domain)=='7.3') echo 'selected'; ?>>7.3</option>
                                        <option <?php if(get_php_version($domain)=='7.4') echo 'selected'; ?>>7.4</option>
                                        <option <?php if(get_php_version($domain)=='8.0') echo 'selected'; ?>>8.0</option>
                                        <option <?php if(get_php_version($domain)=='8.1') echo 'selected'; ?>>8.1</option>
                                    </select>
                                </form>
                            </td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
        <?php } elseif ($page == 'database') { ?>
            <h2>Database Management</h2>
            <iframe src="/phpmyadmin/" width="100%" height="800px" frameborder="0"></iframe>
        <?php } elseif ($page == 'filemanager') { ?>
            <h2>File Manager</h2>
            <iframe src="/filemanager/" width="100%" height="800px" frameborder="0"></iframe>
        <?php } elseif ($page == 'server') { ?>
            <h2>Server Control</h2>
            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body">
                            <h5>OpenLiteSpeed</h5>
                            <form method="post">
                                <input type="hidden" name="action" value="restart_service">
                                <input type="hidden" name="service" value="lsws">
                                <button type="submit" class="btn btn-warning">Restart</button>
                            </form>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body">
                            <h5>MariaDB</h5>
                            <form method="post">
                                <input type="hidden" name="action" value="restart_service">
                                <input type="hidden" name="service" value="mariadb">
                                <button type="submit" class="btn btn-warning">Restart</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        <?php } ?>
    </div>
</body>
</html>
EOF

# Create logout.php
cat << 'EOF' > /home/admin_panel/public_html/logout.php
<?php
session_start();
session_destroy();
header('Location: login.php');
?>
EOF

# Set ownership for public_html
chown -R nobody:nobody /home/admin_panel/public_html

# Restart OpenLiteSpeed
sudo systemctl restart lsws

SERVER_IP=$(hostname -I | awk '{print $1}')
echo -e "\033[0;32mAdmin Panel installed. Access at http://$SERVER_IP:7869\033[0m"
echo -e "\033[0;32mUsername: admin\033[0m"
echo -e "\033[0;32mPassword: admin\033[0m"
