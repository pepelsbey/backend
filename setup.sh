#!/bin/bash

#===============================================================================
# Server Setup & Site Management Script
#===============================================================================
# A unified script for setting up Ubuntu servers and managing static websites
# with Caddy as a reverse proxy with automatic HTTPS.
#
# Usage (root only):
#   setup                  # Interactive mode
#   setup add              # Add a new site
#   setup list             # List all sites
#   setup remove           # Remove a site
#   setup status           # Show server status
#   setup logs             # View Caddy logs
#   setup reload           # Reload Caddy config
#   setup restart          # Restart Caddy container
#   setup update caddy     # Update Caddy image
#   setup update setup     # Update this script
#
# Requirements:
#   - Ubuntu 22.04 or 24.04 LTS
#   - Root access via SSH key
#
# Users:
#   root   - Server management, SSH key-only login
#   deploy - Content deployment only (rsync/scp)
#
# Directory Structure (owned by root):
#   /opt/config            - Server configuration files
#   /opt/sites/<domain>    - Per-site directories
#     /Caddyfile           - Site-specific configuration
#     /public              - Site's public content (owned by deploy)
#===============================================================================

set -euo pipefail

# Cleanup temporary files on exit
cleanup() {
	rm -f "$CONFIG_DIR/setup.sh.new" 2>/dev/null || true
}
trap cleanup EXIT

#-------------------------------------------------------------------------------
# Colors and Logging
#-------------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_header() { echo -e "\n${BOLD}${CYAN}$1${NC}\n"; }

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------

CONFIG_DIR="/opt/config"
SITES_DIR="/opt/sites"
SETUP_MARKER="$CONFIG_DIR/.setup_complete"
DEPLOY_USER="deploy"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_URL="https://raw.githubusercontent.com/pepelsbey/backend/refs/heads/main/setup.sh"

#-------------------------------------------------------------------------------
# Embedded Configuration Files
#-------------------------------------------------------------------------------

generate_docker_compose() {
	cat << 'DOCKER_COMPOSE_EOF'
services:
  caddy:
    image: caddy:2-alpine
    container_name: caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - /opt/sites:/opt/sites:ro
      - /var/log/caddy:/var/log/caddy
      - caddy_data:/data
      - caddy_config:/config
    healthcheck:
      test: ["CMD", "wget", "--spider", "--quiet", "http://localhost:80"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "5"

volumes:
  caddy_data:
    name: caddy_data
  caddy_config:
    name: caddy_config
DOCKER_COMPOSE_EOF
}

generate_caddyfile() {
	cat << 'CADDYFILE_EOF'
# Common configuration snippet for all sites
(common) {
	file_server {
		hide .*
		precompressed br gzip
	}

	# Compression (fallback for non-precompressed files)
	encode zstd gzip

	# Security headers
	header {
		X-Frame-Options "SAMEORIGIN"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "strict-origin-when-cross-origin"
		Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
		Cross-Origin-Resource-Policy "same-origin"
		Cross-Origin-Opener-Policy "same-origin"
		-Server
	}

	# Clean URLs
	try_files {path} {path}.html {path}/index.html {path}/index.xml

	# Cache static assets
	@static {
		path *.css *.js
		path *.ico *.gif *.jpg *.jpeg *.png *.svg *.webp *.avif
		path *.woff *.woff2
		path *.mp3
	}
	header @static Cache-Control "public, max-age=31536000, immutable"

	# Cache HTML with revalidation
	@html path *.html
	header @html Cache-Control "public, max-age=3600, must-revalidate"

	log {
		output file /var/log/caddy/{args[0]}.log {
			roll_size 10mb
			roll_keep 5
		}
		format json
	}
}

# Import all site configurations
import /opt/sites/*/Caddyfile
CADDYFILE_EOF
}

generate_site_caddyfile() {
	local domain="$1"
	local email="$2"
	cat << SITE_CADDYFILE_EOF
$domain {
	root * /opt/sites/$domain/public
	tls $email
	import common $domain

	# header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
	# header Content-Security-Policy "default-src 'self'"

	# redir /old-page /new-page permanent

	handle_errors {
		@404 expression {http.error.status_code} == 404
		handle @404 {
			rewrite * /404.html
			file_server
		}
	}
}

www.$domain {
	tls $email
	redir https://$domain{uri} permanent
}
SITE_CADDYFILE_EOF
}

#-------------------------------------------------------------------------------
# Helper Functions
#-------------------------------------------------------------------------------

check_ubuntu() {
	if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
		log_error "This script is designed for Ubuntu only"
		exit 1
	fi
}

is_setup_complete() {
	[[ -f "$SETUP_MARKER" ]]
}

list_sites() {
	if [[ -d "$SITES_DIR" ]] && [[ -n "$(ls -A "$SITES_DIR" 2>/dev/null)" ]]; then
		for site in "$SITES_DIR"/*/; do
			if [[ -d "$site" ]]; then
				local domain=$(basename "$site")
				local has_content=""
				if [[ -n "$(ls -A "$site/public" 2>/dev/null)" ]]; then
					has_content=" (has content)"
				else
					has_content=" (empty)"
				fi
				echo "  - $domain$has_content"
			fi
		done
	else
		echo "  (no sites configured)"
	fi
}

get_site_count() {
	local count=0
	if [[ -d "$SITES_DIR" ]]; then
		count=$(find "$SITES_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
	fi
	echo "$count"
}

validate_domain() {
	local domain="$1"
	if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]; then
		return 1
	fi
	return 0
}

validate_email() {
	local email="$1"
	if [[ ! "$email" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
		return 1
	fi
	return 0
}

caddy_running() {
	[[ -n "$(docker ps -q --filter 'name=^caddy$' 2>/dev/null)" ]]
}

#-------------------------------------------------------------------------------
# Site Management Functions
#-------------------------------------------------------------------------------

cmd_add_site() {
	if [[ ! -d "$SITES_DIR" ]]; then
		log_error "Sites directory does not exist. Run this script without arguments first to set up the server."
		exit 1
	fi

	local domain="${1:-}"
	local email="${2:-}"

	# Interactive mode if arguments not provided
	if [[ -z "$domain" ]]; then
		read -rp "Enter domain name (e.g., example.com): " domain || true
	fi

	if [[ -z "$email" ]]; then
		read -rp "Enter email for Let's Encrypt certificates: " email || true
	fi

	# Validate inputs
	if [[ -z "$domain" ]]; then
		log_error "Domain name is required"
		return 1
	fi

	if [[ -z "$email" ]]; then
		log_error "Email is required"
		return 1
	fi

	if ! validate_domain "$domain"; then
		log_error "Invalid domain name format: $domain"
		return 1
	fi

	if ! validate_email "$email"; then
		log_error "Invalid email format: $email"
		return 1
	fi

	local site_dir="$SITES_DIR/$domain"

	if [[ -d "$site_dir" ]]; then
		log_error "Site already exists: $site_dir"
		log_info "To reconfigure, remove it first: $SCRIPT_NAME remove $domain"
		return 1
	fi

	log_info "Creating site structure for: $domain"

	# Create directories
	mkdir -p "$site_dir/public"

	# Create site-specific Caddyfile
	generate_site_caddyfile "$domain" "$email" > "$site_dir/Caddyfile"

	# Set ownership: root owns site dir and Caddyfile, deploy only owns public/
	chmod 755 "$site_dir"
	chmod 644 "$site_dir/Caddyfile"
	chmod 755 "$site_dir/public"
	if id "$DEPLOY_USER" &>/dev/null; then
		chown "$DEPLOY_USER:$DEPLOY_USER" "$site_dir/public"
	fi

	log_success "Site added: $domain"
	echo ""
	log_info "Directory structure:"
	echo "  $site_dir/"
	echo "  ├── Caddyfile"
	echo "  └── public/"
	echo ""
	log_info "Next steps:"
	echo "  1. Add your content to: $site_dir/public/"
	echo "  2. Customize $site_dir/Caddyfile as needed"
	if caddy_running; then
		echo "  3. Reload Caddy: $SCRIPT_NAME restart"
	else
		echo "  3. Start Caddy: cd $CONFIG_DIR && docker compose up -d"
	fi
	echo ""

	return 0
}

cmd_remove_site() {
	local domain="${1:-}"

	if [[ -z "$domain" ]]; then
		log_info "Existing sites:"
		list_sites
		echo ""
		read -rp "Enter domain to remove: " domain || true
	fi

	if [[ -z "$domain" ]]; then
		log_error "Domain name is required"
		return 1
	fi

	local site_dir="$SITES_DIR/$domain"

	if [[ ! -d "$site_dir" ]]; then
		log_error "Site not found: $domain"
		return 1
	fi

	echo ""
	log_warning "This will permanently delete:"
	echo "  $site_dir/"
	echo ""
	read -rp "Are you sure you want to remove '$domain'? (yes/no): " confirm || true

	if [[ "$confirm" != "yes" ]]; then
		log_info "Cancelled."
		return 0
	fi

	rm -rf "$site_dir"
	log_success "Site removed: $domain"

	if caddy_running; then
		log_info "Reloading Caddy configuration..."
		if docker exec caddy caddy validate --config /etc/caddy/Caddyfile 2>/dev/null; then
			docker exec caddy caddy reload --config /etc/caddy/Caddyfile 2>/dev/null || true
		else
			log_warning "Caddyfile validation failed — skipping reload"
		fi
	fi

	return 0
}

cmd_list_sites() {
	log_header "Configured Sites"
	list_sites
	echo ""
}

#-------------------------------------------------------------------------------
# Server Management Functions
#-------------------------------------------------------------------------------

cmd_status() {
	log_header "Server Status"

	echo "Setup Status:"
	if is_setup_complete; then
		echo "  ✓ Server setup complete ($(cat "$SETUP_MARKER" 2>/dev/null || echo 'unknown date'))"
	else
		echo "  ✗ Server not yet set up"
	fi
	echo ""

	echo "Caddy Container:"
	if caddy_running; then
		echo "  ✓ Running"
		docker ps --filter "name=caddy" --format "  Image: {{.Image}}\n  Uptime: {{.Status}}" 2>/dev/null
	else
		echo "  ✗ Not running"
	fi
	echo ""

	echo "Sites: $(get_site_count) configured"
	list_sites
	echo ""

	echo "Disk Usage:"
	echo "  Sites:  $(du -sh "$SITES_DIR" 2>/dev/null | cut -f1 || echo 'N/A')"
	echo "  Logs:   $(du -sh /var/log/caddy 2>/dev/null | cut -f1 || echo 'N/A')"
	echo ""

	echo "Firewall (UFW):"
	if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
		echo "  ✓ Active"
	else
		echo "  ✗ Inactive or not installed"
	fi
	echo ""
}

cmd_logs() {
	local domain=""
	local lines="50"

	# Parse arguments: first check if arg looks like a number or domain
	if [[ -n "${1:-}" ]]; then
		if [[ "$1" =~ ^[0-9]+$ ]]; then
			lines="$1"
			domain="${2:-}"
		else
			domain="$1"
			[[ -n "${2:-}" && "$2" =~ ^[0-9]+$ ]] && lines="$2"
		fi
	fi

	if ! caddy_running; then
		log_error "Caddy is not running"
		return 1
	fi

	if [[ -n "$domain" ]]; then
		local log_file="/var/log/caddy/$domain.log"
		if [[ -f "$log_file" ]]; then
			log_info "Showing last $lines lines for $domain:"
			tail -n "$lines" "$log_file"
		else
			log_error "Log file not found: $log_file"
		fi
	else
		log_info "Showing last $lines lines of Caddy logs:"
		docker logs --tail "$lines" caddy 2>&1
	fi
}

cmd_reload() {
	if ! is_setup_complete; then
		log_error "Server has not been set up yet"
		return 1
	fi

	log_info "Reloading Caddy configuration..."

	if caddy_running; then
		if ! docker exec caddy caddy validate --config /etc/caddy/Caddyfile 2>/dev/null; then
			log_error "Caddyfile validation failed — not reloading"
			return 1
		fi
		if docker exec caddy caddy reload --config /etc/caddy/Caddyfile 2>/dev/null; then
			log_success "Caddy configuration reloaded"
		else
			log_error "Reload failed"
			return 1
		fi
	else
		log_error "Caddy is not running. Use 'restart' to start it."
		return 1
	fi
}

cmd_restart() {
	if ! is_setup_complete; then
		log_error "Server has not been set up yet"
		return 1
	fi

	log_info "Restarting Caddy container..."

	cd "$CONFIG_DIR"

	if caddy_running; then
		docker restart caddy
		log_success "Caddy container restarted"
	else
		docker compose up -d
		log_success "Caddy started"
	fi
}

cmd_update() {
	local target="${1:-}"

	if [[ -z "$target" ]]; then
		log_error "Specify what to update: caddy or setup"
		return 1
	fi

	if ! is_setup_complete; then
		log_error "Server has not been set up yet"
		return 1
	fi

	case "$target" in
		caddy)
			echo ""
			log_info "This will pull the latest Caddy image and restart the container."
			read -rp "Continue? (y/n): " confirm || true

			if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
				log_info "Cancelled."
				return 0
			fi

			log_info "Updating Caddy to latest version..."

			cd "$CONFIG_DIR"

			# Pull latest image and recreate container
			docker compose pull
			docker compose up -d --pull always

			# Clean up old images
			docker image prune -f

			log_success "Caddy updated to latest version"
			docker ps --filter "name=caddy" --format "Image: {{.Image}}"
			;;
		setup)
			log_info "Updating setup script from GitHub..."

			if curl -fsSL -o "$CONFIG_DIR/setup.sh.new" "$SCRIPT_URL"; then
				# Validate downloaded file is a bash script
				if ! head -1 "$CONFIG_DIR/setup.sh.new" | grep -q "^#!/bin/bash"; then
					log_error "Downloaded file doesn't appear to be a valid bash script"
					rm -f "$CONFIG_DIR/setup.sh.new"
					return 1
				fi

				# Validate basic bash syntax
				if ! bash -n "$CONFIG_DIR/setup.sh.new" 2>/dev/null; then
					log_error "Downloaded script has syntax errors"
					rm -f "$CONFIG_DIR/setup.sh.new"
					return 1
				fi

				chmod +x "$CONFIG_DIR/setup.sh.new"
				mv "$CONFIG_DIR/setup.sh.new" "$CONFIG_DIR/setup.sh"
				chown root:root "$CONFIG_DIR/setup.sh"
				log_success "Setup script updated"
			else
				log_error "Failed to download setup script"
				rm -f "$CONFIG_DIR/setup.sh.new"
				return 1
			fi
			;;
		*)
			log_error "Unknown update target: $target (use 'caddy' or 'setup')"
			return 1
			;;
	esac
}

cmd_ssl_status() {
	if ! caddy_running; then
		log_error "Caddy is not running"
		return 1
	fi

	log_header "SSL Certificate Status"

	for site in "$SITES_DIR"/*/; do
		if [[ -d "$site" ]]; then
			local domain=$(basename "$site")
			echo -n "  $domain: "

			# Try to get certificate info
			local cert_info=$(echo | timeout 5 openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)

			if [[ -n "$cert_info" ]]; then
				local expiry=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
				echo "Valid until $expiry"
			else
				echo "Unable to check (DNS may not be configured yet)"
			fi
		fi
	done
	echo ""
}

#-------------------------------------------------------------------------------
# Initial Server Setup
#-------------------------------------------------------------------------------

do_initial_setup() {
	check_ubuntu

	log_header "Starting Initial Server Setup"

	#---------------------------------------------------------------------------
	# System Updates
	#---------------------------------------------------------------------------

	log_info "Updating system packages..."
	apt-get update
	DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
	DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y

	#---------------------------------------------------------------------------
	# Install Essential Packages
	#---------------------------------------------------------------------------

	log_info "Installing essential packages..."
	DEBIAN_FRONTEND=noninteractive apt-get install -y \
		apt-transport-https \
		ca-certificates \
		curl \
		gnupg \
		lsb-release \
		ufw \
		unattended-upgrades \
		apt-listchanges

	#---------------------------------------------------------------------------
	# Install Docker
	#---------------------------------------------------------------------------

	log_info "Installing Docker..."

	if command -v docker &> /dev/null; then
		log_info "Docker is already installed"
	else
		# Install Docker using the official apt repository
		install -m 0755 -d /etc/apt/keyrings
		curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
		chmod a+r /etc/apt/keyrings/docker.asc

		echo \
			"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
			$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
			tee /etc/apt/sources.list.d/docker.list > /dev/null

		apt-get update
		DEBIAN_FRONTEND=noninteractive apt-get install -y \
			docker-ce \
			docker-ce-cli \
			containerd.io \
			docker-buildx-plugin \
			docker-compose-plugin

		systemctl enable docker
		systemctl start docker
	fi

	log_success "Docker installed: $(docker --version)"

	#---------------------------------------------------------------------------
	# Configure Firewall (UFW)
	#---------------------------------------------------------------------------

	log_info "Configuring firewall..."

	ufw --force reset
	ufw default deny incoming
	ufw default allow outgoing

	ufw allow 22/tcp comment 'SSH'
	ufw allow 80/tcp comment 'HTTP'
	ufw allow 443/tcp comment 'HTTPS'
	ufw allow 443/udp comment 'HTTP/3'

	ufw --force enable

	log_success "Firewall configured"
	ufw status

	#---------------------------------------------------------------------------
	# Configure SSH Hardening
	#---------------------------------------------------------------------------

	log_info "Hardening SSH configuration..."

	cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

	cat > /etc/ssh/sshd_config.d/99-hardened.conf << 'EOF'
# SSH Hardening Configuration
PasswordAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
EOF

	mkdir -p /run/sshd

	if sshd -t; then
		systemctl restart ssh
		log_success "SSH hardened successfully"
	else
		log_error "SSH configuration error, reverting..."
		rm /etc/ssh/sshd_config.d/99-hardened.conf
		exit 1
	fi

	#---------------------------------------------------------------------------
	# Configure Automatic Updates
	#---------------------------------------------------------------------------

	log_info "Configuring automatic security updates..."

	cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

	cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

	systemctl enable unattended-upgrades
	log_success "Automatic updates configured"

	#---------------------------------------------------------------------------
	# Create Deploy User
	#---------------------------------------------------------------------------

	if ! id "$DEPLOY_USER" &>/dev/null; then
		log_info "Creating deploy user (content deployment only)..."
		adduser --disabled-password --gecos "" "$DEPLOY_USER"

		mkdir -p "/home/$DEPLOY_USER/.ssh"
		if [[ -f /root/.ssh/authorized_keys ]]; then
			cp /root/.ssh/authorized_keys "/home/$DEPLOY_USER/.ssh/"
			chown -R "$DEPLOY_USER:$DEPLOY_USER" "/home/$DEPLOY_USER/.ssh"
			chmod 700 "/home/$DEPLOY_USER/.ssh"
			chmod 600 "/home/$DEPLOY_USER/.ssh/authorized_keys"
		fi

		log_success "Deploy user created"
	else
		log_info "Deploy user already exists"
	fi

	# Create symlink for global 'setup' command (root only)
	ln -sf "$CONFIG_DIR/setup.sh" /usr/local/bin/setup

	#---------------------------------------------------------------------------
	# Create Directory Structure
	#---------------------------------------------------------------------------

	log_info "Creating directory structure..."

	mkdir -p "$CONFIG_DIR"
	mkdir -p "$SITES_DIR"
	mkdir -p /var/log/caddy

	chown -R root:root "$CONFIG_DIR"
	chown -R root:root "$SITES_DIR"
	chown -R root:root /var/log/caddy

	log_success "Directories created"

	#---------------------------------------------------------------------------
	# Write Configuration Files
	#---------------------------------------------------------------------------

	log_info "Writing configuration files..."

	generate_caddyfile > "$CONFIG_DIR/Caddyfile"
	generate_docker_compose > "$CONFIG_DIR/docker-compose.yml"

	# Copy this script to config dir (all config owned by root)
	cp "$0" "$CONFIG_DIR/setup.sh"
	chmod +x "$CONFIG_DIR/setup.sh"

	log_success "Configuration files written to $CONFIG_DIR"

	#---------------------------------------------------------------------------
	# Add Initial Sites
	#---------------------------------------------------------------------------

	log_header "Website Configuration"
	log_info "Now let's configure your websites."
	echo ""

	local sites_added=0

	while true; do
		if [[ $sites_added -eq 0 ]]; then
			read -rp "Enter domain name (e.g., example.com): " domain || true
		else
			echo ""
			read -rp "Enter another domain (or press Enter to finish): " domain || true
		fi

		if [[ -z "$domain" ]]; then
			if [[ $sites_added -eq 0 ]]; then
				log_warning "At least one site is required."
				continue
			else
				break
			fi
		fi

		read -rp "Enter email for Let's Encrypt certificates: " email || true

		if [[ -z "$email" ]]; then
			log_warning "Email is required. Skipping this site."
			continue
		fi

		if cmd_add_site "$domain" "$email"; then
			((sites_added++)) || true
		fi
	done

	#---------------------------------------------------------------------------
	# Mark Setup as Complete
	#---------------------------------------------------------------------------

	echo "$(date -Iseconds)" > "$SETUP_MARKER"

	#---------------------------------------------------------------------------
	# Cleanup
	#---------------------------------------------------------------------------

	log_info "Cleaning up..."
	apt-get autoremove -y
	apt-get autoclean -y

	#---------------------------------------------------------------------------
	# Summary
	#---------------------------------------------------------------------------

	log_header "Server Setup Complete!"

	echo "What was configured:"
	echo "  ✓ System packages updated"
	echo "  ✓ Docker and Docker Compose installed"
	echo "  ✓ Firewall (UFW) configured - ports 22, 80, 443 open"
	echo "  ✓ SSH hardened (key-only auth, root via key)"
	echo "  ✓ Automatic security updates enabled"
	echo "  ✓ Deploy user '$DEPLOY_USER' created (content only)"
	echo "  ✓ Directory structure created"
	echo ""
	echo "Sites configured ($sites_added total):"
	list_sites
	echo ""
	echo "Directory structure:"
	echo "  $CONFIG_DIR/"
	echo "    ├── Caddyfile"
	echo "    ├── docker-compose.yml"
	echo "    └── setup.sh"
	echo "  $SITES_DIR/<domain>/"
	echo "    ├── Caddyfile"
	echo "    └── public/"
	echo ""
	log_warning "IMPORTANT: Before logging out, verify SSH access works!"
	echo ""
	echo "  1. Open a new terminal and test root access:"
	echo "     ssh root@$(hostname -I | awk '{print $1}')"
	echo ""
	echo "  2. Start the web server:"
	echo "     cd $CONFIG_DIR && docker compose up -d"
	echo ""
	echo "  3. Management commands (as root):"
	echo "     setup add       # Add a new site"
	echo "     setup list      # List all sites"
	echo "     setup status    # Show server status"
	echo "     setup logs      # View Caddy logs"
	echo "     setup restart   # Restart Caddy"
	echo ""
	echo "  4. Deploy content (from local machine):"
	echo "     rsync ... ./dist/ $DEPLOY_USER@<server>:/opt/sites/<domain>/public/"
	echo ""
	log_info "Password auth is disabled. Root and deploy use key-based SSH."
	echo ""
}

#-------------------------------------------------------------------------------
# Interactive Menu
#-------------------------------------------------------------------------------

show_menu() {
	while true; do
		log_header "Server Management Menu"

		echo "Sites: $(get_site_count) configured"
		echo "Caddy: $(caddy_running && echo 'Running' || echo 'Not running')"
		echo ""
		echo "Commands:"
		echo "  1) Add a new site"
		echo "  2) Remove a site"
		echo "  3) List all sites"
		echo "  4) Show server status"
		echo "  5) View Caddy logs"
		echo "  6) Reload Caddy config"
		echo "  7) Restart Caddy container"
		echo "  8) Update Caddy image"
		echo "  9) Update setup script"
		echo "  s) Check SSL certificates"
		echo "  0) Exit"
		echo ""
		read -rp "Choose an option: " choice || true

		case "$choice" in
			1) cmd_add_site ;;
			2) cmd_remove_site ;;
			3) cmd_list_sites ;;
			4) cmd_status ;;
			5) cmd_logs ;;
			6) cmd_reload ;;
			7) cmd_restart ;;
			8) cmd_update caddy ;;
			9) cmd_update setup ;;
			s|S) cmd_ssl_status ;;
			0) exit 0 ;;
			*) log_error "Invalid option" ;;
		esac

		echo ""
		read -rp "Press Enter to continue..." || true
	done
}

show_help() {
	cat << EOF
Usage: setup [command] [options]

All commands require root access.

Commands:
  (no command)           Interactive menu
  add [domain] [email]   Add a new site
  remove [domain]        Remove a site
  list                   List all sites
  status                 Show server status
  logs [domain] [n]      View Caddy logs
  reload                 Reload Caddy config
  restart                Restart Caddy container
  update caddy           Update Caddy image
  update setup           Update setup script
  ssl                    Check SSL certificates
  help                   Show help

Examples:
  setup
  setup add example.com me@example.com
  setup remove example.com
  setup update caddy
  setup logs example.com 100

EOF
}

#-------------------------------------------------------------------------------
# Main Entry Point
#-------------------------------------------------------------------------------

main() {
	local command="${1:-}"

	case "$command" in
		add)
			shift
			cmd_add_site "$@"
			;;
		remove|rm|delete)
			shift
			cmd_remove_site "$@"
			;;
		list|ls)
			cmd_list_sites
			;;
		status)
			cmd_status
			;;
		logs|log)
			shift
			cmd_logs "$@"
			;;
		reload)
			cmd_reload
			;;
		restart)
			cmd_restart
			;;
		update)
			shift
			cmd_update "$@"
			;;
		ssl|certs|certificates)
			cmd_ssl_status
			;;
		help|--help|-h)
			show_help
			;;
		"")
			# No command - check if setup is complete
			if is_setup_complete; then
				show_menu
			else
				do_initial_setup
			fi
			;;
		*)
			log_error "Unknown command: $command"
			echo ""
			show_help
			exit 1
			;;
	esac
}

if [[ $EUID -ne 0 ]]; then
	log_error "This script must be run as root"
	log_info "Log in as root: ssh root@$(hostname -I 2>/dev/null | awk '{print $1}')"
	exit 1
fi

main "$@"
