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
#   setup update caddyfile # Update global Caddyfile
#   setup update setup     # Update this script
#   setup upgrade          # Bring server configuration up to date
#   setup upgrade --check  # Show pending configuration changes
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
#     /Caddyfile           - Global configuration (managed by this script)
#     /Caddyfile.local     - Local additions for all sites (never overwritten)
#   /opt/sites/<domain>    - Per-site directories
#     /Caddyfile           - Site-specific configuration
#     /public              - Site's public content (owned by deploy)
#===============================================================================

set -euo pipefail

# Cleanup temporary files on exit
WORK_DIR="$(mktemp -d)"
cleanup() {
	rm -rf "$WORK_DIR" 2>/dev/null || true
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
VERSION_FILE="$CONFIG_DIR/.setup_version"
CADDY_IMAGE="caddy:2-alpine"
DEPLOY_USER="deploy"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_URL="https://raw.githubusercontent.com/pepelsbey/backend/refs/heads/main/setup.sh"

# Version of the server configuration this script produces. Bump it whenever
# a change needs 'setup upgrade' to reach existing servers. Servers set up
# before versioning have no version file and count as version 0.
SCHEMA_VERSION=1

# Run state
CHECK_ONLY=0     # 1 = report differences without changing anything
FRESH_INSTALL=0  # 1 = initial setup of a new server
DRIFT_COUNT=0
STAMP="$(date +%Y%m%d-%H%M%S)"

#-------------------------------------------------------------------------------
# Embedded Configuration Files
#-------------------------------------------------------------------------------

generate_docker_compose() {
	cat << DOCKER_COMPOSE_EOF
services:
  caddy:
    image: ${CADDY_IMAGE}
    container_name: caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ${CONFIG_DIR}:/etc/caddy:ro
      - /opt/sites:/opt/sites:ro
      - /var/log/caddy:/var/log/caddy
      - caddy_data:/data
      - caddy_config:/config
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://localhost:2019/config/ > /dev/null 2>&1"]
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
# Managed by setup.sh: this file is replaced by 'setup upgrade' and
# 'setup update caddyfile'. Put your own changes in Caddyfile.local.

# Common configuration snippet for all sites
(common) {
	file_server {
		hide .*
		index index.html index.xml
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

	# Local additions for all sites
	import /etc/caddy/Caddyfile.local
}

# Import all site configurations
import /opt/sites/*/Caddyfile
CADDYFILE_EOF
}

generate_caddyfile_local() {
	cat << 'CADDYFILE_LOCAL_EOF'
# Local additions to the common configuration. Directives in this file apply
# to every site, after the defaults from /opt/config/Caddyfile, and are never
# overwritten by 'setup upgrade' or 'setup update caddyfile'.
#
# Examples:
#
# header X-Frame-Options "DENY"
# header -Cross-Origin-Resource-Policy
CADDYFILE_LOCAL_EOF
}

generate_site_caddyfile() {
	local domain="$1"
	local email="$2"
	local www="${3:-yes}"
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
SITE_CADDYFILE_EOF

	if [[ "$www" == "yes" ]]; then
		cat << SITE_WWW_EOF

www.$domain {
	tls $email
	redir https://$domain{uri} permanent
}
SITE_WWW_EOF
	fi
}

generate_deploy_shell() {
	cat << 'DEPLOY_SHELL_EOF'
#!/bin/bash
set -euo pipefail

# Restricted shell for the deploy user.
# Only allows rsync in server mode; interactive login is denied.
# File-system permissions ensure writes only reach public/ directories.

if [[ -z "${SSH_ORIGINAL_COMMAND:-}" ]]; then
	echo "Interactive login is disabled for this account."
	echo "Use rsync to deploy content to /opt/sites/<domain>/public/"
	exit 1
fi

if [[ "$SSH_ORIGINAL_COMMAND" == rsync\ --server* ]]; then
	exec $SSH_ORIGINAL_COMMAND
fi

echo "Only rsync is permitted for this account."
exit 1
DEPLOY_SHELL_EOF
}

generate_sshd_config() {
	cat << 'SSHD_CONFIG_EOF'
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

# Restrict deploy user to rsync only via forced command
Match User deploy
	ForceCommand /usr/local/bin/deploy-shell
	AllowTcpForwarding no
	PermitTunnel no
	AllowAgentForwarding no
SSHD_CONFIG_EOF
}

generate_auto_upgrades() {
	cat << 'AUTO_UPGRADES_EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTO_UPGRADES_EOF
}

generate_unattended_upgrades() {
	cat << 'UNATTENDED_UPGRADES_EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
UNATTENDED_UPGRADES_EOF
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

# Containers created by earlier versions mount the global Caddyfile as a single
# file, which pins the file's inode: a replaced file is invisible to Caddy
# until the container is recreated.
caddy_legacy_mount() {
	docker inspect caddy --format '{{range .Mounts}}{{println .Destination}}{{end}}' 2>/dev/null \
		| grep -qx '/etc/caddy/Caddyfile'
}

# Validate the configuration files on disk in a throwaway container, so the
# result doesn't depend on what the running container has mounted.
caddy_validate() {
	local output
	if output="$(docker run --rm \
		-v "$CONFIG_DIR:/etc/caddy:ro" \
		-v "$SITES_DIR:/opt/sites:ro" \
		-v /var/log/caddy:/var/log/caddy \
		"$CADDY_IMAGE" caddy validate --config /etc/caddy/Caddyfile 2>&1)"; then
		return 0
	fi
	echo "$output" >&2
	return 1
}

caddy_reload() {
	local output
	if caddy_legacy_mount; then
		log_warning "This container predates the current setup. Run '$SCRIPT_NAME upgrade' to bring it up to date."
	fi
	if output="$(docker exec caddy caddy reload --config /etc/caddy/Caddyfile 2>&1)"; then
		return 0
	fi
	echo "$output" >&2
	return 1
}

installed_version() {
	if [[ -f "$VERSION_FILE" ]]; then
		cat "$VERSION_FILE"
	else
		echo 0
	fi
}

write_version() {
	echo "$SCHEMA_VERSION" > "$VERSION_FILE"
}

upgrade_pending() {
	is_setup_complete && [[ "$(installed_version)" -lt "$SCHEMA_VERSION" ]]
}

# Report a difference between the server and what this script would set up
drift() {
	DRIFT_COUNT=$((DRIFT_COUNT + 1))
	echo -e "  ${YELLOW}•${NC} $1"
}

# Bring a generated file in line with its template.
#   sync_file <path> <mode> <generator> [backup]
# Returns 0 if the file was changed (or would be, in check mode) and 1 if it
# was already current, so always call it from an 'if' or with '|| true'.
# With 'backup', the previous file is kept as <path>.bak.<timestamp>.
sync_file() {
	local path="$1"
	local mode="$2"
	local generator="$3"
	local backup="${4:-}"
	local tmp="$WORK_DIR/sync_file.tmp"

	"$generator" > "$tmp"

	if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then
		return 1
	fi

	if (( CHECK_ONLY )); then
		if [[ -f "$path" ]]; then
			drift "$path differs from the current template:"
			diff -u --label current --label new "$path" "$tmp" | sed 's/^/      /' || true
		else
			drift "$path is missing"
		fi
		return 0
	fi

	if [[ -f "$path" && -n "$backup" ]]; then
		cp -p "$path" "$path.bak.$STAMP"
		log_info "Previous version saved as $path.bak.$STAMP"
	fi

	cat "$tmp" > "$path"
	chmod "$mode" "$path"
	chown root:root "$path"
	log_success "Updated $path"
	return 0
}

#-------------------------------------------------------------------------------
# Site Management Functions
#-------------------------------------------------------------------------------

cmd_add_site() {
	if [[ ! -d "$SITES_DIR" ]]; then
		log_error "Sites directory does not exist. Run this script without arguments first to set up the server."
		exit 1
	fi

	local domain=""
	local email=""
	local www=""
	local arg

	for arg in "$@"; do
		case "$arg" in
			--www) www="yes" ;;
			--no-www) www="no" ;;
			*)
				if [[ -z "$domain" ]]; then
					domain="$arg"
				elif [[ -z "$email" ]]; then
					email="$arg"
				fi
				;;
		esac
	done

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

	# The www redirect needs its own DNS record and certificate, so it's only
	# the default for domains that look like an apex (example.com)
	if [[ -z "$www" ]]; then
		local www_default="no"
		if [[ "$domain" =~ ^[^.]+\.[^.]+$ ]]; then
			www_default="yes"
		fi

		www="$www_default"
		if [[ -t 0 ]]; then
			local answer=""
			read -rp "Also redirect www.$domain to $domain? (y/n) [$www_default]: " answer || true
			case "$answer" in
				[Yy]*) www="yes" ;;
				[Nn]*) www="no" ;;
			esac
		fi
	fi

	log_info "Creating site structure for: $domain"

	# Create directories
	mkdir -p "$site_dir/public"

	# Create site-specific Caddyfile
	generate_site_caddyfile "$domain" "$email" "$www" > "$site_dir/Caddyfile"

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
		echo "  3. Reload Caddy: $SCRIPT_NAME reload"
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

	# The domain becomes part of a path passed to rm -rf
	if ! validate_domain "$domain"; then
		log_error "Invalid domain name format: $domain"
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
		if ! caddy_validate; then
			log_warning "Caddyfile validation failed — skipping reload"
		elif ! caddy_reload; then
			log_warning "Reload failed — Caddy is still running the previous configuration"
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
		if upgrade_pending; then
			echo "  ! Configuration version $(installed_version), current is $SCHEMA_VERSION — run: $SCRIPT_NAME upgrade"
		else
			echo "  ✓ Configuration version $(installed_version)"
		fi
	else
		echo "  ✗ Server not yet set up"
	fi
	echo ""

	echo "Caddy Container:"
	if caddy_running; then
		echo "  ✓ Running"
		docker ps --filter 'name=^caddy$' --format "  Image: {{.Image}}\n  Uptime: {{.Status}}" 2>/dev/null
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
	if command -v ufw &>/dev/null && ufw status | grep -q "^Status: active"; then
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
		if ! caddy_validate; then
			log_error "Caddyfile validation failed — not reloading"
			return 1
		fi
		if caddy_reload; then
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
		log_error "Specify what to update: caddy, caddyfile, or setup"
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
			docker ps --filter 'name=^caddy$' --format "Image: {{.Image}}"
			;;
		caddyfile)
			if caddy_running && caddy_legacy_mount; then
				log_error "This container predates the current setup. Run '$SCRIPT_NAME upgrade' instead."
				return 1
			fi

			log_info "Updating global Caddyfile from template..."
			ensure_caddy_config caddyfile
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
				log_info "Run '$SCRIPT_NAME upgrade --check' to see if the server configuration needs updating"
			else
				log_error "Failed to download setup script"
				rm -f "$CONFIG_DIR/setup.sh.new"
				return 1
			fi
			;;
		*)
			log_error "Unknown update target: $target (use 'caddy', 'caddyfile', or 'setup')"
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
# Setup Steps
#-------------------------------------------------------------------------------
# Each step compares the server with what this script sets up and fixes only
# the differences, so the same steps serve both the initial setup and upgrades
# of servers set up by any earlier version. With CHECK_ONLY=1 a step reports
# what it would change and touches nothing.

ensure_packages() {
	local packages=(
		apt-transport-https
		bash-completion
		ca-certificates
		curl
		gnupg
		lsb-release
		rsync
		ufw
		unattended-upgrades
		vnstat
		apt-listchanges
	)
	local missing=()
	local package

	for package in "${packages[@]}"; do
		if [[ "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)" != "installed" ]]; then
			missing+=("$package")
		fi
	done

	if [[ ${#missing[@]} -eq 0 ]]; then
		return 0
	fi

	if (( CHECK_ONLY )); then
		drift "Packages not installed: ${missing[*]}"
		return 0
	fi

	log_info "Installing packages: ${missing[*]}"
	apt-get update
	DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

ensure_docker() {
	if command -v docker &> /dev/null; then
		return 0
	fi

	if (( CHECK_ONLY )); then
		drift "Docker is not installed"
		return 0
	fi

	log_info "Installing Docker..."

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

	log_success "Docker installed: $(docker --version)"
}

ensure_firewall() {
	local rules=("22/tcp:SSH" "80/tcp:HTTP" "443/tcp:HTTPS" "443/udp:HTTP/3")
	local rule port comment

	# A new server starts from a clean rule set. An existing one may have rules
	# of its own, so there only what's missing is added.
	if (( FRESH_INSTALL )); then
		log_info "Configuring firewall..."

		ufw --force reset
		ufw default deny incoming
		ufw default allow outgoing

		for rule in "${rules[@]}"; do
			ufw allow "${rule%%:*}" comment "${rule#*:}"
		done

		ufw --force enable

		log_success "Firewall configured"
		ufw status
		return 0
	fi

	local status=""
	if command -v ufw &> /dev/null; then
		status="$(ufw status 2>/dev/null || true)"
	fi

	for rule in "${rules[@]}"; do
		port="${rule%%:*}"
		comment="${rule#*:}"

		if grep -qE "^${port}[[:space:]]+ALLOW" <<< "$status"; then
			continue
		fi

		if (( CHECK_ONLY )); then
			drift "Firewall rule missing: allow $port ($comment)"
		else
			ufw allow "$port" comment "$comment"
		fi
	done

	if ! grep -q "^Status: active" <<< "$status"; then
		if (( CHECK_ONLY )); then
			drift "Firewall is not active (it will be enabled, denying other incoming traffic)"
		else
			ufw default deny incoming
			ufw default allow outgoing
			ufw --force enable
			log_success "Firewall enabled"
		fi
	fi
}

ensure_deploy_user() {
	if ! id "$DEPLOY_USER" &> /dev/null; then
		if (( CHECK_ONLY )); then
			drift "Deploy user '$DEPLOY_USER' does not exist"
		else
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
		fi
	fi

	# Restricted shell for deploy user (rsync-only). Installed before the SSH
	# configuration that forces it, so deploys keep working in between.
	sync_file /usr/local/bin/deploy-shell 755 generate_deploy_shell || true
}

ensure_ssh() {
	local conf="/etc/ssh/sshd_config.d/99-hardened.conf"
	local previous="$WORK_DIR/sshd-previous.conf"

	rm -f "$previous"
	if [[ -f "$conf" ]]; then
		cp -p "$conf" "$previous"
	fi

	if ! sync_file "$conf" 644 generate_sshd_config; then
		return 0
	fi

	if (( CHECK_ONLY )); then
		return 0
	fi

	mkdir -p /run/sshd

	if sshd -t; then
		systemctl reload ssh 2>/dev/null || systemctl restart ssh
		log_success "SSH hardened successfully"
	else
		log_error "SSH configuration error, reverting..."
		if [[ -f "$previous" ]]; then
			cat "$previous" > "$conf"
		else
			rm -f "$conf"
		fi
		exit 1
	fi
}

ensure_auto_updates() {
	sync_file /etc/apt/apt.conf.d/20auto-upgrades 644 generate_auto_upgrades || true
	sync_file /etc/apt/apt.conf.d/50unattended-upgrades 644 generate_unattended_upgrades || true

	if ! systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
		if (( CHECK_ONLY )); then
			drift "Automatic security updates are not enabled"
		else
			systemctl enable unattended-upgrades
			log_success "Automatic updates enabled"
		fi
	fi
}

ensure_shell() {
	# Up/Down arrows search history by the typed prefix (both normal and
	# application cursor key modes)
	if grep -q "# setup.sh: history prefix search" /etc/inputrc 2>/dev/null; then
		return 0
	fi

	if (( CHECK_ONLY )); then
		drift "Shell history prefix search is not configured in /etc/inputrc"
		return 0
	fi

	cat >> /etc/inputrc << 'EOF'

# setup.sh: history prefix search
"\e[A": history-search-backward
"\e[B": history-search-forward
"\eOA": history-search-backward
"\eOB": history-search-forward
EOF

	log_success "Shell history search configured"
}

ensure_directories() {
	local dir

	# Not recursive: public/ directories inside sites belong to the deploy user
	for dir in "$CONFIG_DIR" "$SITES_DIR" /var/log/caddy; do
		if [[ -d "$dir" ]]; then
			continue
		fi

		if (( CHECK_ONLY )); then
			drift "$dir is missing"
		else
			mkdir -p "$dir"
			chown root:root "$dir"
			log_success "Created $dir"
		fi
	done

	# Global 'setup' command (root only)
	if [[ "$(readlink /usr/local/bin/setup 2>/dev/null || true)" != "$CONFIG_DIR/setup.sh" ]]; then
		if (( CHECK_ONLY )); then
			drift "/usr/local/bin/setup does not point to $CONFIG_DIR/setup.sh"
		else
			ln -sf "$CONFIG_DIR/setup.sh" /usr/local/bin/setup
		fi
	fi
}

# Bring the Caddy configuration in line with the templates and apply it.
#   ensure_caddy_config [all|caddyfile]
# 'caddyfile' leaves docker-compose.yml alone. New files are validated before
# Caddy sees them and rolled back if they don't pass.
ensure_caddy_config() {
	local scope="${1:-all}"
	local compose="$CONFIG_DIR/docker-compose.yml"
	local caddyfile="$CONFIG_DIR/Caddyfile"
	local caddyfile_local="$CONFIG_DIR/Caddyfile.local"
	local compose_changed=0
	local caddyfile_changed=0
	local file

	# Created once, then left to the user
	if [[ ! -f "$caddyfile_local" ]]; then
		if (( CHECK_ONLY )); then
			drift "$caddyfile_local is missing"
		else
			generate_caddyfile_local > "$caddyfile_local"
			chmod 644 "$caddyfile_local"
			chown root:root "$caddyfile_local"
			log_success "Created $caddyfile_local"
		fi
	fi

	if [[ "$scope" == "all" ]] && sync_file "$compose" 644 generate_docker_compose backup; then
		compose_changed=1
	fi

	if sync_file "$caddyfile" 644 generate_caddyfile backup; then
		caddyfile_changed=1
	fi

	if (( CHECK_ONLY )); then
		return 0
	fi

	if (( ! compose_changed && ! caddyfile_changed )); then
		if [[ "$scope" == "caddyfile" ]]; then
			log_info "Global Caddyfile is already up to date"
		fi
		return 0
	fi

	# Nothing to validate against or apply to on a server that's still being set up
	if ! is_setup_complete; then
		return 0
	fi

	if ! caddy_validate; then
		for file in "$compose" "$caddyfile"; do
			if [[ -f "$file.bak.$STAMP" ]]; then
				cat "$file.bak.$STAMP" > "$file"
			fi
		done
		log_error "New Caddy configuration failed validation — rolled back to the previous files"
		return 1
	fi

	if ! caddy_running; then
		log_info "Caddy is not running — start it to apply: $SCRIPT_NAME restart"
		return 0
	fi

	# Changes to docker-compose.yml only take effect in a new container, and a
	# container with the old single-file mount can't see the new Caddyfile
	if (( compose_changed )) || caddy_legacy_mount; then
		log_info "Recreating Caddy container..."
		(cd "$CONFIG_DIR" && docker compose up -d)
		log_success "Caddy container recreated"
	elif caddy_reload; then
		log_success "Caddy configuration reloaded"
	else
		log_error "Reload failed — Caddy is still running the previous configuration"
		return 1
	fi
}

run_setup_steps() {
	ensure_packages
	ensure_docker
	ensure_firewall
	ensure_deploy_user
	ensure_ssh
	ensure_auto_updates
	ensure_shell
	ensure_directories
	ensure_caddy_config
}

#-------------------------------------------------------------------------------
# Upgrade
#-------------------------------------------------------------------------------

cmd_upgrade() {
	local check_only=0
	local assume_yes=0
	local arg

	for arg in "$@"; do
		case "$arg" in
			--check) check_only=1 ;;
			--yes|-y) assume_yes=1 ;;
			*)
				log_error "Unknown option: $arg (use '--check' or '--yes')"
				return 1
				;;
		esac
	done

	if ! is_setup_complete; then
		log_error "Server has not been set up yet"
		return 1
	fi

	check_ubuntu

	log_header "Checking Server Configuration"

	DRIFT_COUNT=0
	CHECK_ONLY=1
	run_setup_steps
	CHECK_ONLY=0

	if (( DRIFT_COUNT == 0 )); then
		if (( ! check_only )); then
			write_version
		fi
		log_success "Server configuration is up to date"
		return 0
	fi

	echo ""

	if (( check_only )); then
		log_info "$DRIFT_COUNT change(s) pending. Apply with: $SCRIPT_NAME upgrade"
		return 0
	fi

	log_warning "Applying $DRIFT_COUNT change(s):"
	echo "  - Replaced Caddy files are kept as <file>.bak.$STAMP"
	echo "  - Your changes to the global Caddyfile belong in $CONFIG_DIR/Caddyfile.local"
	echo "  - Caddy is recreated if docker-compose.yml changes (a few seconds of downtime)"
	echo "  - If SSH changes, keep this session open until a new login works"
	echo ""

	if (( ! assume_yes )); then
		local confirm=""
		read -rp "Continue? (y/n): " confirm || true

		if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
			log_info "Cancelled."
			return 0
		fi
	fi

	log_header "Upgrading Server Configuration"

	run_setup_steps
	write_version

	log_success "Server configuration upgraded to version $SCHEMA_VERSION"
}

#-------------------------------------------------------------------------------
# Initial Server Setup
#-------------------------------------------------------------------------------

do_initial_setup() {
	check_ubuntu

	log_header "Starting Initial Server Setup"

	log_info "Updating system packages..."
	apt-get update
	DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
	DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y

	FRESH_INSTALL=1
	CHECK_ONLY=0
	run_setup_steps

	# Copy this script to config dir (all config owned by root)
	if [[ "$(readlink -f "$0")" != "$CONFIG_DIR/setup.sh" ]]; then
		cp "$0" "$CONFIG_DIR/setup.sh"
	fi
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
	write_version

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
	echo "    ├── Caddyfile.local"
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
	echo "  2. Point your domain's A record to this server IP"
	echo ""
	echo "  3. Start the web server:"
	echo "     cd $CONFIG_DIR && docker compose up -d"
	echo ""
	echo "  4. Management commands (as root):"
	echo "     setup add       # Add a new site"
	echo "     setup list      # List all sites"
	echo "     setup status    # Show server status"
	echo "     setup logs      # View Caddy logs"
	echo "     setup restart   # Restart Caddy"
	echo ""
	echo "  5. Deploy content (from local machine):"
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
		if upgrade_pending; then
			log_warning "Server configuration is outdated — choose 11 to upgrade"
		fi
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
		echo "  9) Update global Caddyfile"
		echo " 10) Update setup script"
		echo " 11) Upgrade server configuration"
		echo "  s) Check SSL certificates"
		echo "  0) Exit"
		echo ""
		read -rp "Choose an option: " choice || true

		case "$choice" in
			# A failed command returns to the menu instead of ending the script
			1) cmd_add_site || true ;;
			2) cmd_remove_site || true ;;
			3) cmd_list_sites || true ;;
			4) cmd_status || true ;;
			5) cmd_logs || true ;;
			6) cmd_reload || true ;;
			7) cmd_restart || true ;;
			8) cmd_update caddy || true ;;
			9) cmd_update caddyfile || true ;;
			10) cmd_update setup || true ;;
			11) cmd_upgrade || true ;;
			s|S) cmd_ssl_status || true ;;
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
  add [domain] [email]   Add a new site (--www or --no-www to skip the prompt)
  remove [domain]        Remove a site
  list                   List all sites
  status                 Show server status
  logs [domain] [n]      View Caddy logs
  reload                 Reload Caddy config
  restart                Restart Caddy container
  update caddy           Update Caddy image
  update caddyfile       Update global Caddyfile
  update setup           Update setup script
  upgrade [--check]      Bring server configuration up to date
  ssl                    Check SSL certificates
  help                   Show help

Examples:
  setup
  setup add example.com me@example.com
  setup remove example.com
  setup add blog.example.com me@example.com --no-www
  setup update caddy
  setup upgrade --check
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
		upgrade)
			shift
			cmd_upgrade "$@"
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
