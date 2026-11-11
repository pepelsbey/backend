# Backend

A multi-site static web server using Docker and Caddy.

## Project structure

`setup.sh` — unified server setup and management script.

The script is checked with [ShellCheck](https://www.shellcheck.net/) on every push: `shellcheck --severity=warning setup.sh`.

## Server structure

```
/opt/
├── config/
│   ├── Caddyfile
│   ├── Caddyfile.local
│   ├── docker-compose.yml
│   └── setup.sh
└── sites/
    └── example.com/
        ├── Caddyfile
        └── public/
```

## Deployment guide

### Step 1: Prepare your server

Create a new Ubuntu 24 server and add your SSH key during creation.

### Step 2: Run server setup

```bash
ssh root@YOUR_SERVER_IP
curl -O https://raw.githubusercontent.com/pepelsbey/backend/refs/heads/main/setup.sh
bash setup.sh
```

The script will:

- Update system packages
- Install Docker
- Configure firewall and SSH hardening (key-only auth, root via key)
- Create a deploy user (content deployment only)
- Prompt you to add your first site

### Step 3: Verify SSH access

Before closing the root session, open a new terminal and test:

```bash
ssh root@YOUR_SERVER_IP
```

### Step 4: Update DNS

Point your domain's A record to your server IP.

### Step 5: Start the server

```bash
cd /opt/config && docker compose up -d
```

## Management commands

The `setup` command is available globally as root:

```bash
setup              # Interactive menu
setup add          # Add a new site
setup remove       # Remove a site
setup list         # List all sites
setup status       # Show server status
setup logs         # View Caddy logs
setup reload       # Reload Caddy config
setup restart      # Restart Caddy container
setup update caddy     # Update Caddy image
setup update caddyfile # Update global Caddyfile
setup update setup     # Update setup script
setup upgrade          # Bring server configuration up to date
setup upgrade --check  # Show pending configuration changes
setup ssl              # Check SSL certificates
setup help             # Show help
```

`setup add` also creates a `www` redirect for domains like `example.com`. Pass `--www` or `--no-www` to choose explicitly.

## Upgrading an existing server

`setup update setup` only replaces the script. To bring the rest of the server (packages, firewall, SSH, Docker and Caddy configuration) in line with it:

```bash
setup update setup
```

```bash
setup upgrade --check
```

```bash
setup upgrade
```

`--check` lists what differs and changes nothing. `upgrade` shows the same list, asks for confirmation, and then:

- Keeps replaced Caddy files as `<file>.bak.<timestamp>` in `/opt/config/`
- Validates the new Caddy configuration first and rolls back if it fails
- Recreates the Caddy container when `docker-compose.yml` changes (a few seconds of downtime)
- Adds missing firewall rules without touching existing ones
- Reloads SSH after checking its configuration, so keep your session open until a new login works

The global Caddyfile is replaced by the upgrade. If you’ve edited it, move your changes to `Caddyfile.local` afterwards, using the backup as a reference.

## Deploying your site

The deploy user can only run rsync and only write to `/opt/sites/<domain>/public/` directories:

```bash
rsync --archive --verbose --compress --delete --delete-excluded --exclude '.DS_Store' ./dist/ deploy@example.com:/opt/sites/example.com/public/
```

Deploy keys live in `/home/deploy/.ssh/authorized_keys`. The file is owned by root, so edit it as root.

## Configuration

All configuration files are owned by root.

### Global config

`/opt/config/Caddyfile` holds the defaults for all sites (security headers, caching, compression, etc.) and is managed by the script: `setup upgrade` and `setup update caddyfile` replace it.

Put your own settings for all sites in `/opt/config/Caddyfile.local`. It’s applied after the defaults and never overwritten:

```
header X-Frame-Options "DENY"
header -Cross-Origin-Resource-Policy
```

Run `setup reload` to apply.

### Site-specific config

Edit `/opt/sites/example.com/Caddyfile` for site-specific settings (redirects, custom headers, etc.)

## License

[MIT](LICENSE.md)
