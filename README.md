# Backend

A multi-site static web server using Docker and Caddy.

## Project structure

`setup.sh` — unified server setup and management script.

## Server structure

```
/opt/
├── config/
│   ├── Caddyfile
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

### Step 2: Upload setup script

```bash
ssh root@YOUR_SERVER_IP "curl -O https://raw.githubusercontent.com/pepelsbey/backend/refs/heads/main/setup.sh"
```

### Step 3: Run server setup

```bash
ssh root@YOUR_SERVER_IP
bash setup.sh
```

The script will:

- Update system packages
- Install Docker
- Configure firewall and SSH hardening (key-only auth, root via key)
- Create a deploy user (content deployment only)
- Prompt you to add your first site

### Step 4: Verify SSH access

Before closing the root session, open a new terminal and test:

```bash
ssh root@YOUR_SERVER_IP
```

### Step 5: Start the server

```bash
cd /opt/config && docker compose up -d
```

### Step 6: Update DNS

Point your domain's A record to your server IP.

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
setup update caddy # Update Caddy image
setup update setup # Update setup script
setup ssl          # Check SSL certificates
setup help         # Show help
```

## Deploying your site

The deploy user can only write to `/opt/sites/<domain>/public/` directories:

```bash
rsync --archive --verbose --compress --delete --delete-excluded --exclude '.DS_Store' ./dist/ deploy@example.com:/opt/sites/example.com/public/
```

## Configuration

All configuration files are owned by root.

### Global config

Edit `/opt/config/Caddyfile` to change settings that apply to all sites (security headers, caching, compression, etc.)

### Site-specific config

Edit `/opt/sites/example.com/Caddyfile` for site-specific settings (redirects, custom headers, etc.)

## License

[MIT](LICENSE.md)
