# Mailcow Logs Viewer - Quick Start Guide

Get up and running in 5 minutes! 🚀

## Prerequisites

- Docker & Docker Compose installed
- Mailcow instance with API access
- Mailcow API key (generate from Mailcow admin panel)

## Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/mailcow-logs-viewer.git
cd mailcow-logs-viewer
```

## Step 2: Configure Environment

```bash
# Copy the example configuration
cp env.example .env

# Edit the configuration file
nano .env  # or use your favorite editor
```

### Minimum Required Configuration

```bash
# Your Mailcow instance URL (without trailing slash)
MAILCOW_URL=https://mail.example.com

# Your Mailcow API key (from System → API in Mailcow)
MAILCOW_API_KEY=your-api-key-here

# Your local email domains (comma-separated)
MAILCOW_LOCAL_DOMAINS=example.com,domain.net

# Database password (change this!)
POSTGRES_PASSWORD=your-secure-password-here
```

### Getting Your Mailcow API Key

1. Log in to your Mailcow admin panel
2. Navigate to **System** → **API**
3. Click **Add API Key**
4. Give it a name (e.g., "Logs Viewer")
5. Enable read access for logs
6. Copy the generated API key

## Step 3: Start the Application

```bash
docker-compose up -d
```

This will:
- Pull required Docker images
- Start PostgreSQL database
- Start the application
- Initialize the database schema
- Begin fetching logs

## Step 4: Access the Dashboard

Open your browser and navigate to:

```
http://localhost:8080
```

You should see the dashboard with your mail statistics!

## Step 5: Verify Everything Works

### Check Application Health

```bash
curl http://localhost:8080/api/health
```

You should see:
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "1.0.0"
}
```

### Check Logs

```bash
# View application logs
docker-compose logs -f app

# View database logs
docker-compose logs -f db
```

### Check if Data is Being Fetched

Wait 1-2 minutes for the first fetch cycle, then check:
```bash
curl http://localhost:8080/api/stats/dashboard
```

You should see message counts and statistics.

## Common Issues & Solutions

### Issue: "Cannot connect to Mailcow API"

**Solution:**
- Verify `MAILCOW_URL` is correct
- Check API key is valid
- Ensure Mailcow is accessible from the container
- Check firewall rules

```bash
# Test API connectivity
docker-compose exec app curl -H "X-API-Key: YOUR_API_KEY" https://mail.example.com/api/v1/get/logs/postfix/1
```

### Issue: "Database connection failed"

**Solution:**
- Wait 30 seconds for PostgreSQL to fully start
- Check database password in `.env`
- Restart services:

```bash
docker-compose restart
```

### Issue: "No logs appearing"

**Solution:**
- Wait for first fetch cycle (check `FETCH_INTERVAL` in `.env`)
- Check application logs:

```bash
docker-compose logs app | grep "Stored.*logs"
```

- Verify Mailcow has logs to fetch

### Issue: Port 8080 already in use

**Solution:**
Change the port in `.env`:
```bash
APP_PORT=8081
```

Then restart:
```bash
docker-compose down
docker-compose up -d
```

## Next Steps

### Configure Traefik (Optional)

If you use Traefik, uncomment the labels in `docker-compose.yml`:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.mailcow-logs.rule=Host(`logs.example.com`)"
  # ... etc
```

### Adjust Fetch Settings

Edit `.env` to customize:

```bash
# Fetch every 30 seconds for high-volume servers
FETCH_INTERVAL=30

# Fetch more logs per request
FETCH_COUNT=1000

# Keep logs for 30 days
RETENTION_DAYS=30
```

Then restart:
```bash
docker-compose restart app
```

### Enable Debug Mode (Development Only)

```bash
DEBUG=true
LOG_LEVEL=DEBUG
```

⚠️ **Never use in production!**

## Updating the Application

```bash
# Pull latest changes
git pull

# Rebuild containers
docker-compose down
docker-compose up -d --build
```

## Backup & Restore

### Backup Database

```bash
docker-compose exec db pg_dump -U mailcowlogs mailcowlogs > backup_$(date +%Y%m%d).sql
```

### Restore Database

```bash
cat backup_20241217.sql | docker-compose exec -T db psql -U mailcowlogs mailcowlogs
```

## Monitoring

### Check Disk Usage

```bash
# Check database size
docker-compose exec db psql -U mailcowlogs -c "SELECT pg_size_pretty(pg_database_size('mailcowlogs'));"

# Check container sizes
docker system df
```

### View Statistics

```bash
# Dashboard stats
curl http://localhost:8080/api/stats/dashboard | jq

# Recent activity
curl http://localhost:8080/api/stats/recent-activity | jq
```

## Stopping the Application

```bash
# Stop containers (keeps data)
docker-compose stop

# Stop and remove containers (keeps data)
docker-compose down

# Remove everything including data (⚠️ destructive)
docker-compose down -v
```

## Getting Help

1. Check the logs: `docker-compose logs app`
2. Read the full [README.md](README.md)
3. Check [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) for architecture details
4. Open an issue on GitHub

## Performance Tuning

For high-volume mail servers:

```bash
# Increase database connections
# Add to docker-compose.yml under db service:
command: postgres -c max_connections=200

# Increase fetch frequency
FETCH_INTERVAL=30
FETCH_COUNT=1000

# Increase scheduler workers
SCHEDULER_WORKERS=8
```

## Security Checklist

- [ ] Changed default PostgreSQL password
- [ ] Using strong API key
- [ ] Firewall rules configured
- [ ] Not exposing port directly (use Traefik/nginx)
- [ ] Regular backups enabled
- [ ] Logs reviewed for errors

## Default Ports

- **Application**: 8080 (configurable)
- **PostgreSQL**: 5432 (internal only)

---

That's it! You should now have a fully functional Mailcow logs viewer. 🎉

For more advanced configuration and features, see the [README.md](README.md).