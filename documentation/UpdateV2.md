# Upgrade Guide v2.0 - New Environment Variables

## Overview

This update introduces several new optional features and configuration options for v2 mailcow-logs-viewer application. All changes are **backward compatible** - existing installations will continue to work without any modifications.

## What's New

### 1. **GeoIP Integration (MaxMind)**
Add geographic location data to your DMARC reports and log analysis.

### 2. **SMTP Email Notifications**
Configure email notifications for system alerts and DMARC processing errors.

### 3. **Admin Email**
Centralized admin contact for system notifications.

### 4. **Enhanced DMARC Features**
- Configurable retention period
- Manual report upload capability
- Automatic IMAP import for DMARC reports

---

# TL;DR

## Optional Features (all disabled by default)

Add to your `.env` file:

**MaxMind GeoIP:**
```env
MAXMIND_ACCOUNT_ID=your_id
MAXMIND_LICENSE_KEY=your_key
```

Add a mounted folder for MaxMind databases
```yaml
services:
  app:
    volumes:
      - ./data:/app/data

```

**SMTP Notifications:**
```env
SMTP_ENABLED=true
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USER=user
SMTP_PASSWORD=pass
SMTP_FROM=noreply@yourdomain.com
```

**DMARC IMAP Auto-Import:**
```env
DMARC_IMAP_ENABLED=true
DMARC_IMAP_HOST=imap.yourdomain.com
DMARC_IMAP_PORT=993
DMARC_IMAP_USE_SSL=true
DMARC_IMAP_USER=dmarc@yourdomain.com
DMARC_IMAP_PASSWORD=your_password
```

**Other optional settings:**
- `ADMIN_EMAIL=admin@yourdomain.com` 
- `DMARC_RETENTION_DAYS=60` (default: 60)
- `DMARC_MANUAL_UPLOAD_ENABLED=true` (default: true)
- `DMARC_ERROR_EMAIL=` (optional, uses ADMIN_EMAIL if not set)

**Upgrade**

```bash
docker compose pull
docker compose up -d
```

**That's it!**.

---

## Changes

### Admin Email
Add this variable to your `.env` file:

```env
ADMIN_EMAIL=admin@yourdomain.com
```

**Replace `admin@yourdomain.com` with your actual email address.** This email will receive system notifications and error alerts.

---

## Optional Features

### MaxMind GeoIP (Optional)

To enable geographic location enrichment in Email Source IP & DMARC reports:

* [ ] Sign up for a free MaxMind account at [https://www.maxmind.com/](https://www.maxmind.com/)
* [ ] Create a **License Key**
* [ ] Copy your **Account ID** and **License Key**
* [ ] Add the credentials to your `.env` file:

```env
MAXMIND_ACCOUNT_ID=your_account_id
MAXMIND_LICENSE_KEY=your_license_key

```

* [ ] **Map the data volume** in your `docker-compose.yml` to persist the database after a container restart:

```yaml
services:
  app:
    # ... other configurations
    volumes:
      - ./data:/app/data

```

> [!NOTE]
> The application will automatically download and update the GeoIP database into this folder using the credentials provided.

**If not configured:** The application works normally without GeoIP data.

---

### SMTP Email Notifications (Optional)

To enable email notifications:

```env
SMTP_ENABLED=true
SMTP_HOST=smtp.yourdomain.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=your_smtp_user
SMTP_PASSWORD=your_smtp_password
SMTP_FROM=noreply@yourdomain.com
```

**If not configured:** No email notifications will be sent (default: `SMTP_ENABLED=false`).

---

### DMARC Configuration (Optional)

#### Retention Period
Control how long DMARC reports are stored:

```env
DMARC_RETENTION_DAYS=60
```

**Default:** 60 days if not specified.

---

#### Manual Upload
Enable/disable manual DMARC report upload via the web interface:

```env
DMARC_MANUAL_UPLOAD_ENABLED=true
```

**Default:** `true` (enabled).

---

#### IMAP Auto-Import
Automatically fetch DMARC reports from an email inbox:

```env
DMARC_IMAP_ENABLED=true
DMARC_IMAP_HOST=imap.yourdomain.com
DMARC_IMAP_PORT=993
DMARC_IMAP_USE_SSL=true
DMARC_IMAP_USER=dmarc@yourdomain.com
DMARC_IMAP_PASSWORD=your_password
DMARC_IMAP_FOLDER=INBOX
DMARC_IMAP_DELETE_AFTER=true
DMARC_IMAP_INTERVAL=3600
DMARC_IMAP_RUN_ON_STARTUP=true
```

**Configuration options:**
- `DMARC_IMAP_DELETE_AFTER`: Delete emails after processing (default: `true`)
- `DMARC_IMAP_INTERVAL`: Check interval in seconds (default: 3600 = 1 hour)
- `DMARC_IMAP_RUN_ON_STARTUP`: Process existing emails on startup (default: `true`)

**If not configured:** IMAP auto-import remains disabled (default: `DMARC_IMAP_ENABLED=false`).

---

#### DMARC Error Notifications
Override the admin email specifically for DMARC processing errors:

```env
DMARC_ERROR_EMAIL=dmarc-alerts@yourdomain.com
```

**If not configured:** Uses `ADMIN_EMAIL` by default.

---

## Upgrade Steps

1. **Update your `.env` file:**
   - Add `ADMIN_EMAIL=your@email.com`
   - Add any optional features you want to enable

2. **Pull the latest image:**
   ```bash
   docker compose pull
   ```

3. **Start the container:**
   ```bash
   docker compose up -d
   ```

**That's it!** The application will automatically:
- Run database migrations
- Initialize new features
- Apply your configuration

---

## Full v2 Configuration Example

Complete example with all features enabled:

```env
# Required
ADMIN_EMAIL=admin@yourdomain.com

# MaxMind GeoIP
MAXMIND_ACCOUNT_ID=123456
MAXMIND_LICENSE_KEY=your_license_key_here

# SMTP Notifications
SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USER=notifications@yourdomain.com
SMTP_PASSWORD=your_app_password
SMTP_FROM=noreply@yourdomain.com

# DMARC Settings
DMARC_RETENTION_DAYS=90
DMARC_MANUAL_UPLOAD_ENABLED=true

# DMARC IMAP Auto-Import
DMARC_IMAP_ENABLED=true
DMARC_IMAP_HOST=imap.gmail.com
DMARC_IMAP_PORT=993
DMARC_IMAP_USE_SSL=true
DMARC_IMAP_USER=dmarc-reports@yourdomain.com
DMARC_IMAP_PASSWORD=your_app_password
DMARC_IMAP_FOLDER=INBOX
DMARC_IMAP_DELETE_AFTER=true
DMARC_IMAP_INTERVAL=3600
DMARC_IMAP_RUN_ON_STARTUP=true

# Optional: Separate email for DMARC errors
DMARC_ERROR_EMAIL=dmarc-admin@yourdomain.com
```

---

## Troubleshooting

**Container won't start after update:**
- Verify `ADMIN_EMAIL` is set
- Check Docker logs: `docker compose logs -f`

**IMAP not working:**
- Verify credentials and connection settings
- Check firewall allows outbound connections to IMAP server
- For Gmail: use App Passwords, not your regular password

**No email notifications:**
- Ensure `SMTP_ENABLED=true`
- Verify SMTP credentials and server settings
- Check Docker logs for SMTP errors

---

## Need Help?

If you encounter any issues during the upgrade, please open an issue on GitHub with:
- Your Docker logs
- Your `.env` configuration (remove sensitive data)
- Description of the problem