# Mailcow Logs Viewer - API Documentation

This document describes all available API endpoints for the Mailcow Logs Viewer application.

**Base URL:** `http://your-server:8080/api`

**Authentication:** When `AUTH_ENABLED=true`, all API endpoints (except `/api/health`) require HTTP Basic Authentication. Include the `Authorization: Basic <base64(username:password)>` header in all requests.

---

## Table of Contents

1. [Authentication](#authentication)
2. [Health & Info](#health--info)
3. [Job Status Tracking](#job-status-tracking)
4. [Domains](#domains)
5. [Messages (Unified View)](#messages-unified-view)
6. [Logs](#logs)
   - [Postfix Logs](#postfix-logs)
   - [Rspamd Logs](#rspamd-logs)
   - [Netfilter Logs](#netfilter-logs)
7. [Queue & Quarantine](#queue--quarantine)
8. [Statistics](#statistics)
9. [Status](#status)
10. [Settings](#settings)
11. [Export](#export)

---

## Authentication

### Overview

When authentication is enabled (`AUTH_ENABLED=true`), all API endpoints except `/api/health` require HTTP Basic Authentication.

**Public Endpoints (No Authentication Required):**
- `GET /api/health` - Health check (for Docker monitoring)
- `GET /login` - Login page (HTML)

**Protected Endpoints (Authentication Required):**
- All other `/api/*` endpoints

### Authentication Method

Use HTTP Basic Authentication with the credentials configured in your environment:
- Username: `AUTH_USERNAME` (default: `admin`)
- Password: `AUTH_PASSWORD`

**Example Request:**
```bash
curl -u username:password http://your-server:8080/api/info
```

Or with explicit header:
```bash
curl -H "Authorization: Basic $(echo -n 'username:password' | base64)" \
  http://your-server:8080/api/info
```

### Login Endpoint

#### GET /login

Serves the login page (HTML). This endpoint is always publicly accessible.

**Response:** HTML page with login form

**Note:** When authentication is disabled, accessing this endpoint will automatically redirect to the main application.

---

## Health & Info

### GET /health

Health check endpoint for monitoring and load balancers.

**Authentication:** Not required (public endpoint for Docker health checks)

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "1.4.9",
  "config": {
    "fetch_interval": 60,
    "retention_days": 7,
    "mailcow_url": "https://mail.example.com",
    "blacklist_enabled": true,
    "auth_enabled": false
  }
}
```

---

### GET /info

Application information and configuration.

**Response:**
```json
{
  "name": "Mailcow Logs Viewer",
  "version": "1.4.9",
  "mailcow_url": "https://mail.example.com",
  "local_domains": ["example.com", "mail.example.com"],
  "fetch_interval": 60,
  "retention_days": 7,
  "timezone": "UTC",
  "app_title": "Mailcow Logs Viewer",
  "app_logo_url": "",
  "blacklist_count": 3,
  "auth_enabled": false
}
```

---

## Job Status Tracking

### Overview

The application includes a real-time job status tracking system that monitors all background jobs. Each job reports its execution status, timestamp, and any errors that occurred.

### Job Status Data Structure

```python
job_status = {
    'fetch_logs': {'last_run': datetime, 'status': str, 'error': str|None},
    'complete_correlations': {'last_run': datetime, 'status': str, 'error': str|None},
    'update_final_status': {'last_run': datetime, 'status': str, 'error': str|None},
    'expire_correlations': {'last_run': datetime, 'status': str, 'error': str|None},
    'cleanup_logs': {'last_run': datetime, 'status': str, 'error': str|None},
    'check_app_version': {'last_run': datetime, 'status': str, 'error': str|None},
    'dns_check': {'last_run': datetime, 'status': str, 'error': str|None}
}
```

### Status Values

| Status | Description | Badge Color |
|--------|-------------|-------------|
| `running` | Job is currently executing | Blue (bg-blue-500) |
| `success` | Job completed successfully | Green (bg-green-600) |
| `failed` | Job encountered an error | Red (bg-red-600) |
| `idle` | Job hasn't run yet | Gray (bg-gray-500) |
| `scheduled` | Job is scheduled but runs infrequently | Purple (bg-purple-600) |

### Accessing Job Status

Job status is accessible through:
1. **Backend Function**: `get_job_status()` in `scheduler.py`
2. **API Endpoint**: `GET /api/settings/info` (includes `background_jobs` field)
3. **Frontend Display**: Settings page > Background Jobs section

### Background Jobs List

| Job Name | Interval | Description |
|----------|----------|-------------|
| **Fetch Logs** | 60 seconds | Imports Postfix, Rspamd, and Netfilter logs from Mailcow API |
| **Complete Correlations** | 120 seconds (2 min) | Links Postfix logs to message correlations |
| **Update Final Status** | 120 seconds (2 min) | Updates message delivery status for late-arriving logs |
| **Expire Correlations** | 60 seconds (1 min) | Marks old incomplete correlations as expired (after 10 minutes) |
| **Cleanup Logs** | Daily at 2 AM | Removes logs older than retention period |
| **Check App Version** | 6 hours | Checks GitHub for application updates |
| **DNS Check** | 6 hours | Validates DNS records (SPF, DKIM, DMARC) for all active domains |

### Implementation Details

**Update Function:**
```python
def update_job_status(job_name: str, status: str, error: str = None):
    """Update job execution status"""
    job_status[job_name] = {
        'last_run': datetime.now(timezone.utc),
        'status': status,
        'error': error
    }
```

**Usage in Jobs:**
```python
async def some_background_job():
    try:
        update_job_status('job_name', 'running')
        # ... job logic ...
        update_job_status('job_name', 'success')
    except Exception as e:
        update_job_status('job_name', 'failed', str(e))
```

**UI Display:**
- Compact card layout with status badges
- Icon indicators (⏱ ⏳ 📅 🗂 📋)
- Last run timestamp always visible
- Error messages displayed in red alert boxes
- Pending items count for correlation jobs

---

## Domains

### GET /api/domains/all

Get list of all domains with statistics and cached DNS validation results.

**Response:**
```json
{
  "total": 10,
  "active": 8,
  "last_dns_check": "2026-01-08T01:34:08Z",
  "domains": [
    {
      "domain_name": "example.com",
      "active": true,
      "mboxes_in_domain": 5,
      "mboxes_left": 995,
      "max_num_mboxes_for_domain": 1000,
      "aliases_in_domain": 3,
      "aliases_left": 397,
      "max_num_aliases_for_domain": 400,
      "created": "2025-01-01T00:00:00Z",
      "bytes_total": 1572864,
      "msgs_total": 1234,
      "quota_used_in_domain": "1572864",
      "max_quota_for_domain": 10240000,
      "backupmx": false,
      "relay_all_recipients": false,
      "relay_unknown_only": false,
      "dns_checks": {
        "spf": {
          "status": "success",
          "message": "SPF configured correctly with strict -all policy",
          "record": "v=spf1 mx include:_spf.google.com -all",
          "has_strict_all": true,
          "includes_mx": true,
          "includes": ["_spf.google.com"],
          "warnings": []
        },
        "dkim": {
          "status": "success",
          "message": "DKIM configured correctly",
          "selector": "dkim",
          "dkim_domain": "dkim._domainkey.example.com",
          "expected_record": "v=DKIM1;k=rsa;p=MIIBIjANBg...",
          "actual_record": "v=DKIM1;k=rsa;p=MIIBIjANBg...",
          "match": true
        },
        "dmarc": {
          "status": "success",
          "message": "DMARC configured with strict policy",
          "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
          "policy": "reject",
          "subdomain_policy": null,
          "pct": "100",
          "is_strong": true,
          "warnings": []
        },
        "checked_at": "2026-01-08T01:34:08Z"
      }
    }
  ]
}
```

**Response Fields:**
- `total`: Total number of domains
- `active`: Number of active domains
- `last_dns_check`: Timestamp of last global DNS check (only updated by scheduled or manual full checks)
- `domains`: Array of domain objects

**Domain Object Fields:**
- `domain_name`: Domain name
- `active`: Boolean indicating if domain is active
- `mboxes_in_domain`: Number of mailboxes
- `mboxes_left`: Available mailbox slots
- `max_num_mboxes_for_domain`: Maximum mailboxes allowed
- `aliases_in_domain`: Number of aliases
- `aliases_left`: Available alias slots
- `max_num_aliases_for_domain`: Maximum aliases allowed
- `created`: Domain creation timestamp (UTC)
- `bytes_total`: Total storage used (bytes)
- `msgs_total`: Total messages
- `quota_used_in_domain`: Storage quota used (string format)
- `max_quota_for_domain`: Maximum storage quota
- `backupmx`: Boolean - true if domain is backup MX
- `relay_all_recipients`: Boolean - true if relaying all recipients
- `relay_unknown_only`: Boolean - true if relaying only unknown recipients
- `dns_checks`: DNS validation results (cached from database)

**DNS Check Status Values:**
- `success`: Check passed with no issues
- `warning`: Check passed but with recommendations for improvement
- `error`: Check failed or record not found
- `unknown`: Check not yet performed

**SPF Status Indicators:**
- `-all`: Strict policy (status: success)
- `~all`: Soft fail (status: warning) - Consider using -all for stricter policy
- `?all`: Neutral (status: warning) - Provides minimal protection
- `+all`: Pass all (status: error) - Provides no protection
- Missing `all`: No policy defined (status: error)

**DKIM Validation:**
- Fetches expected DKIM record from Mailcow API
- Queries DNS for actual DKIM record
- Compares expected vs actual records
- `match`: Boolean indicating if records match

**DMARC Policy Types:**
- `reject`: Strict policy (status: success)
- `quarantine`: Moderate policy (status: warning) - Consider upgrading to reject
- `none`: Monitor only (status: warning) - Provides no protection

**Notes:**
- DNS checks are cached in database for performance
- `last_dns_check` only updates from global/scheduled checks, not individual domain checks
- `checked_at` (per domain) updates whenever that specific domain is checked
- All timestamps include UTC timezone indicator ('Z' suffix)

---

### POST /api/domains/check-all-dns

Manually trigger DNS validation for all active domains.

**Description:** 
Performs DNS checks (SPF, DKIM, DMARC) for all active domains and updates the global `last_dns_check` timestamp. Results are cached in database.

**Authentication:** Required

**Response:**
```json
{
  "status": "success",
  "message": "Checked 8 domains",
  "domains_checked": 8,
  "errors": []
}
```

**Response Fields:**
- `status`: `success` (all domains checked) or `partial` (some domains failed)
- `message`: Summary message
- `domains_checked`: Number of domains successfully checked
- `errors`: Array of error messages for failed domains (empty if all successful)

**Error Response (partial success):**
```json
{
  "status": "partial",
  "message": "Checked 7 domains",
  "domains_checked": 7,
  "errors": [
    "example.com: DNS timeout"
  ]
}
```

**Notes:**
- Only checks active domains
- Updates `is_full_check=true` flag in database
- Updates global `last_dns_check` timestamp
- Frontend shows progress with toast notifications
- Returns immediately with status (check runs asynchronously)

---

### POST /api/domains/{domain}/check-dns

Manually trigger DNS validation for a specific domain.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Domain name to check |

**Authentication:** Required

**Example Request:**
```
POST /api/domains/example.com/check-dns
```

**Response:**
```json
{
  "status": "success",
  "message": "DNS checked for example.com",
  "data": {
    "domain": "example.com",
    "spf": {
      "status": "success",
      "message": "SPF configured correctly with strict -all policy",
      "record": "v=spf1 mx include:_spf.google.com -all",
      "has_strict_all": true,
      "includes_mx": true,
      "includes": ["_spf.google.com"],
      "warnings": []
    },
    "dkim": {
      "status": "success",
      "message": "DKIM configured correctly",
      "selector": "dkim",
      "dkim_domain": "dkim._domainkey.example.com",
      "expected_record": "v=DKIM1;k=rsa;p=MIIBIjANBg...",
      "actual_record": "v=DKIM1;k=rsa;p=MIIBIjANBg...",
      "match": true
    },
    "dmarc": {
      "status": "success",
      "message": "DMARC configured with strict policy",
      "record": "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
      "policy": "reject",
      "is_strong": true,
      "warnings": []
    },
    "checked_at": "2026-01-08T01:45:23Z"
  }
}
```

**Notes:**
- Only checks the specified domain
- Updates `is_full_check=false` flag in database
- Does NOT update global `last_dns_check` timestamp
- Frontend updates only that domain's section (no page refresh)
- Useful for verifying DNS changes immediately

---

### DNS Check Technical Details

**Async DNS Validation:**
- All DNS queries use async resolvers with 5-second timeout
- Queries run in parallel for performance
- Comprehensive error handling for timeouts, NXDOMAIN, NoAnswer

**SPF Validation:**
- Queries TXT records for SPF (`v=spf1`)
- Detects policy: `-all`, `~all`, `?all`, `+all`, or missing
- Checks for `mx` mechanism
- Extracts `include:` directives
- Provides policy-specific warnings

**DKIM Validation:**
- Fetches expected DKIM value from Mailcow API (`/api/v1/get/dkim/{domain}`)
- Queries DNS at `{selector}._domainkey.{domain}`
- Compares expected vs actual records (whitespace-normalized)
- Reports mismatch details

**DMARC Validation:**
- Queries TXT records at `_dmarc.{domain}`
- Parses policy (`p=` tag)
- Checks for subdomain policy (`sp=` tag)
- Validates percentage (`pct=` tag)
- Provides policy upgrade recommendations

**Background Checks:**
- Automated DNS checks run every 6 hours via scheduler
- Only checks active domains
- All automated checks marked as `is_full_check=true`
- Results cached in `domain_dns_checks` table

**Caching:**
- DNS results stored in PostgreSQL with JSONB columns
- Indexed on `domain_name` and `checked_at` for performance
- Upsert pattern (update if exists, insert if new)
- `is_full_check` flag distinguishes check types

---

## Messages (Unified View)

### GET /messages

Get unified messages view combining Postfix and Rspamd data.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `limit` | int | Items per page (default: 50, max: 500) |
| `search` | string | Search in sender, recipient, subject, message_id, queue_id |
| `sender` | string | Filter by sender email |
| `recipient` | string | Filter by recipient email |
| `direction` | string | Filter by direction: `inbound`, `outbound`, `internal` |
| `status` | string | Filter by status: `delivered`, `bounced`, `deferred`, `rejected`, `spam`<br>**Note:** `spam` filter checks both `final_status='spam'` and `is_spam=True` from Rspamd |
| `user` | string | Filter by authenticated user |
| `ip` | string | Filter by source IP address |
| `start_date` | datetime | Start date (ISO format) |
| `end_date` | datetime | End date (ISO format) |

**Example Request:**
```
GET /api/messages?page=1&limit=50&direction=outbound&sender=user@example.com
```

**Response:**
```json
{
  "total": 1234,
  "page": 1,
  "limit": 50,
  "pages": 25,
  "data": [
    {
      "correlation_key": "abc123def456...",
      "message_id": "<unique-id@example.com>",
      "queue_id": "ABC123DEF",
      "sender": "user@example.com",
      "recipient": "recipient@gmail.com",
      "subject": "Hello World",
      "direction": "outbound",
      "final_status": "delivered",
      "is_complete": true,
      "first_seen": "2025-12-25T10:30:00Z",
      "last_seen": "2025-12-25T10:30:05Z",
      "spam_score": 0.5,
      "is_spam": false,
      "user": "user@example.com",
      "ip": "192.168.1.100"
    }
  ]
}
```

---

### GET /message/{correlation_key}/details

Get complete message details with all related logs.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `correlation_key` | string | The correlation key (SHA256 hash) |

**Response:**
```json
{
  "correlation_key": "abc123def456...",
  "message_id": "<unique-id@example.com>",
  "queue_id": "ABC123DEF",
  "sender": "user@example.com",
  "recipient": "recipient@gmail.com",
  "recipients": ["recipient@gmail.com", "cc@gmail.com"],
  "recipient_count": 2,
  "subject": "Hello World",
  "direction": "outbound",
  "final_status": "delivered",
  "is_complete": true,
  "first_seen": "2025-12-25T10:30:00Z",
  "last_seen": "2025-12-25T10:30:05Z",
  "rspamd": {
    "time": "2025-12-25T10:30:00Z",
    "score": 0.5,
    "required_score": 15,
    "action": "no action",
    "symbols": {
      "MAILCOW_AUTH": {"score": -20, "description": "mailcow authenticated"},
      "RCVD_COUNT_ZERO": {"score": 0, "options": ["0"]}
    },
    "is_spam": false,
    "direction": "outbound",
    "ip": "192.168.1.100",
    "user": "user@example.com",
    "has_auth": true,
    "size": 1024
  },
  "postfix": [
    {
      "time": "2025-12-25T10:30:00Z",
      "program": "postfix/smtpd",
      "priority": "info",
      "message": "ABC123DEF: client=...",
      "status": null,
      "relay": null,
      "delay": null,
      "dsn": null
    },
    {
      "time": "2025-12-25T10:30:05Z",
      "program": "postfix/smtp",
      "priority": "info",
      "message": "ABC123DEF: to=<recipient@gmail.com>, relay=gmail-smtp-in.l.google.com...",
      "status": "sent",
      "relay": "gmail-smtp-in.l.google.com[142.251.168.26]:25",
      "delay": 1.5,
      "dsn": "2.0.0"
    }
  ],
  "postfix_by_recipient": {
    "recipient@gmail.com": [...],
    "cc@gmail.com": [...],
    "_system": [...]
  },
  "netfilter": []
}
```

---

## Logs

### Postfix Logs

#### GET /logs/postfix

Get Postfix logs grouped by Queue-ID.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `limit` | int | Items per page (default: 50, max: 500) |
| `search` | string | Search in message, sender, recipient, queue_id |
| `sender` | string | Filter by sender |
| `recipient` | string | Filter by recipient |
| `status` | string | Filter by status: `sent`, `bounced`, `deferred`, `rejected` |
| `queue_id` | string | Filter by specific queue ID |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:**
```json
{
  "total": 500,
  "page": 1,
  "limit": 50,
  "pages": 10,
  "data": [
    {
      "id": 12345,
      "time": "2025-12-25T10:30:00Z",
      "program": "postfix/smtp",
      "priority": "info",
      "message": "ABC123DEF: to=<user@example.com>...",
      "queue_id": "ABC123DEF",
      "message_id": "<unique-id@example.com>",
      "sender": "sender@example.com",
      "recipient": "user@example.com",
      "status": "sent",
      "relay": "mail.example.com[1.2.3.4]:25",
      "delay": 1.5,
      "dsn": "2.0.0",
      "correlation_key": "abc123..."
    }
  ]
}
```

---

#### GET /logs/postfix/by-queue/{queue_id}

Get all Postfix logs for a specific Queue-ID with linked Rspamd data.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `queue_id` | string | The Postfix queue ID |

**Response:**
```json
{
  "queue_id": "ABC123DEF",
  "correlation_key": "abc123...",
  "rspamd": {
    "score": 0.5,
    "required_score": 15,
    "action": "no action",
    "symbols": {...},
    "is_spam": false,
    "direction": "outbound",
    "subject": "Hello World"
  },
  "logs": [
    {
      "id": 12345,
      "time": "2025-12-25T10:30:00Z",
      "program": "postfix/smtpd",
      "priority": "info",
      "message": "ABC123DEF: client=...",
      "queue_id": "ABC123DEF",
      "message_id": "<unique-id@example.com>",
      "sender": "sender@example.com",
      "recipient": "user@example.com",
      "status": null,
      "relay": null,
      "delay": null,
      "dsn": null
    }
  ]
}
```

---

### Rspamd Logs

#### GET /logs/rspamd

Get Rspamd spam analysis logs.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `limit` | int | Items per page (default: 50, max: 500) |
| `search` | string | Search in subject, sender, message_id |
| `sender` | string | Filter by sender |
| `direction` | string | Filter: `inbound`, `outbound`, `internal`, `unknown` |
| `min_score` | float | Minimum spam score |
| `max_score` | float | Maximum spam score |
| `action` | string | Filter by action: `no action`, `greylist`, `add header`, `reject` |
| `is_spam` | boolean | Filter spam only (`true`) or clean only (`false`) |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:**
```json
{
  "total": 1000,
  "page": 1,
  "limit": 50,
  "pages": 20,
  "data": [
    {
      "id": 5678,
      "time": "2025-12-25T10:30:00Z",
      "message_id": "<unique-id@example.com>",
      "subject": "Hello World",
      "size": 1024,
      "sender_smtp": "sender@example.com",
      "recipients_smtp": ["user@example.com"],
      "score": 0.5,
      "required_score": 15,
      "action": "no action",
      "direction": "outbound",
      "ip": "192.168.1.100",
      "is_spam": false,
      "has_auth": true,
      "user": "sender@example.com",
      "symbols": {
        "MAILCOW_AUTH": {"score": -20, "description": "mailcow authenticated"},
        "RCVD_COUNT_ZERO": {"score": 0, "options": ["0"]}
      },
      "correlation_key": "abc123..."
    }
  ]
}
```

---

### Netfilter Logs

#### GET /logs/netfilter

Get Netfilter authentication failure logs.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `limit` | int | Items per page (default: 50, max: 500) |
| `search` | string | Search in message, IP, username |
| `ip` | string | Filter by IP address |
| `username` | string | Filter by username |
| `action` | string | Filter: `warning`, `banned` |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:**
```json
{
  "total": 100,
  "page": 1,
  "limit": 50,
  "pages": 2,
  "data": [
    {
      "id": 999,
      "time": "2025-12-25T10:30:00Z",
      "priority": "warn",
      "message": "1.1.1.1 matched rule id 3...",
      "ip": "1.1.1.1",
      "rule_id": 3,
      "attempts_left": 9,
      "username": "user@example.com",
      "auth_method": "SASL LOGIN",
      "action": "warning"
    }
  ]
}
```

---

## Queue & Quarantine

### GET /queue

Get current mail queue from Mailcow (real-time).

**Response:**
```json
{
  "total": 5,
  "data": [
    {
      "queue_name": "deferred",
      "queue_id": "ABC123DEF",
      "arrival_time": 1735123456,
      "message_size": 515749,
      "forced_expire": false,
      "sender": "sender@example.com",
      "recipients": [
        "user@example.com (connect to example.com[1.2.3.4]:25: Connection timed out)"
      ]
    }
  ]
}
```

---

### GET /quarantine

Get quarantined messages from Mailcow (real-time).

**Response:**
```json
{
  "total": 3,
  "data": [
    {
      "id": 123,
      "subject": "Suspicious Email",
      "sender": "spammer@evil.com",
      "recipients": ["user@example.com"],
      "created": "2025-12-25T10:30:00Z",
      "reason": "High spam score"
    }
  ]
}
```

---

## Statistics

### GET /stats/dashboard

Get main dashboard statistics.

**Response:**
```json
{
  "messages": {
    "24h": 1234,
    "7d": 8765,
    "30d": 34567
  },
  "spam": {
    "24h": 56,
    "7d": 234,
    "percentage_24h": 4.54
  },
  "failed_deliveries": {
    "24h": 12,
    "7d": 45
  },
  "auth_failures": {
    "24h": 89,
    "7d": 456
  },
  "direction": {
    "inbound_24h": 800,
    "outbound_24h": 434,
    "internal_24h": 120
  }
}
```

---

### GET /stats/timeline

Get message timeline for charts.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `hours` | int | Number of hours to show (default: 24) |

**Response:**
```json
{
  "timeline": [
    {
      "hour": "2025-12-25T08:00:00Z",
      "total": 45,
      "spam": 2,
      "clean": 43
    },
    {
      "hour": "2025-12-25T09:00:00Z",
      "total": 67,
      "spam": 5,
      "clean": 62
    }
  ]
}
```

---

### GET /stats/top-spam-triggers

Get top spam detection symbols.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Number of results (default: 10) |

**Response:**
```json
{
  "triggers": [
    {"symbol": "RCVD_IN_DNSWL_NONE", "count": 456},
    {"symbol": "DKIM_SIGNED", "count": 234},
    {"symbol": "SPF_PASS", "count": 200}
  ]
}
```

---

### GET /stats/top-blocked-ips

Get top blocked/warned IP addresses.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Number of results (default: 10) |

**Response:**
```json
{
  "blocked_ips": [
    {
      "ip": "1.1.1.1",
      "count": 45,
      "last_seen": "2025-12-25T10:30:00Z"
    }
  ]
}
```

---

### GET /stats/recent-activity

Get recent message activity stream.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `limit` | int | Number of results (default: 20) |

**Response:**
```json
{
  "activity": [
    {
      "time": "2025-12-25T10:30:00Z",
      "sender": "user@example.com",
      "recipient": "other@gmail.com",
      "subject": "Hello World",
      "direction": "outbound",
      "status": "delivered",
      "correlation_key": "abc123..."
    }
  ]
}
```

---

## Status

### GET /status/containers

Get status of all Mailcow containers.

**Response:**
```json
{
  "containers": {
    "postfix-mailcow": {
      "name": "postfix",
      "state": "running",
      "started_at": "2025-12-20T08:00:00Z"
    },
    "dovecot-mailcow": {
      "name": "dovecot",
      "state": "running",
      "started_at": "2025-12-20T08:00:00Z"
    }
  },
  "summary": {
    "running": 18,
    "stopped": 0,
    "total": 18
  }
}
```

---

### GET /status/storage

Get storage/disk usage information.

**Response:**
```json
{
  "disk": "/dev/sda1",
  "used": "45G",
  "total": "100G",
  "used_percent": "45%"
}
```

---

### GET /status/version

Get Mailcow version and update status.

**Response:**
```json
{
  "current_version": "2025-01",
  "latest_version": "2025-01a",
  "update_available": true,
  "changelog": "Bug fixes and improvements...",
  "last_checked": "2025-12-25T10:30:00Z"
}
```

---

### GET /status/app-version

Get application version and check for updates from GitHub.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `force` | boolean | Force a fresh version check regardless of cache age (default: false) |

**Response:**
```json
{
  "current_version": "1.4.9",
  "latest_version": "1.4.9",
  "update_available": false,
  "changelog": "### Added\n\n#### Background Jobs Enhanced UI\n- Compact layout...",
  "last_checked": "2026-01-08T15:52:46Z"
}
```

**Implementation Notes:**
- Version checks are performed by the scheduler every 6 hours
- Results are cached in `app_version_cache` (managed by `scheduler.py`)
- Status endpoint retrieves cached data via `get_app_version_cache()`
- Use `force=true` parameter to bypass cache and trigger immediate check
- All timestamps include UTC timezone indicator ('Z' suffix)
- Changelog is retrieved from GitHub releases in Markdown format

**Version Check Process:**
1. Scheduler job `check_app_version_update` runs every 6 hours
2. Fetches latest release from `https://api.github.com/repos/ShlomiPorush/mailcow-logs-viewer/releases/latest`
3. Compares current version (from `/app/VERSION` file) with latest GitHub release
4. Updates cache with result and changelog
5. Job status tracked with `update_job_status()` (visible in Settings > Background Jobs)

---

### GET /status/app-version/changelog/{version}

Get changelog for a specific app version from GitHub.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `version` | string | Version number (with or without 'v' prefix, e.g., "1.4.6" or "v1.4.6") |

**Response:**
```json
{
  "version": "1.4.6",
  "changelog": "Full changelog in Markdown format for the specified version..."
}
```

**Note:** Returns the changelog from the GitHub release for the specified version tag.

---

### GET /status/mailcow-connection

Check Mailcow API connection status.

**Response:**
```json
{
  "connected": true,
  "timestamp": "2026-01-05T15:52:46Z"
}
```

**Note:** Returns connection status and current timestamp in UTC format.

---

### GET /status/mailcow-info

Get Mailcow system information.

**Response:**
```json
{
  "domains": {
    "total": 5,
    "active": 5
  },
  "mailboxes": {
    "total": 25,
    "active": 23
  },
  "aliases": {
    "total": 50,
    "active": 48
  }
}
```

---

### GET /status/summary

Get combined status summary for dashboard.

**Response:**
```json
{
  "containers": {
    "running": 18,
    "stopped": 0,
    "total": 18
  },
  "storage": {
    "used_percent": "45%",
    "used": "45G",
    "total": "100G"
  },
  "system": {
    "domains": 5,
    "mailboxes": 25,
    "aliases": 50
  }
}
```

---

## Settings

### GET /settings/info

Get system configuration and status information.

**Response:**
```json
{
  "configuration": {
    "mailcow_url": "https://mail.example.com",
    "local_domains": ["example.com"],
    "fetch_interval": 60,
    "fetch_count_postfix": 2000,
    "fetch_count_rspamd": 500,
    "fetch_count_netfilter": 500,
    "retention_days": 7,
    "timezone": "UTC",
    "app_title": "Mailcow Logs Viewer",
    "log_level": "WARNING",
    "blacklist_enabled": true,
    "blacklist_count": 3,
    "max_search_results": 1000,
    "csv_export_limit": 10000,
    "scheduler_workers": 4,
    "auth_enabled": false,
    "auth_username": null
  },
  "import_status": {
    "postfix": {
      "last_import": "2025-12-25T10:30:00Z",
      "last_fetch_run": "2025-12-25T10:35:00Z",
      "total_entries": 50000,
      "oldest_entry": "2025-12-18T00:00:00Z"
    },
    "rspamd": {
      "last_import": "2025-12-25T10:30:00Z",
      "last_fetch_run": "2025-12-25T10:35:00Z",
      "total_entries": 45000,
      "oldest_entry": "2025-12-18T00:00:00Z"
    },
    "netfilter": {
      "last_import": "2025-12-25T10:30:00Z",
      "last_fetch_run": "2025-12-25T10:35:00Z",
      "total_entries": 1000,
      "oldest_entry": "2025-12-18T00:00:00Z"
    }
  },
  "correlation_status": {
    "last_update": "2025-12-25T10:30:00Z",
    "total": 40000,
    "complete": 39500,
    "incomplete": 500,
    "expired": 100,
    "completion_rate": 98.75
  },
  "background_jobs": {
    "fetch_logs": {
      "interval": "60 seconds",
      "description": "Imports logs from Mailcow API",
      "status": "success",
      "last_run": "2026-01-08T12:14:56Z",
      "error": null
    },
    "complete_correlations": {
      "interval": "120 seconds (2 minutes)",
      "description": "Links Postfix logs to messages",
      "status": "running",
      "last_run": "2026-01-08T12:13:56Z",
      "error": null,
      "pending_items": 93
    },
    "update_final_status": {
      "interval": "120 seconds (2 minutes)",
      "description": "Updates final status for correlations with late-arriving Postfix logs",
      "max_age": "10 minutes",
      "status": "success",
      "last_run": "2026-01-08T12:13:56Z",
      "error": null,
      "pending_items": 25
    },
    "expire_correlations": {
      "interval": "60 seconds (1 minute)",
      "description": "Marks old incomplete correlations as expired",
      "expire_after": "10 minutes",
      "status": "success",
      "last_run": "2026-01-08T12:14:45Z",
      "error": null
    },
    "cleanup_logs": {
      "schedule": "Daily at 2 AM",
      "description": "Removes old logs based on retention period",
      "retention": "7 days",
      "status": "scheduled",
      "last_run": "2026-01-08T02:00:00Z",
      "error": null
    },
    "check_app_version": {
      "interval": "6 hours",
      "description": "Checks for application updates from GitHub",
      "status": "success",
      "last_run": "2026-01-08T10:00:00Z",
      "error": null
    },
    "dns_check": {
      "interval": "6 hours",
      "description": "Validates DNS records (SPF, DKIM, DMARC) for all active domains",
      "status": "success",
      "last_run": "2026-01-08T08:00:00Z",
      "error": null
    }
  },
  "recent_incomplete_correlations": [
    {
      "message_id": "<unique-id@example.com>",
      "queue_id": "ABC123",
      "sender": "user@example.com",
      "recipient": "other@gmail.com",
      "created_at": "2025-12-25T10:28:00Z",
      "age_minutes": 2
    }
  ]
}
```

**Background Jobs Status Tracking:**

Each background job reports real-time execution status:

| Field | Type | Description |
|-------|------|-------------|
| `interval` / `schedule` | string | How often the job runs |
| `description` | string | Human-readable job description |
| `status` | string | Current status: `running`, `success`, `failed`, `idle`, `scheduled` |
| `last_run` | datetime | UTC timestamp of last execution (with 'Z' suffix) |
| `error` | string / null | Error message if job failed, otherwise null |
| `pending_items` | int | Number of items waiting (for correlation jobs only) |
| `max_age` / `expire_after` / `retention` | string | Job-specific configuration |

**Status Values:**
- `running` - Job is currently executing
- `success` - Job completed successfully
- `failed` - Job encountered an error
- `idle` - Job hasn't run yet
- `scheduled` - Job is scheduled but runs infrequently (e.g., daily cleanup)

**Job Descriptions:**

1. **fetch_logs**: Fetches Postfix, Rspamd, and Netfilter logs from Mailcow API every 60 seconds
2. **complete_correlations**: Links Postfix logs to message correlations every 2 minutes
3. **update_final_status**: Updates message delivery status when late-arriving Postfix logs are found
4. **expire_correlations**: Marks old incomplete correlations as expired after 10 minutes
5. **cleanup_logs**: Removes logs older than retention period (runs daily at 2 AM)
6. **check_app_version**: Checks GitHub for application updates every 6 hours
7. **dns_check**: Validates DNS records (SPF, DKIM, DMARC) for all active domains every 6 hours

---

### GET /settings/health

Detailed health check with timing information.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-12-25T10:30:00Z",
  "database": {
    "status": "connected",
    "response_time_ms": 1.25
  },
  "recent_activity": {
    "last_5_minutes": {
      "postfix_imported": 45,
      "rspamd_imported": 42,
      "correlations_created": 40
    }
  }
}
```

---

## Export

### GET /export/postfix/csv

Export Postfix logs to CSV file.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search filter |
| `sender` | string | Filter by sender |
| `recipient` | string | Filter by recipient |
| `status` | string | Filter by status |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:** CSV file download

**Columns:** Time, Program, Priority, Queue ID, Message ID, Sender, Recipient, Status, Relay, Delay, DSN, Message

---

### GET /export/rspamd/csv

Export Rspamd logs to CSV file.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search filter |
| `sender` | string | Filter by sender |
| `direction` | string | Filter by direction |
| `min_score` | float | Minimum spam score |
| `max_score` | float | Maximum spam score |
| `is_spam` | boolean | Filter by spam status |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:** CSV file download

**Columns:** Time, Message ID, Subject, Sender, Recipients, Score, Required Score, Action, Direction, Is Spam, Has Auth, User, IP, Size, Top Symbols

---

### GET /export/netfilter/csv

Export Netfilter logs to CSV file.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search filter |
| `ip` | string | Filter by IP |
| `username` | string | Filter by username |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:** CSV file download

**Columns:** Time, IP, Username, Auth Method, Action, Attempts Left, Rule ID, Priority, Message

---

### GET /export/messages/csv

Export Messages (correlations) to CSV file.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search filter |
| `sender` | string | Filter by sender |
| `recipient` | string | Filter by recipient |
| `direction` | string | Filter by direction |
| `status` | string | Filter by status |
| `user` | string | Filter by authenticated user |
| `ip` | string | Filter by IP address |
| `start_date` | datetime | Start date |
| `end_date` | datetime | End date |

**Response:** CSV file download

**Columns:** Time, Sender, Recipient, Subject, Direction, Status, Queue ID, Message ID, Spam Score, Is Spam, User, IP, Is Complete

---

## Error Responses

All endpoints may return the following error responses:

### 400 Bad Request
```json
{
  "detail": "Invalid parameter value"
}
```

### 404 Not Found
```json
{
  "detail": "Resource not found"
}
```

### 401 Unauthorized
```json
{
  "detail": "Authentication required"
}
```

**Note:** Returned when authentication is enabled but no valid credentials are provided. The response does not include `WWW-Authenticate` header to prevent browser popup dialogs.

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "detail": "Error description (only in debug mode)"
}
```