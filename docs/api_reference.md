# SentinelX API Reference — Phase 2

Base URL: `http://localhost:8000`  
All protected routes require: `Authorization: Bearer <access_token>`

---

## Authentication

### Register

```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "username": "analyst1",
  "email": "analyst1@corp.com",
  "password": "SecurePass@2025!",
  "full_name": "Alice Analyst"
}
```

**201 Created**
```json
{
  "success": true,
  "data": {
    "id": 2,
    "username": "analyst1",
    "email": "analyst1@corp.com",
    "role": "viewer"
  }
}
```

> New accounts default to `viewer` role. Admins must promote via the DB.

---

### Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "admin@sentinelx.ai",
  "password": "SentinelX@2025!"
}
```

**200 OK**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGci...",
    "refresh_token": "eyJhbGci...",
    "token_type": "bearer",
    "expires_in": 1800,
    "user": { "id": 1, "email": "admin@sentinelx.ai", "role": "admin" }
  }
}
```

---

## Log Management

### Upload Log File

```http
POST /api/v1/logs/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file=<binary>
force_log_type=linux_syslog   (optional)
description=Production auth log   (optional)
```

**201 Created**
```json
{
  "success": true,
  "data": {
    "log_id": 5,
    "filename": "auth.log",
    "status": "pending",
    "file_size_bytes": 14721,
    "message": "Log uploaded. Call POST /logs/5/parse to run the NLP pipeline."
  }
}
```

---

### Run NLP Pipeline

```http
POST /api/v1/logs/{id}/parse
Authorization: Bearer <token>
Content-Type: application/json

{}
```

Optional body: `{ "force_log_type": "linux_syslog" }`

**200 OK**
```json
{
  "success": true,
  "data": {
    "log_id": 5,
    "log_type": "linux_syslog",
    "status": "completed",
    "parsed_event_count": 31,
    "ioc_count": 36,
    "processing_time_ms": 187,
    "message": "Pipeline complete: 31 events, 36 IOCs, 8 threats."
  }
}
```

---

### List Logs

```http
GET /api/v1/logs?page=1&page_size=20&status=completed&log_type=linux_syslog
```

---

### Get Log Detail

```http
GET /api/v1/logs/{id}
```

**200 OK** — includes `pipeline_summary` with event/IOC/threat counts.

---

### Get Parsed Events

```http
GET /api/v1/logs/{id}/events
  ?severity=high|medium|low|critical|info
  &threats_only=true
  &event_type=Failed+Login
  &page=1&per_page=50
```

**200 OK** — each event includes `mitre_technique_id`, `mitre_tactic`, `severity_score`, `source_ip`, `username`.

---

### Get IOCs for a Log

```http
GET /api/v1/logs/{id}/iocs?ioc_type=ipv4&page=1&page_size=50
```

---

### Delete Log (admin only)

```http
DELETE /api/v1/logs/{id}
```

---

## IOC Intelligence

### Search / List IOCs

```http
GET /api/v1/iocs/search
  ?q=185.24          substring match (omit to list all)
  &ioc_type=ipv4     filter by type
  &page=1&page_size=50
```

**IOC types:** `ipv4` `ipv6` `domain` `url` `md5` `sha1` `sha256` `email` `cve` `username` `hostname` `filename` `registry_key` `command_line` `port` `mac_address`

---

## Incidents

### List Incidents

```http
GET /api/v1/incidents?status=open&severity=critical&page=1&page_size=20
```

Incidents are auto-created for events with `severity_score >= 9` (CRITICAL).

### Update Status

```http
PATCH /api/v1/incidents/{id}/status
Content-Type: application/json

{ "status": "investigating" }
```

**Valid statuses:** `open` → `investigating` → `resolved` | `false_positive`

---

## Statistics

```http
GET /api/v1/statistics
```

**200 OK**
```json
{
  "data": {
    "total_logs": 4,
    "total_events": 53,
    "total_iocs": 50,
    "severity_breakdown": { "critical": 2, "high": 6, "medium": 14, "low": 20, "info": 11 },
    "log_type_breakdown": { "linux_syslog": 2, "apache_access": 2 },
    "top_source_ips": [{ "ip": "185.24.18.15", "count": 12 }],
    "ioc_type_breakdown": { "ipv4": 18, "domain": 12 },
    "mitre_tactic_breakdown": { "Credential Access": 8, "Initial Access": 6 }
  }
}
```

---

## Health Check

```http
GET /health
```

**200 OK** — reports `status`, `version`, and per-service health (`postgres`, `redis`, `neo4j`, `qdrant`).

---

## Error Envelope

```json
{
  "success": false,
  "error": {
    "type": "AuthenticationError",
    "message": "Invalid email or password."
  }
}
```

| HTTP | Error Type | Cause |
|------|-----------|-------|
| 400 | `ValidationError` | Bad request body |
| 401 | `AuthenticationError` | Missing/expired token |
| 403 | `PermissionDeniedError` | Insufficient role |
| 404 | `NotFoundError` | Resource not found |
| 409 | `ConflictError` | Duplicate email/username |
| 422 | `ValidationError` | Query parameter error |
| 500 | `InternalServerError` | Unhandled exception |
