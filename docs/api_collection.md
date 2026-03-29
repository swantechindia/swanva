# Swan VA API Collection

All endpoints are served under `/api/v1` and require the platform `Authorization` header.
Unless noted otherwise, `GET` and `DELETE` endpoints do not accept a JSON request body.

## Dashboard

### GET `/api/v1/dashboard/summary`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "total_assets": 248,
    "total_scanned": 248,
    "vulnerabilities": {
      "critical": 19,
      "high": 84,
      "medium": 84,
      "low": 146
    }
  }
}
```

### GET `/api/v1/dashboard/trends?days=7`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "dates": ["2026-03-23", "2026-03-24"],
    "critical": [1, 2],
    "high": [4, 3],
    "medium": [7, 6],
    "low": [11, 10]
  }
}
```

### GET `/api/v1/dashboard/asset-risk`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": [
    {
      "asset_name": "web-server-01",
      "critical": 5,
      "high": 12,
      "medium": 23,
      "low": 45
    }
  ]
}
```

## Assets

### GET `/api/v1/assets?page=1&limit=20&type=endpoint&search=192.168`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": 1,
        "name": "web-server-01",
        "asset_type": "endpoint",
        "target": "192.168.1.10",
        "created_at": "2026-03-29T10:00:00",
        "last_scanned_at": "2026-03-29T12:00:00",
        "last_connection_status": "success"
      }
    ],
    "page": 1,
    "limit": 20,
    "total": 1
  }
}
```

### POST `/api/v1/assets`

JSON payload required.

Common top-level shape:

```json
{
  "name": "asset-name",
  "asset_type": "endpoint",
  "description": "Optional description",
  "config": {}
}
```

Endpoint asset example:

```json
{
  "name": "linux-host-01",
  "asset_type": "endpoint",
  "description": "Ubuntu application host",
  "config": {
    "ip": "192.168.1.20",
    "os_type": "linux",
    "os_version": "22.04",
    "credentials": {
      "username": "ubuntu",
      "password": "plain-text-sent-over-https"
    }
  }
}
```

Database asset example:

```json
{
  "name": "db-primary",
  "asset_type": "database",
  "description": "Primary PostgreSQL instance",
  "config": {
    "db_type": "postgres",
    "ip": "192.168.1.25",
    "version": "15.2",
    "credentials": {
      "username": "postgres",
      "password": "plain-text-sent-over-https"
    }
  }
}
```

Web asset example:

```json
{
  "name": "customer-portal",
  "asset_type": "web",
  "description": "Public web application",
  "config": {
    "url": "https://example.com",
    "protocol": "https",
    "port": 443
  }
}
```

Response example:

```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "db-primary",
    "target": "192.168.1.25",
    "asset_type": "database",
    "config": {
      "db_type": "postgres",
      "ip": "192.168.1.25",
      "version": "15.2",
      "credentials": {
        "username": "postgres"
      }
    },
    "description": "Primary PostgreSQL instance",
    "last_connection_status": null,
    "last_checked_at": null,
    "created_at": "2026-03-29T10:00:00",
    "updated_at": "2026-03-29T10:00:00"
  }
}
```

### GET `/api/v1/assets/{asset_id}`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "db-primary",
    "target": "192.168.1.25",
    "asset_type": "database",
    "config": {
      "db_type": "postgres",
      "ip": "192.168.1.25",
      "version": "15.2",
      "credentials": {
        "username": "postgres"
      }
    },
    "description": "Primary PostgreSQL instance",
    "last_connection_status": "success",
    "last_checked_at": "2026-03-29T11:00:00",
    "created_at": "2026-03-29T10:00:00",
    "updated_at": "2026-03-29T10:05:00"
  }
}
```

### PUT `/api/v1/assets/{asset_id}`

JSON payload required.

Partial updates are supported. Nested `config` values are deep-merged with the existing asset config.

Example payload:

```json
{
  "name": "db-primary-renamed",
  "config": {
    "version": "15.3"
  }
}
```

Response example:

```json
{
  "success": true,
  "data": {
    "id": 1,
    "name": "db-primary-renamed",
    "target": "192.168.1.25",
    "asset_type": "database",
    "config": {
      "db_type": "postgres",
      "ip": "192.168.1.25",
      "version": "15.3",
      "credentials": {
        "username": "postgres"
      }
    },
    "description": "Primary PostgreSQL instance",
    "last_connection_status": "success",
    "last_checked_at": "2026-03-29T11:00:00",
    "created_at": "2026-03-29T10:00:00",
    "updated_at": "2026-03-29T10:10:00"
  }
}
```

### DELETE `/api/v1/assets/{asset_id}`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "id": 1,
    "deleted": true
  }
}
```

### POST `/api/v1/assets/{asset_id}/test-connection`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "status": "success",
    "message": "Connection successful."
  }
}
```

## Scans

### GET `/api/v1/scans/ready-assets`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": [
    {
      "asset_id": 1,
      "asset_name": "web-server",
      "asset_type": "endpoint",
      "target": "192.168.1.10",
      "last_scanned_at": "2026-03-29T10:00:00",
      "status": "ready"
    }
  ]
}
```

### POST `/api/v1/scans/start`

JSON payload required.

Required fields:

```json
{
  "asset_ids": [1],
  "scan_type": "web",
  "config": {}
}
```

The API also accepts the legacy single-asset shape using `asset_id`, and `scanner_type` is accepted as an alias of `scan_type`.

Web scan example:

```json
{
  "asset_ids": [1, 2, 3],
  "scan_type": "web",
  "config": {
    "tools": ["nuclei"]
  }
}
```

Network scan example:

```json
{
  "asset_ids": [4],
  "scan_type": "network",
  "config": {
    "ports": "1-1000",
    "threads": 100,
    "timeout": 1.0,
    "scan_type": "tcp_connect",
    "service_detection": true
  }
}
```

OS scan example:

```json
{
  "asset_ids": [7],
  "scan_type": "os",
  "config": {}
}
```

DB scan example:

```json
{
  "asset_ids": [9],
  "scan_type": "db",
  "config": {}
}
```

Response example:

```json
{
  "success": true,
  "data": [
    {
      "scan_id": "SCAN-000101",
      "job_id": 101,
      "asset_id": 1,
      "type": "web",
      "status": "queued"
    }
  ]
}
```

### GET `/api/v1/scans?asset_id=1&status=analysis_completed&type=web&page=1&limit=20`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "items": [
      {
        "scan_id": "SCAN-000101",
        "job_id": 101,
        "asset_id": 1,
        "asset_name": "web-server",
        "type": "web",
        "status": "analysis_completed",
        "date": "2026-03-29T10:00:00"
      }
    ],
    "page": 1,
    "limit": 20,
    "total": 1
  }
}
```

### GET `/api/v1/scans/{scan_id}`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "scan_id": "SCAN-000101",
    "job_id": 101,
    "asset": {
      "id": 1,
      "name": "web-server",
      "target": "https://example.com",
      "asset_type": "web"
    },
    "type": "web",
    "status": "analysis_completed",
    "stage": "analysis_completed",
    "progress": 100,
    "created_at": "2026-03-29T10:00:00",
    "started_at": "2026-03-29T10:01:00",
    "completed_at": "2026-03-29T10:03:00",
    "results_summary": {
      "result_count": 2,
      "result_types": ["vulnerability_engine", "web"],
      "report_status": "ready",
      "total_vulnerabilities": 12,
      "severity_counts": {
        "critical": 1,
        "high": 3,
        "medium": 4,
        "low": 4
      }
    }
  }
}
```

### DELETE `/api/v1/scans/{scan_id}`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "scan_id": "SCAN-000101",
    "deleted": true
  }
}
```

## Vulnerabilities

### GET `/api/v1/vulnerabilities/summary`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "critical": 3,
    "high": 8,
    "medium": 21,
    "low": 55
  }
}
```

### GET `/api/v1/vulnerabilities?severity=critical&asset_id=1&status=new&page=1&limit=20`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": "VUL-000001",
        "asset_id": 1,
        "asset_name": "web-server",
        "severity": "critical",
        "description": "Remote code execution vulnerability",
        "status": "new"
      }
    ],
    "page": 1,
    "limit": 20,
    "total": 1
  }
}
```

## Reports

### POST `/api/v1/reports/generate`

JSON payload required.

```json
{
  "scan_id": "SCAN-000101"
}
```

Response example:

```json
{
  "success": true,
  "data": {
    "report_id": "REP-000010",
    "scan_id": "SCAN-000101",
    "created_at": "2026-03-29T10:05:00",
    "status": "ready",
    "total_vulnerabilities": 12,
    "severity_counts": {
      "critical": 1,
      "high": 3,
      "medium": 4,
      "low": 4
    },
    "version": 1
  }
}
```

### GET `/api/v1/reports`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": [
    {
      "report_id": "REP-000010",
      "scan_id": "SCAN-000101",
      "created_at": "2026-03-29T10:05:00",
      "status": "ready",
      "total_vulnerabilities": 12,
      "severity_counts": {
        "critical": 1,
        "high": 3,
        "medium": 4,
        "low": 4
      },
      "version": 1
    }
  ]
}
```

### GET `/api/v1/reports/{report_id}`

JSON payload: none.

Response example:

```json
{
  "success": true,
  "data": {
    "report_id": "REP-000010",
    "scan_id": "SCAN-000101",
    "created_at": "2026-03-29T10:05:00",
    "status": "ready",
    "total_vulnerabilities": 12,
    "severity_counts": {
      "critical": 1,
      "high": 3,
      "medium": 4,
      "low": 4
    },
    "version": 1
  }
}
```

### GET `/api/v1/reports/{report_id}/download`

JSON payload: none.

Response:

Returns `application/json` as an attachment. Example payload:

```json
{
  "report_id": "REP-000010",
  "scan_id": "SCAN-000101",
  "created_at": "2026-03-29T10:05:00",
  "status": "ready",
  "version": 1,
  "report": {
    "scan_id": "scan_101",
    "asset": "web-server",
    "summary": {
      "critical": 1,
      "high": 3,
      "medium": 4,
      "low": 4
    },
    "total_vulnerabilities": 12,
    "vulnerabilities": {}
  }
}
```
