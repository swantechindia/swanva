# Swan VA Engineering Audit Report v1.2

## 1. Executive Summary

Swan VA is a prototype, not a production-ready backend. The happy-path architecture is understandable, but the implementation has multiple hard blockers: committed secrets, plaintext scan-time credential storage, zero authorization or tenant isolation, broken report and analytics paths, and an ORM schema collision that should fail real runtime initialization. Production-readiness score: **2.5/10**.

This audit verified repository structure and static code paths, and `python3 -m compileall` completed successfully. A full runtime boot/import validation was not possible in the current environment because core backend dependencies are missing, which also exposed a packaging problem: `va_manager` is not packaged as an installable backend with declared dependencies.

## 2. System Architecture

### Text Architecture Diagram

```text
Client
  -> FastAPI API
  -> SQLAlchemy session
  -> scan_jobs row created
  -> polling worker claims queued job from DB
  -> executor dispatches scanner package in-process
  -> raw scanner result stored in scan_results
  -> vulnerability engine builds inventory
  -> in-memory vuln index + vuln DB correlation
  -> report/vulnerability rows persisted
  -> API exposes status, results, reports, analytics
```

### Runtime Execution Flow

The runtime flow is:

1. `/scans/start` accepts a scan request.
2. The API writes a `scan_jobs` row.
3. A polling worker claims the next queued job using DB row locking.
4. The worker dispatches the requested scanner in-process through the executor.
5. Raw scanner output is stored in `scan_results`.
6. The vulnerability engine builds normalized inventory from scanner output.
7. The in-memory vulnerability index and vulnerability DB are used for correlation.
8. Structured reports and normalized vulnerability rows are persisted.
9. API endpoints expose status, raw results, structured reports, and analytics.

### Dependency Boundaries

Current boundaries are weak:

- The executor mutates `sys.path` and imports scanner packages directly instead of through stable package contracts.
- The vulnerability engine shares the same SQLAlchemy declarative base and metadata namespace as application tables.
- Raw scan execution and post-processing are coupled inside one worker path.

## 3. Codebase Structure

```text
/root/swanva
├── scanners/
│   ├── network_scanner/pscan/        TCP/SYN/UDP scanner + banner grabbing
│   ├── os_scanner/swan_os_scanner/   SSH-based Linux inventory collector
│   ├── web_scanner/web_scanner/      Nikto/Nuclei plugin runner
│   └── db_scanner/                   Placeholder only
├── va_manager/
│   ├── api/                          FastAPI routes, deps, app bootstrap
│   ├── executor/                     Scanner dispatch bridge
│   ├── models/                       App ORM models for assets/jobs/results/reports
│   ├── queue/                        DB-backed queue claim helper
│   ├── security/                     Secret encryption helper
│   ├── services/                     Scan/report/analytics services
│   ├── vuln_data_service/            In-memory CPE/version-range index
│   ├── vulnerability_engine/         Feed ingestion, inventory, matching, scoring
│   └── workers/                      Polling scan worker
├── README.md
└── requirements.txt
```

### Major Directory Responsibilities

- `scanners/network_scanner/pscan/`: threaded TCP connect, SYN, UDP scanning, plus optional banner grabbing and service detection.
- `scanners/os_scanner/swan_os_scanner/`: SSH-based Linux host inventory collector that gathers packages, services, users, sudo config, cron, permissions, and network information.
- `scanners/web_scanner/web_scanner/`: plugin-driven web scanning wrapper around Nikto and Nuclei using subprocess execution and output normalization.
- `scanners/db_scanner/`: placeholder package with no active scanner implementation.
- `va_manager/api/`: FastAPI app entrypoint, router composition, auth dependency, and resource routes.
- `va_manager/executor/`: dispatches jobs to scanner implementations.
- `va_manager/models/`: ORM models for assets, jobs, results, reports, and normalized vulnerability findings.
- `va_manager/queue/`: job claim helper using database row locking.
- `va_manager/security/`: secret encryption/decryption helper for stored credentials.
- `va_manager/services/`: app-level services for scan job creation, reports, and analytics.
- `va_manager/vuln_data_service/`: in-memory exact and version-range index for vulnerability correlation.
- `va_manager/vulnerability_engine/`: feed sync, database ingestion, inventory extraction, correlation, scoring, and report construction.
- `va_manager/workers/`: polling worker loop for job execution and analysis.

There is no `pyproject.toml` for `va_manager`; only the scanner packages are packaged. That is an operational smell for the actual backend.

## 4. Module Analysis

### Scanner Layer

#### Strengths

- Network scanner output is the cleanest and most structured.
- Web scanner has a reasonable normalized result schema.
- OS scanner collects rich system inventory.

#### Findings

- There is no formal scanner interface or protocol. Dispatch is hardcoded by string in the executor.
- Output formats are only partially standardized. Network, OS, and web scanners each emit different shapes and rely on extractor heuristics later.
- The executor depends on `sys.path` mutation for imports rather than package contracts.
- OS scanner exposes extremely sensitive host inventory, including sudo, cron, permissions, and service state.
- DB scanner is not implemented.

#### Extensibility Assessment

Extensibility is weak. New scanner support currently requires:

1. Adding a new scanner package.
2. Updating executor dispatch logic.
3. Defining a new result shape.
4. Teaching inventory extraction and correlation logic how to interpret that shape.

There is no stable abstraction boundary to keep this maintainable as scanner count grows.

### Orchestration Layer

#### Strengths

- Uses `FOR UPDATE SKIP LOCKED`, which is a reasonable primitive for a small DB-backed worker queue.

#### Findings

- Queue design is minimal: DB row insert plus polling.
- No retries.
- No dead-letter queue.
- No heartbeat.
- No lease timeout.
- No stuck-job recovery.
- No cancellation path.
- No priority support.
- No rate limits or backpressure.

The worker executes raw scan and vulnerability analysis in the same process and same critical path, which reduces isolation and makes long-running jobs expensive.

### Vulnerability Engine

#### Feed Ingestion

- NVD sync is paginated and tracks feed metadata.
- CPE dictionary sync is full-refresh.
- EUVD sync is lightweight and less mature.

#### Findings

- Feed ingestion structure is decent for an MVP.
- Correlation accuracy is limited by heuristic inventory extraction and simplified matching.
- Software entries without a usable version are dropped from matching.
- Findings lose port context during matching because the matcher hardcodes `port=None`.
- Risk scoring is simplistic and inflates severity based on hardcoded ports/services rather than defensible contextual risk modeling.

#### CVE Correlation Accuracy

Accuracy is likely mediocre in real environments:

- Versionless detections are skipped.
- Regex-based extraction from banners and web evidence is fragile.
- Alias resolution is heuristic.
- Product normalization is simplistic.

This will produce both false negatives and false positives in production.

### Vulnerability Data Service

#### Strengths

- Clear split between exact CPE lookup and version-range matching.
- In-memory lookup design is fast once loaded.

#### Findings

- Each worker loads the full index into process memory.
- Memory cost scales linearly with worker count.
- Feed refresh is only process-local.
- Large list materialization during index load is inefficient.
- Initialization strategy is simplistic and lacks distributed cache coordination.

This design is acceptable for a small single-process deployment, not for scaled workers or large vulnerability datasets.

### API Layer

#### Strengths

- Thin route layer.
- Authentication dependency is applied consistently.

#### Findings

- Endpoint design is minimal but under-specified.
- Input validation is shallow: `scanner_type` is free text and `config` is an untyped bag.
- There is authentication but effectively no authorization.
- No tenant isolation.
- No ownership checks.
- No pagination on result-heavy responses.
- No mutation routes beyond create/start, which suggests the lifecycle model is incomplete.

## 5. Security Review

### CRITICAL

#### 1. Committed Secrets

`va_manager/.env` contains non-empty runtime secrets and `.gitignore` explicitly whitelists that file.

Impact:

- Secret disclosure through repo access.
- Credential reuse risk.
- Environment compromise if these are real.

#### 2. Plaintext Scan-Time Credential Storage

OS scan passwords can be stored in plaintext in `scan_jobs.scan_config`.

Flow:

- API accepts arbitrary `config`.
- Job service persists it verbatim.
- Executor reads `config["password"]` directly for OS scans.

Impact:

- Plaintext SSH credentials at rest.
- Exposure through DB compromise, admin queries, backups, and debug dumps.

#### 3. No Authorization or Tenant Isolation

Routes decode a JWT and then ignore the claims. No owner, user, or tenant field exists on assets, jobs, results, or reports.

Impact:

- Any authenticated caller can enumerate or access other users’ data.
- Total failure of multi-tenant isolation.

### HIGH

#### 4. Raw Sensitive Scan Artifacts Exposed

The results API returns raw stored scanner outputs wholesale, including potentially sensitive OS inventory.

Impact:

- Sensitive host configuration leakage.
- Wider blast radius from token compromise.

#### 5. Weak JWT Validation Model

JWT validation uses a shared symmetric secret without issuer, audience, or required claim checks, and the same `SECRET_KEY` is reused for both JWT validation and credential encryption derivation.

Impact:

- Weak trust boundary.
- Cross-purpose key reuse.
- Easier misconfiguration and compromise propagation.

#### 6. SSH Host Key Validation Disabled

OS scanner uses `paramiko.AutoAddPolicy()`.

Impact:

- MITM risk during credentialed scans.
- Unacceptable default for a security product.

### MEDIUM

#### 7. Username Disclosure

Asset usernames are stored and returned in metadata responses.

#### 8. Unrestricted Scan Proxy Behavior

This backend can act as an authenticated scanning proxy with no per-user quotas, target restrictions, or abuse controls.

### LOW

#### 9. Legacy Plaintext Decryption Fallback

The secret manager returns non-Fernet values unchanged to preserve legacy plaintext rows.

Impact:

- Migration convenience traded for ongoing unsafe behavior.

## 6. Performance Analysis

### Bottlenecks

- Full vulnerability indexes are loaded into every worker process.
- Worker throughput is bounded by synchronous polling and in-process execution.
- Large raw JSON payloads are stored and returned without projection or paging.
- Large port scans can oversubscribe sockets and threads under concurrent worker load.

### Scalability Concerns

- Memory usage scales per worker, not per dataset.
- Feed reload coordination does not scale across processes.
- Long web or OS scans monopolize workers.
- No queue backpressure or workload shaping.

### Inefficient Patterns

- Product-CPE loading performs full ordered scans and concatenates large lists.
- Correlation skips unversioned software entirely, sacrificing recall for simplicity.
- Raw result storage and retrieval strategy will degrade badly as result size grows.

## 7. Reliability Assessment

### Findings

- No retry mechanism.
- No dead-letter handling.
- No lease timeout for claimed jobs.
- No worker heartbeat.
- No stuck-job recovery.
- No cancellation model.
- No idempotency guarantees around report generation.

### Failure Isolation

There is some intentional separation between scan execution and post-scan analysis, but failure isolation is still weak because:

- Both phases run in one worker path.
- Report persistence is transactionally brittle.
- Feed/index state is local to process memory.

### Concrete Reliability Blockers

- The worker and analytics services reference `asset.name`, but the `Asset` model only defines `target`.
- Report generation commits inside a higher-level worker transaction block.
- Schema creation relies on `create_all()` instead of proper migrations.

## 8. Code Quality

### Structure and Modularity

- Overall directory layout is understandable.
- Internal module boundaries are not disciplined enough for growth.
- Executor/package boundaries are especially weak.

### Type Safety

- Some scanner components are typed reasonably well.
- Service and API internals rely heavily on `dict[str, Any]`.

### Validation

- Validation exists at the request boundary, but internal schemas are mostly free-form dicts.
- `scanner_type` and `config` should be typed per scanner, not generic.

### Error Handling

- Basic error handling exists.
- Failure modeling is inconsistent.
- There is no durable operational recovery model.

### Logging

- Logging is present.
- No structured logging.
- No correlation IDs.
- No audit trail.
- No security event logging.

### Dead Code / Duplication / Structural Defects

- DB scanner is a placeholder package.
- There are duplicated conceptual models for vulnerabilities.
- Two different ORM classes map to the same `vulnerabilities` table under the same declarative base, which is a major structural defect.

### Test Coverage

Test coverage is effectively zero. No tests or test directories were found in the repository.

## 9. Production Readiness

- **Maturity level:** Prototype
- **Score:** 2.5/10

### Biggest Blockers to Production

1. Committed secrets.
2. Plaintext credential persistence in job configs.
3. No authorization or tenant isolation.
4. Broken ORM/schema design around vulnerabilities.
5. Broken report and analytics code paths.
6. No migrations.
7. No tests.
8. Weak packaging and runtime boundary management.

## 10. Recommendations

### P0 Immediate Fixes

1. Remove `va_manager/.env` from git, rotate every secret it contains, and stop whitelisting it in `.gitignore`.
2. Eliminate plaintext secret storage from `scan_jobs.scan_config`. Replace with encrypted credential references or short-lived vault lookups only.
3. Add real authorization and tenancy. Every asset, job, result, report, and vulnerability row needs tenant or ownership scoping enforced in every query.
4. Split feed intelligence tables from scan finding tables immediately. The duplicate `vulnerabilities` table mapping is a hard blocker.
5. Fix `Asset.name` references and repair the broken report and analytics path.
6. Remove inner `commit()` behavior from `generate_report()` and define clear transaction ownership.

### P1 Short-Term Improvements

1. Replace `Base.metadata.create_all()` with Alembic migrations.
2. Package `va_manager` properly with a `pyproject.toml` and pinned backend dependencies.
3. Add retry counts, dead-letter states, worker heartbeats, lease timeouts, and cancellation semantics to job execution.
4. Stop returning raw scan blobs by default. Add filtered views, paging, and sensitive-data access controls.
5. Enforce SSH host key validation with managed trust material.
6. Tighten JWT validation with issuer, audience, expiration, and claim requirements.
7. Add typed scanner-specific config schemas instead of generic dict configs.

### P2 Long-Term Architecture Improvements

1. Replace per-process in-memory vulnerability indexes with a shared indexed service or coordinated distributed cache.
2. Introduce a formal scanner interface contract and plugin registration model.
3. Separate scan execution, vulnerability analysis, and reporting into independently recoverable stages.
4. Improve correlation fidelity to preserve port/service context and support partial or versionless evidence more safely.
5. Add comprehensive integration tests for API -> queue -> worker -> report flow and fixture-driven correlation tests.

## Reference Notes

Key observations used in this report came from:

- API and auth wiring in `va_manager/api/`
- Worker and executor flow in `va_manager/workers/scan_worker.py` and `va_manager/executor/scan_executor.py`
- ORM models in `va_manager/models/` and `va_manager/vulnerability_engine/database/models.py`
- Vulnerability feed/index/correlation code in `va_manager/vulnerability_engine/` and `va_manager/vuln_data_service/`
- Scanner packages in `scanners/`

