# Swan VA Engineering Report

## 1. Executive Summary

Swan VA is an early-stage vulnerability assessment platform organized as a Python monorepo with independently installable scanners under `scanners/` and a shared orchestration and intelligence layer under `va_manager/`.

The system already has the shape of a useful platform:
- a network scanner (`pscan`)
- a credentialed Linux inventory scanner (`swan_os_scanner`)
- a plugin-based web scanner
- a database-backed scan job manager
- a vulnerability intelligence pipeline
- an in-memory CPE and version-range indexing service
- a thin HTTPS API layer

Architecturally, this is a strong start. The repo shows a consistent desire to separate concerns and keep scanners independent from orchestration. The `vulnerability_engine` and `vuln_data_service` modules are especially promising because they move the system toward reusable intelligence instead of scanner-specific post-processing.

That said, the current implementation is still prototype to early pre-production maturity, not production-ready. The main reasons are:
- critical security issues around secret handling and credential exposure
- a few architectural shortcuts that will become operational bottlenecks
- limited validation, typing rigor, and test coverage
- incomplete feed synchronization and weak normalization fidelity
- coupling between scan execution success and vulnerability analysis success

Current maturity level: **prototype / internal engineering preview**

Production readiness: **low**

Most urgent issues:
- plaintext credential handling in API and database
- `.env` tracking and weak secret management
- full vulnerability index rebuild on every scan analysis
- incomplete NVD ingestion strategy
- missing migrations, tests, and operational controls

## 2. System Architecture

### High-Level Architecture

Swan VA is organized into four layers:

1. **Scanner layer**
   - `scanners/network_scanner/pscan`
   - `scanners/os_scanner/swan_os_scanner`
   - `scanners/web_scanner`
   - `scanners/db_scanner` placeholder

2. **Orchestration layer**
   - `va_manager`
   - asset registry
   - scan job queue
   - worker
   - scanner executor
   - results persistence

3. **Vulnerability intelligence layer**
   - `va_manager/vulnerability_engine`
   - feed clients
   - local vulnerability schema
   - correlation and scoring
   - reporting

4. **Indexing acceleration layer**
   - `va_manager/vuln_data_service`
   - exact CPE index
   - vendor/product version-range index
   - in-memory lookup service

### Runtime Flow

```text
Frontend / API client
        |
        v
va_manager API
        |
        v
ScanJob row created
        |
        v
scan_worker polls DB queue
        |
        v
scan_executor dispatches scanner
        |
        v
scanner returns structured JSON
        |
        v
ScanResult(raw scanner output)
        |
        v
vulnerability_engine.analyze_scan_results()
        |
        v
vuln_data_service exact/range lookup
        |
        v
risk scoring + report builder
        |
        v
ScanResult(vulnerability report)
```

### Architecture Diagram

```text
+-------------------+       +-----------------------+
|  Scanner Packages | ----> |      va_manager       |
|-------------------|       |-----------------------|
| pscan             |       | manager.py            |
| swan_os_scanner   |       | models/               |
| web_scanner       |       | services/             |
| db_scanner        |       | queue/                |
+-------------------+       | executor/             |
                            | workers/              |
                            | api/                  |
                            +-----------+-----------+
                                        |
                                        v
                            +-----------------------+
                            | vulnerability_engine  |
                            |-----------------------|
                            | feeds/                |
                            | database/             |
                            | correlation/          |
                            | scoring/              |
                            | reporting/            |
                            +-----------+-----------+
                                        |
                                        v
                            +-----------------------+
                            |  vuln_data_service    |
                            |-----------------------|
                            | exact_cpe_index       |
                            | version_range_index   |
                            | O(1) CPE lookup       |
                            +-----------------------+
```

### Architectural Strengths

- Clear attempt at layered separation.
- Scanners are mostly independent from backend orchestration.
- Scan results are structured JSON, which makes downstream correlation feasible.
- The queue model uses database-backed durability.
- Vulnerability indexing is correctly placed behind a service boundary.

### Architectural Weaknesses

- `va_manager/executor/scan_executor.py` relies on runtime `sys.path.insert(...)` instead of proper package installation or dependency injection.
- `va_manager` is both orchestration layer and application container, but it lacks a cohesive bootstrap and dependency-management strategy.
- The vulnerability engine is coupled directly into scan completion, so a correlation failure can fail an otherwise successful scan job.

## 3. Codebase Structure Review

### Strengths

- The repository layout is understandable.
- Scanner boundaries are clear.
- `va_manager` has meaningful internal subpackages:
  - `models`
  - `services`
  - `queue`
  - `executor`
  - `workers`
  - `api`
  - `vulnerability_engine`
  - `vuln_data_service`

### Structural Concerns

1. **Backend packaging is incomplete**
   - Scanners are package-managed with `pyproject.toml`.
   - `va_manager` is not packaged similarly.
   - This creates deployment inconsistency.

2. **Dynamic import path mutation**
   - `scan_executor.py` inserts repo paths into `sys.path`.
   - This is fragile, environment-dependent, and hard to test.

3. **Generated artifacts present in working tree**
   - `__pycache__` directories are present under scanners and `va_manager`.
   - This is a repository hygiene and reproducibility issue.

4. **Tracked environment file pattern**
   - `.gitignore` explicitly allows `va_manager/.env`.
   - That is dangerous because it normalizes committing runtime secrets.

5. **Dead or stale code paths**
   - `scanners/web_scanner/web_scanner/plugins/nikto/runner.py` still uses JSON output even though the active plugin path uses XML.
   - `va_manager/vulnerability_engine/database/queries.py` appears largely bypassed by the newer in-memory index architecture.

### Assessment

The structure is conceptually good, but operational discipline is still immature. The codebase needs a stronger packaging model, clearer dependency ownership, and better cleanup of stale code.

## 4. Scanner Integration Analysis

### Current Integration Model

Scanners return structured JSON, and `va_manager/executor/scan_executor.py` adapts them to a common orchestration path:

- Network: `ScannerEngine(...).run()`
- OS: `scan_host(...)`
- Web: `start_scan(...)`

### Strengths

- The executor isolates scanner dispatch logic.
- Results are JSON-like dicts, which supports downstream persistence and analysis.
- The scanners themselves remain mostly untouched by orchestration concerns.

### Weaknesses

1. **No formal scanner interface**
   - There is no shared protocol or abstract base class.
   - `va_manager` relies on scanner-specific knowledge.

2. **Result format inconsistency**
   - Network scanner returns ports and services.
   - OS scanner returns nested `system` inventory.
   - Web scanner returns `findings/errors`.
   - The analyzer compensates with heuristic extraction rather than consuming a canonical schema.

3. **Config pass-through is weakly validated**
   - Arbitrary `config` dicts are accepted and interpreted ad hoc.

4. **Web scanner stream interface loses errors**
   - Streaming yields findings only.
   - Tool errors are logged and discarded from the generator interface.

5. **No versioned result contract**
   - There is no schema version in `ScanResult.result_json`.
   - Contract evolution will be brittle.

### Overall Assessment

Scanner integration works, but it is adapter-driven rather than contract-driven. That is acceptable early on, but it will become a serious maintainability problem as more scanners and report consumers are added.

## 5. Vulnerability Engine Analysis

### Current Design

The `vulnerability_engine` performs:
- feed retrieval
- local storage
- software extraction
- heuristic CPE mapping
- CVE correlation
- CVSS/risk translation
- final report generation

### Strengths

- Logical decomposition into feeds, database, correlation, scoring, and reporting.
- Separation between raw scan collection and vulnerability analysis.
- Local storage schema is sufficient for basic CVE metadata, CPEs, CVSS, and references.
- Version-range data is now preserved and indexed.

### Key Weaknesses

1. **Feed synchronization is incomplete**
   - `fetch_cves()` pulls one NVD page only.
   - There is no pagination loop, incremental sync, resumption, or filtering by change window.
   - Result: the local vulnerability database is incomplete by design.

2. **No feed provenance or freshness tracking**
   - There is no metadata table for:
     - sync time
     - page state
     - source version
     - last successful import

3. **Weak normalization fidelity**
   - CPE handling is heuristic.
   - Version matching logic is simplified and does not model ecosystem-specific versioning semantics.

4. **Correlation quality is limited**
   - `cpe_mapper.py` maps a small set of names to guessed vendor/product tuples.
   - This will create both false negatives and false positives.

5. **Report generation is thin**
   - `report_builder.py` is effectively a pass-through.
   - No enrichment, grouping, deduplication strategy by root cause, or evidence traceability.

6. **Risk scoring is naive**
   - `risk_engine.py` raises severity based on a short list of ports/services.
   - That is easy to understand, but not robust enough for real prioritization.

7. **Vulnerability analysis runs inline with job completion**
   - If correlation fails, the scan job is marked failed even if the scanner itself succeeded.
   - This is the wrong failure boundary.

### Design Quality Assessment

The engine is promising but still heuristic-heavy. It is appropriate for a prototype, not for trusted vulnerability intelligence.

## 6. Vulnerability Data Service Analysis

### What It Does Well

The `vuln_data_service` introduces the right optimization boundary:

- exact CPE index:
  - `cpe_uri -> tuple[cve_ids]`
- version range index:
  - `vendor:product -> tuple[VersionRange, ...]`

This is a good design because:
- exact CPE lookup is O(1)
- version-range lookup is O(1) to key lookup plus O(ranges_for_product)
- data is loaded once into memory
- the correlation engine no longer needs per-CPE database queries

### Strengths

- Good use of immutable tuples for compact storage.
- Reasonable deduplication in index building.
- Thread-safe store with reload support.
- Clear separation between:
  - database loading
  - index building
  - in-memory storage
  - lookup service

### Critical Design Problem

`analyze_scan_results()` currently calls:

```python
vulnerability_data_service.initialize(db)
```

on every analysis. That means the full vulnerability index is rebuilt for every scan job, defeating the purpose of an in-memory acceleration layer.

Impact:
- large startup overhead per scan
- redundant DB reads
- memory churn
- poor worker throughput

This is the single biggest performance flaw in the current backend.

### Version Range Matching Review

The new range index is directionally correct, but the matcher is simplistic:

- tokenization uses `\d+|[a-z]+`
- no distro-specific handling
- no epoch handling
- no revision/release semantics
- no packaging ecosystem awareness

Examples it may mishandle:
- `1:2.3.4-1ubuntu2`
- `7.2p2`
- `1.1.1f`
- `2.4.49-rc1`

### Memory Usage Considerations

The current index model is acceptable for moderate CVE datasets, but it will become expensive if:
- the vulnerability DB grows to full NVD scale
- the same process hosts API, workers, and feed loading

No memory budget, index compaction strategy, or lazy loading mechanism exists yet.

## 7. Performance Analysis

### Likely Bottlenecks

1. **Full vulnerability index rebuild per scan**
   - Most serious current bottleneck.

2. **Feed ingestion strategy**
   - CVEs are upserted row by row.
   - Relationship lists are replaced wholesale.
   - This will become slow at scale.

3. **Worker transaction scope**
   - Result persistence and vulnerability analysis occur in the completion path.
   - If correlation or index initialization is slow, job completion latency expands sharply.

4. **Repeated vulnerability object loading during matching**
   - `_load_vulnerabilities()` caches within a scan, which helps.
   - But the engine still queries the DB for vulnerability objects instead of indexing richer in-memory vulnerability records.

5. **Web scanner subprocess model**
   - Each scan spawns external tools.
   - Good for isolation, but expensive under large scan volumes.

6. **Network scanner concurrency model**
   - Threaded port scanning is fine for one asset.
   - It does not scale naturally to fleet-level scanning without rate controls and orchestration.

### Scalability Estimate

Current design likely works for:
- tens to low hundreds of assets
- low to moderate concurrent jobs
- moderate local CVE datasets

Current design will struggle with:
- thousands of assets
- large recurring credentialed scans
- full NVD-scale ingestion without incremental sync
- multiple worker processes rebuilding indexes repeatedly

## 8. Security Review

### Critical Findings

1. **Plaintext credentials in the database**
   - `Asset.password` stores raw credentials.
   - There is no encryption-at-rest strategy.

2. **Plaintext credentials exposed over the API**
   - `AssetResponse` includes `username` and `password`.
   - `GET /api/v1/assets` appears to return stored credentials to any authenticated caller.

3. **Tracked `.env` pattern**
   - `.gitignore` explicitly permits `va_manager/.env`.
   - The `.env` file contains DB credentials and a secret key placeholder.
   - This encourages committing secrets.

4. **Weak SSH trust model**
   - `paramiko.AutoAddPolicy()` accepts host keys automatically.
   - This is vulnerable to man-in-the-middle attacks.

5. **OS scanner CLI exposes credentials in process args**
   - `--password` on the command line leaks into shell history and process lists.

### High-Risk Findings

6. **JWT validation is minimal**
   - Signature validation exists.
   - There is no issuer, audience, tenant, or role validation.

7. **No authorization model**
   - API checks authentication only.
   - No ownership or tenancy boundaries are enforced for assets, jobs, or results.

8. **Startup schema creation in the app process**
   - `Base.metadata.create_all(...)` in API startup is not safe as a deployment migration strategy.

9. **External scan tools run directly**
   - Web scanner launches `nikto` and `nuclei` via subprocess.
   - Targets are passed as argv, which avoids shell injection, but tool output and resource usage remain unbounded.

10. **Raw sensitive system data is collected and stored**
   - OS scanner captures:
     - `/etc/sudoers`
     - users
     - services
     - cron
     - file permissions
   - There is no redaction, classification, or access control around these stored results.

### Medium-Risk Findings

11. **Network exposure assumptions**
   - API assumes HTTPS, but operational hardening is incomplete.
   - `HTTPSRedirectMiddleware` is not a substitute for hardened reverse-proxy deployment.

12. **No rate limiting or abuse controls**
   - The API can queue scan jobs without visible rate controls.

## 9. Code Quality Review

### Strengths

- Generally readable file organization.
- Most modules have docstrings.
- Type hints are used broadly.
- Pydantic models are used in the web scanner and API.
- Logging is present in several critical areas.

### Weaknesses

1. **Inconsistent rigor across modules**
   - Some areas use structured models.
   - Others use loose `dict[str, Any]` payloads.

2. **Dead and duplicated code**
   - Nikto runner duplication.
   - Old DB query helpers partly bypassed by the index service.

3. **Loose schemas**
   - Scanner outputs are not validated at persistence boundaries.
   - `ScanResult.result_json` is fully untyped JSON.

4. **Error handling quality is uneven**
   - Some functions degrade gracefully.
   - Others swallow useful context or convert failures into generic strings.

5. **Logging is not consistently structured**
   - No request IDs, job IDs everywhere, or correlation IDs.

6. **No tests found**
   - No unit tests
   - No integration tests
   - No fixture-based feed normalization tests
   - No API tests

### Technical Debt Summary

- dynamic imports
- no backend packaging
- stale helper code
- heuristic correlation logic
- missing schema versioning
- weak operational instrumentation

## 10. Reliability & Fault Tolerance

### What Works Well

- The queue uses `FOR UPDATE SKIP LOCKED`, which is the correct pattern for PostgreSQL multi-worker safety.
- Jobs move through `queued -> running -> completed/failed`.
- Scan results are persisted, giving partial auditability.

### Reliability Gaps

1. **Scan success is coupled to vuln-analysis success**
   - A vulnerability-engine failure can fail the job after the scanner already succeeded.

2. **No retry strategy**
   - No retry policy for:
     - transient feed failures
     - scanner timeouts
     - DB deadlocks
     - external tool failures

3. **No poison-job handling**
   - Repeatedly failing jobs are not quarantined.

4. **No worker shutdown coordination**
   - Infinite worker loop has no graceful stop behavior.

5. **No feed resilience**
   - Requests use `raise_for_status()` but no retry, backoff, caching, or pagination checkpointing.

6. **No schema migration path**
   - `create_all()` is not enough for evolving production data.

## 11. Scalability Analysis

### Network Scale

`pscan` is a per-target threaded scanner. It can handle moderate host scans, but the platform lacks:
- scheduling controls
- rate limiting
- distributed coordination
- per-network concurrency caps

### Asset Scale

The job model can represent many assets, but operationally the system is not ready for thousands of assets because:
- no pagination in core API endpoints
- no index warmup strategy
- no work partitioning
- no observability for queue depth or worker saturation

### Vulnerability Data Scale

The vulnerability model can store a large dataset, but current ingestion and reload behavior will become a bottleneck at full-feed scale.

### API Scale

The FastAPI layer is currently thin and should scale reasonably for metadata operations, but it lacks:
- caching
- pagination
- async DB access
- job admission control
- response filtering

## 12. Recommendations

### Critical Improvements

1. Remove credentials from API responses immediately.
2. Encrypt stored secrets or move them to a vault/KMS-backed secret store.
3. Stop tracking `va_manager/.env`; replace with `.env.example`.
4. Remove `AutoAddPolicy()` or make trust-on-first-use explicit and configurable.
5. Decouple vulnerability analysis from scanner job success.
6. Fix `vulnerability_data_service.initialize(db)` so it does not rebuild the index on every scan.

### Architecture Improvements

1. Define a formal scanner interface or protocol.
2. Introduce canonical scan-result schemas with versioning.
3. Package `va_manager` properly with its own project metadata.
4. Eliminate `sys.path.insert(...)` by using real package dependencies or a workspace bootstrap.
5. Split raw scan result persistence from derived vulnerability-report persistence.

### Performance Improvements

1. Warm the vulnerability index once per process and reload only after feed updates.
2. Add feed pagination and incremental sync.
3. Use bulk ingestion/upsert strategies for CVE data.
4. Consider indexing richer vulnerability objects in memory, not just CVE IDs.
5. Batch vulnerability object loading after full software extraction rather than per item.

### Security Improvements

1. Add secret encryption and redaction.
2. Validate JWT issuer, audience, and tenant context.
3. Add per-user or per-tenant authorization on assets, jobs, and results.
4. Protect sensitive OS scan outputs with access classification.
5. Add request size and job submission controls.
6. Separate example config from runtime secret files.

### Developer Experience Improvements

1. Add unit and integration tests.
2. Add Alembic migrations.
3. Add structured logging and metrics.
4. Add schema docs for scanner outputs and stored results.
5. Remove stale code paths and duplicate helpers.

## 13. Future Roadmap

Recommended roadmap order:

### Near Term

- stabilize contracts between scanners and `va_manager`
- harden secrets and API auth
- introduce migrations
- add test coverage
- fix index rebuild behavior

### Mid Term

- plugin registration for scanners
- incremental feed update scheduler
- richer vulnerability normalization
- tenant-aware authorization
- queue metrics and worker observability

### Longer Term

- distributed worker architecture
- remote scanner execution pools
- exploit intelligence integration
- asset grouping and policy-driven scanning
- enterprise reporting and remediation workflows

## 14. Final Verdict

Swan VA has a sound conceptual direction and a better-than-average prototype architecture. The scanner/orchestrator/intelligence split is a strong foundation, and the introduction of `vuln_data_service` is exactly the kind of architectural move that enables future scale.

However, the current implementation is **not production-ready**.

### Maturity Assessment

- Architecture: **promising**
- Code quality: **mixed**
- Security posture: **weak**
- Operational readiness: **low**
- Scalability readiness: **low to moderate after fixes**

### Immediate Next Steps

1. Fix secrets and credential exposure.
2. Stop rebuilding the vulnerability index per scan.
3. Add migrations and tests.
4. Formalize scanner result schemas.
5. Decouple scan execution from vulnerability post-processing.

If those issues are addressed, Swan VA can move from prototype to a credible internal platform. Without them, growth will amplify both operational risk and false confidence in scan results.
