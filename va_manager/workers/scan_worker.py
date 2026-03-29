"""Queue worker for scan execution."""

from __future__ import annotations

import logging
from datetime import datetime
from time import sleep
from typing import Callable

from sqlalchemy.orm import Session

from va_manager.executor.scan_executor import execute
from va_manager.models.asset import Asset
from va_manager.models.scan_job import ScanJob
from va_manager.models.scan_result import ScanResult
from va_manager.queue.job_queue import get_next_job
from va_manager.services.asset_service import AssetNotFoundError
from va_manager.services.report_service import generate_report
from va_manager.services.scan_service import get_scan_asset
from va_manager.vuln_data_service.service import vulnerability_data_service
from va_manager.vulnerability_engine.service import analyze_scan_results

LOGGER = logging.getLogger(__name__)


def process_next_job(session_factory: Callable[[], Session]) -> bool:
    """Process one queued scan job and persist its results.

    Scan execution and vulnerability analysis are deliberately treated as
    separate phases. A completed scan must not be downgraded to `failed` just
    because the post-processing intelligence layer raises an error.
    """

    job_id: int | None = None
    asset_id: int | None = None
    scanner_type: str | None = None
    result: dict[str, object] | None = None

    try:
        claim_db = session_factory()
        try:
            with claim_db.begin():
                job = get_next_job(claim_db)
                if job is None:
                    return False

                job_id = job.id
                scanner_type = job.scanner_type
                asset_id = job.asset_id

                asset = claim_db.get(Asset, asset_id)
                if asset is None:
                    finished_at = datetime.utcnow()
                    job.status = "failed"
                    job.stage = "failed"
                    job.progress = 100
                    job.finished_at = finished_at
                    claim_db.add(
                        ScanResult(
                            scan_job_id=job.id,
                            scanner=job.scanner_type,
                            result_json={"error": f"Asset {asset_id} not found."},
                        )
                    )
                    LOGGER.error("Worker failed job %s because asset %s was not found", job.id, asset_id)
                    return True

                job.status = "running"
                job.stage = "starting"
                job.progress = 5
                job.started_at = datetime.utcnow()
                LOGGER.info(
                    "Worker claimed job %s for asset %s using scanner %s",
                    job.id,
                    asset_id,
                    job.scanner_type,
                )
        finally:
            claim_db.close()

        execution_db = session_factory()
        try:
            job = execution_db.get(ScanJob, job_id)
            asset = None if asset_id is None else get_scan_asset(execution_db, asset_id, job.scanner_type if job else "")
        except AssetNotFoundError:
            asset = None
        finally:
            execution_db.close()

        if job is None or asset is None:
            raise ValueError(f"Job {job_id} or asset {asset_id} could not be reloaded for execution.")

        progress_db = session_factory()
        try:
            with progress_db.begin():
                running_job = progress_db.get(ScanJob, job_id)
                if running_job is not None:
                    running_job.stage = "running"
                    running_job.progress = 50
        finally:
            progress_db.close()

        result = execute(job, asset)

        persist_db = session_factory()
        try:
            with persist_db.begin():
                job = persist_db.get(ScanJob, job_id)
                asset = persist_db.get(Asset, asset_id)
                if job is None or asset is None:
                    raise ValueError(f"Job {job_id} or asset {asset_id} could not be reloaded for completion.")

                job.stage = "processing_results"
                job.progress = 90
                persist_db.add(
                    ScanResult(
                        scan_job_id=job.id,
                        scanner=job.scanner_type,
                        result_json=result,
                    )
                )
                job.status = "scan_completed"
                job.stage = "scan_completed"
        finally:
            persist_db.close()

        LOGGER.info("Worker completed scan execution for job %s on asset %s", job_id, asset_id)

        try:
            analysis_db = session_factory()
            try:
                vulnerability_report = analyze_scan_results(result, analysis_db, scan_id=f"scan_{job_id}")
            finally:
                analysis_db.close()

            completion_db = session_factory()
            try:
                with completion_db.begin():
                    job = completion_db.get(ScanJob, job_id)
                    asset = completion_db.get(Asset, asset_id)
                    if job is None:
                        raise ValueError(f"Job {job_id} could not be reloaded for analysis completion.")
                    if asset is None:
                        raise ValueError(f"Asset {asset_id} could not be reloaded for analysis completion.")

                    job.status = "analysis_completed"
                    job.stage = "analysis_completed"
                    job.progress = 100
                    job.finished_at = datetime.utcnow()
                    completion_db.add(
                        ScanResult(
                            scan_job_id=job.id,
                            scanner="vulnerability_engine",
                            result_json=vulnerability_report,
                        )
                    )

                    # Generate structured report from vulnerability findings
                    findings = vulnerability_report.get("vulnerabilities", [])
                    generate_report(
                        completion_db,
                        job_id,
                        asset_id,
                        asset.target,
                        findings,
                    )
            finally:
                completion_db.close()

            LOGGER.info("Worker completed vulnerability analysis for job %s", job_id)
        except Exception as exc:
            LOGGER.exception("Vulnerability analysis failed for job %s: %s", job_id, exc)
            analysis_failure_db = session_factory()
            try:
                with analysis_failure_db.begin():
                    job = analysis_failure_db.get(ScanJob, job_id)
                    if job is not None:
                        # Preserve successful scan completion while recording
                        # that the optional analysis phase failed.
                        job.status = "scan_completed"
                        job.stage = "analysis_failed"
                        job.progress = 100
                        job.finished_at = datetime.utcnow()
                        analysis_failure_db.add(
                            ScanResult(
                                scan_job_id=job.id,
                                scanner="vulnerability_engine",
                                result_json={
                                    "analysis_status": "failed",
                                    "error": str(exc),
                                },
                            )
                        )
            finally:
                analysis_failure_db.close()

        return True
    except Exception as exc:
        if job_id is not None and scanner_type is not None:
            failure_db = session_factory()
            try:
                with failure_db.begin():
                    job = failure_db.get(ScanJob, job_id)
                    if job is not None:
                        job.status = "failed"
                        job.stage = "failed"
                        job.progress = 100
                        job.finished_at = datetime.utcnow()
                        failure_db.add(
                            ScanResult(
                                scan_job_id=job.id,
                                scanner=scanner_type,
                                result_json={"error": str(exc)},
                            )
                        )
            finally:
                failure_db.close()

        LOGGER.exception("Worker failed job %s: %s", job_id, exc)
        return job_id is not None


def run_worker(session_factory: Callable[[], Session], poll_interval: float = 5.0) -> None:
    """Continuously poll for queued jobs and execute them.

    The worker warms the vulnerability index once during startup so repeated
    jobs reuse the same in-memory lookup tables instead of rebuilding them.
    """

    LOGGER.info("Scan worker started with poll interval %ss", poll_interval)
    _initialize_vulnerability_index(session_factory)
    while True:
        processed = process_next_job(session_factory)
        if not processed:
            sleep(poll_interval)


def _initialize_vulnerability_index(session_factory: Callable[[], Session]) -> None:
    """Warm the in-memory vulnerability index for the current worker process."""

    db = session_factory()
    try:
        vulnerability_data_service.initialize(db)
    finally:
        db.close()
