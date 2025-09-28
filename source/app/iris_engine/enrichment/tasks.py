"""
IOC Enrichment Celery Tasks
Handles async enrichment jobs with IRIS integration
"""

import logging
import uuid
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

from celery import Task
from celery.signals import task_prerun

from app import app, db
from app.datamgmt.case.case_db import get_case
from app.iris_engine.utils.tracker import track_activity

from .profiles import get_profile
from .sources import SOURCES
from .normalizer import EnrichmentNormalizer
from .markdown_renderer import MarkdownRenderer
from .job_manager import get_job_manager
from .storage import get_storage_manager
from .config import (
    get_enrichment_config,
    get_enrichment_cache,
    get_rate_limiter,
    get_retry_handler,
)

log = logging.getLogger(__name__)


class EnrichmentTask(Task):
    """Base class for enrichment tasks with proper context management"""

    def __call__(self, *args, **kwargs):
        with app.app_context():
            return self.run(*args, **kwargs)


@task_prerun.connect
def enrichment_task_prerun(*args, **kwargs):
    """Dispose DB connections before task execution"""
    db.engine.dispose()


def run_ioc_enrichment(case_id: int, ioc_type: str, ioc_value: str,
                      profile_name: str, user_id: int = None,
                      job_id: str = None) -> Dict[str, Any]:
    """
    Main enrichment task that processes an IOC through the specified profile

    Args:
        case_id: ID of the case to enrich
        ioc_type: Type of IOC (ip, domain, hash, etc.)
        ioc_value: The IOC value to enrich
        profile_name: Name of the enrichment profile to use
        user_id: ID of user requesting enrichment (optional)
        job_id: Unique job identifier (auto-generated if not provided)

    Returns:
        Dict with job results and metadata
    """
    if not job_id:
        job_id = str(uuid.uuid4())

    # Initialize service singletons
    job_manager = get_job_manager()
    storage_manager = get_storage_manager()
    config = get_enrichment_config()
    cache = get_enrichment_cache()
    rate_limiter = get_rate_limiter()
    retry_handler = get_retry_handler()

    try:
        # Start job tracking
        job_manager.start_job(job_id, case_id, ioc_type, ioc_value, profile_name, user_id)
        log.info(f"Starting enrichment job {job_id} for {ioc_type}:{ioc_value} with profile {profile_name}")

        # Validate inputs
        case = get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        profile = get_profile(profile_name)
        if not profile:
            raise ValueError(f"Profile '{profile_name}' not found")

        if not profile.supports_ioc_type(ioc_type):
            raise ValueError(f"Profile '{profile_name}' does not support IOC type '{ioc_type}'")

        # Update job status
        job_manager.update_job_status(job_id, "running", {"phase": "collecting_data"})

        # Execute enrichment sources
        results = {}
        total_sources = max(len(profile.sources), 1)
        completed_sources = 0

        for source_name in profile.sources:
            try:
                log.info(f"Job {job_id}: Fetching data from {source_name}")

                # Update progress
                progress = (completed_sources / total_sources) * 100
                job_manager.update_job_status(job_id, "running", {
                    "phase": "collecting_data",
                    "current_source": source_name,
                    "progress": progress
                })

                if source_name not in SOURCES:
                    log.warning(f"Job {job_id}: Source {source_name} not implemented")
                    results[source_name] = {"_error": f"Source {source_name} not implemented"}
                    completed_sources += 1
                    continue

                # Check cache first
                cached_result = cache.get(source_name, ioc_type, ioc_value)
                if cached_result:
                    results[source_name] = dict(cached_result)
                    results[source_name]["_cached"] = True
                    log.info(f"Job {job_id}: Using cached data for {source_name}")
                    completed_sources += 1
                    continue

                # Enforce rate limiting
                if not rate_limiter.is_allowed(source_name):
                    retry_after = rate_limiter.get_retry_after(source_name)
                    error_msg = (
                        f"Rate limit exceeded for {source_name}. "
                        f"Try again in {retry_after:.0f}s"
                    )
                    results[source_name] = {"_error": error_msg}
                    log.warning(f"Job {job_id}: {error_msg}")
                    completed_sources += 1
                    continue

                source_class = SOURCES[source_name]
                source_config = config.get_source_config(source_name)
                source = source_class(config=source_config)

                max_attempts = 1
                if config.retry_enabled:
                    max_attempts = max(config.max_retries, 1)

                attempt = 0
                source_result: Dict[str, Any] = {}

                while attempt < max_attempts:
                    attempt += 1
                    try:
                        timeout = min(profile.timeout_s, config.max_timeout)
                        source_result = source.fetch(ioc_type, ioc_value, timeout)

                        if "_error" in source_result:
                            raise RuntimeError(source_result["_error"])

                        cache.set(source_name, ioc_type, ioc_value, source_result, ttl=profile.cache_ttl)
                        log.info(f"Job {job_id}: Successfully fetched data from {source_name}")
                        break

                    except Exception as fetch_error:
                        error_message = str(fetch_error)
                        should_retry = retry_handler.should_retry(attempt, fetch_error)

                        if should_retry and attempt < max_attempts:
                            delay = retry_handler.get_retry_delay(attempt)
                            log.warning(
                                f"Job {job_id}: Error from {source_name} (attempt {attempt}/{max_attempts}): "
                                f"{error_message}. Retrying in {delay:.1f}s"
                            )
                            time.sleep(delay)
                            continue

                        source_result = {"_error": error_message}
                        log.error(f"Job {job_id}: Failed to fetch {source_name}: {error_message}")
                        break

                results[source_name] = source_result
                completed_sources += 1

        # Update job status for processing
        job_manager.update_job_status(job_id, "running", {
            "phase": "processing_data",
            "progress": 75
        })

        # Normalize results
        normalizer = EnrichmentNormalizer()
        normalized_data = normalizer.normalize(ioc_type, ioc_value, results)

        log.info(f"Job {job_id}: Data normalized, risk score: {normalized_data['summary']['risk_score']}")

        # Update job status for artifact creation
        job_manager.update_job_status(job_id, "running", {
            "phase": "creating_artifacts",
            "progress": 85
        })

        # Store raw data as artifacts using the storage manager
        sanitized_results: Dict[str, Dict[str, Any]] = {}
        for source_name, source_data in results.items():
            if isinstance(source_data, dict):
                cleaned = dict(source_data)
                cleaned.pop("_cached", None)
                sanitized_results[source_name] = cleaned
            else:
                sanitized_results[source_name] = source_data

        try:
            artifact_ids = storage_manager.create_enrichment_artifacts_batch(
                case_id=case_id,
                enrichment_results=sanitized_results,
                ioc_value=ioc_value,
                profile_name=profile_name
            )
        except Exception as storage_error:
            log.error(
                f"Job {job_id}: Error while creating enrichment artifacts: {storage_error}"
            )
            artifact_ids = []

        artifact_ids = [str(aid) for aid in artifact_ids]

        # Update job status for note creation
        job_manager.update_job_status(job_id, "running", {
            "phase": "creating_note",
            "progress": 92
        })

        # Generate markdown report
        renderer = MarkdownRenderer()
        markdown_content = renderer.render_enrichment_report(
            normalized_data,
            profile_name,
            artifact_ids
        )

        # Create or update case note
        note_title = f"IOC Enrichment: {ioc_value}"
        enrichment_block = _wrap_report_with_run_metadata(markdown_content, profile_name)
        note_id = upsert_enrichment_note(case_id, note_title, enrichment_block)

        # Track activity
        if user_id:
            track_activity(f"completed IOC enrichment for {ioc_type}:{ioc_value} using profile {profile_name}")

        # Complete job
        job_result = {
            "job_id": job_id,
            "status": "completed",
            "case_id": case_id,
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "profile_name": profile_name,
            "note_id": note_id,
            "artifact_ids": artifact_ids,
            "risk_score": normalized_data['summary']['risk_score'],
            "risk_level": normalized_data['summary']['risk_level'],
            "sources_succeeded": len(normalized_data['metadata']['sources_succeeded']),
            "sources_failed": len(normalized_data['metadata']['sources_failed']),
            "completed_at": datetime.utcnow().isoformat()
        }

        job_manager.complete_job(job_id, job_result)
        job_manager.update_job_status(job_id, "completed", {"progress": 100})

        log.info(f"Job {job_id}: Enrichment completed successfully")
        return job_result

    except Exception as e:
        error_msg = str(e)
        log.error(f"Job {job_id}: Enrichment failed: {error_msg}")

        # Mark job as failed
        job_manager.fail_job(job_id, error_msg)

        return {
            "job_id": job_id,
            "status": "failed",
            "error": error_msg,
            "case_id": case_id,
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "profile_name": profile_name,
            "failed_at": datetime.utcnow().isoformat()
        }


def upsert_enrichment_note(case_id: int, note_title: str, markdown_content: str) -> Optional[int]:
    """Create or update an enrichment note in the case."""

    try:
        storage_manager = get_storage_manager()
        note_result = storage_manager.upsert_enrichment_note(
            case_id=case_id,
            title=note_title,
            content=markdown_content,
            update_mode="prepend",
        )

        if not note_result:
            log.error(f"Failed to upsert enrichment note '{note_title}' for case {case_id}")
            return None

        if hasattr(note_result, "note_id"):
            return note_result.note_id

        return note_result


def batch_ioc_enrichment(case_id: int, ioc_list: List[Dict[str, str]],
                        profile_name: str, user_id: int = None) -> List[str]:
    """
    Process multiple IOCs in batch

    Args:
        case_id: Case ID
        ioc_list: List of dicts with 'type' and 'value' keys
        profile_name: Enrichment profile to use
        user_id: User requesting the enrichment

    Returns:
        List of job IDs for tracking
    """
    job_ids: List[str] = []

    for ioc_data in ioc_list:
        job_id = str(uuid.uuid4())

        try:
            run_ioc_enrichment(
                case_id=case_id,
                ioc_type=ioc_data['type'],
                ioc_value=ioc_data['value'],
                profile_name=profile_name,
                user_id=user_id,
                job_id=job_id
            )
            job_ids.append(job_id)
        except Exception as e:
            log.error(f"Failed to process enrichment for {ioc_data}: {str(e)}")

    return job_ids


def _wrap_report_with_run_metadata(report: str, profile_name: str) -> str:
    """Attach run metadata to the generated markdown report."""

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    header = (
        f"### Enrichment Run — {timestamp}\n"
        f"*Profile:* **{profile_name}**\n\n"
    )
    return f"{header}{report}\n\n---"


# Celery task decorators would be applied here in the actual implementation
# For now, these are regular functions that can be called directly or via Celery
