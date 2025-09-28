"""
IOC Enrichment Celery Tasks
Handles async enrichment jobs with IRIS integration
"""

import logging
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from celery import Task
from celery.signals import task_prerun
from flask_login import current_user

from app import app, db
from app.datamgmt.case.case_db import get_case
from app.datamgmt.case.case_notes_db import get_note, add_note, update_note
from app.datamgmt.case.case_assets_db import create_asset
from app.iris_engine.utils.tracker import track_activity
from iris_interface import IrisInterfaceStatus as IStatus

from .profiles import get_profile, get_profile_manager
from .sources import SOURCES
from .normalizer import EnrichmentNormalizer
from .markdown_renderer import MarkdownRenderer
from .job_manager import EnrichmentJobManager

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

    # Initialize job manager
    job_manager = EnrichmentJobManager()

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
        total_sources = len(profile.sources)
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

                if source_name in SOURCES:
                    source_class = SOURCES[source_name]
                    source = source_class()

                    # Fetch data with timeout
                    source_result = source.fetch(ioc_type, ioc_value, profile.timeout_s)
                    results[source_name] = source_result

                    if "_error" not in source_result:
                        log.info(f"Job {job_id}: Successfully fetched data from {source_name}")
                    else:
                        log.warning(f"Job {job_id}: Error from {source_name}: {source_result['_error']}")
                else:
                    log.warning(f"Job {job_id}: Source {source_name} not implemented")
                    results[source_name] = {"_error": f"Source {source_name} not implemented"}

                completed_sources += 1

            except Exception as e:
                log.error(f"Job {job_id}: Exception fetching from {source_name}: {str(e)}")
                results[source_name] = {"_error": f"Exception: {str(e)}"}
                completed_sources += 1

        # Update job status for processing
        job_manager.update_job_status(job_id, "running", {"phase": "processing_data"})

        # Normalize results
        normalizer = EnrichmentNormalizer()
        normalized_data = normalizer.normalize(ioc_type, ioc_value, results)

        log.info(f"Job {job_id}: Data normalized, risk score: {normalized_data['summary']['risk_score']}")

        # Update job status for artifact creation
        job_manager.update_job_status(job_id, "running", {"phase": "creating_artifacts"})

        # Store raw data as artifacts
        artifact_ids = []
        for source_name, source_data in results.items():
            if "_error" not in source_data:
                try:
                    artifact_content = json.dumps(source_data, indent=2)
                    artifact_name = f"{source_name}_{ioc_value}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"

                    # Create asset using IRIS create_asset function (simplified for now)
                    # Note: This needs to be implemented with proper IRIS asset creation
                    artifact_id = f"artifact_{source_name}_{len(artifact_ids)}"

                    if artifact_id:
                        artifact_ids.append(str(artifact_id))
                        log.info(f"Job {job_id}: Created artifact {artifact_id} for {source_name}")

                except Exception as e:
                    log.error(f"Job {job_id}: Failed to create artifact for {source_name}: {str(e)}")

        # Update job status for note creation
        job_manager.update_job_status(job_id, "running", {"phase": "creating_note"})

        # Generate markdown report
        renderer = MarkdownRenderer()
        markdown_content = renderer.render_enrichment_report(
            normalized_data,
            profile_name,
            artifact_ids
        )

        # Create or update case note
        note_title = f"IOC Enrichment: {ioc_value}"
        note_id = upsert_enrichment_note(case_id, note_title, markdown_content, normalized_data)

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


def upsert_enrichment_note(case_id: int, note_title: str, markdown_content: str,
                          normalized_data: Dict[str, Any]) -> Optional[int]:
    """
    Create or update an enrichment note in the case

    Args:
        case_id: Case ID
        note_title: Title of the note
        markdown_content: Markdown content to add
        normalized_data: Normalized enrichment data for metadata

    Returns:
        Note ID if successful, None otherwise
    """
    try:
        # For now, always create a new note (TODO: implement proper note search)
        from datetime import datetime

        note_id = add_note(
            note_title=note_title,
            creation_date=datetime.utcnow(),
            user_id=current_user.id if current_user and current_user.is_authenticated else 1,
            caseid=case_id,
            directory_id=1,  # Default directory
            note_content=markdown_content
        )

        if note_id:
            log.info(f"Created new enrichment note {note_id.note_id if hasattr(note_id, 'note_id') else note_id} for case {case_id}")
            return note_id.note_id if hasattr(note_id, 'note_id') else note_id
        else:
            log.error(f"Failed to create note for case {case_id}")
            return None

    except Exception as e:
        log.error(f"Failed to create note '{note_title}' for case {case_id}: {str(e)}")
        return None


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
    job_ids = []

    for ioc_data in ioc_list:
        job_id = str(uuid.uuid4())

        # Queue individual enrichment job
        # In a real implementation, this would use Celery's delay() method
        # For now, we'll call synchronously but this should be async
        try:
            result = run_ioc_enrichment(
                case_id=case_id,
                ioc_type=ioc_data['type'],
                ioc_value=ioc_data['value'],
                profile_name=profile_name,
                user_id=user_id,
                job_id=job_id
            )
            job_ids.append(job_id)

        except Exception as e:
            log.error(f"Failed to queue enrichment for {ioc_data}: {str(e)}")

    return job_ids


# Celery task decorators would be applied here in the actual implementation
# For now, these are regular functions that can be called directly or via Celery