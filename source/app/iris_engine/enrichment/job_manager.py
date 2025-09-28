"""
Enrichment Job Management System
Handles job status tracking, progress updates, and result storage
"""

import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from enum import Enum

log = logging.getLogger(__name__)


class JobStatus(Enum):
    """Enrichment job status enumeration"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EnrichmentJob:
    """Represents an enrichment job with all its metadata"""

    def __init__(self, job_id: str, case_id: int, ioc_type: str, ioc_value: str,
                 profile_name: str, user_id: int = None):
        self.job_id = job_id
        self.case_id = case_id
        self.ioc_type = ioc_type
        self.ioc_value = ioc_value
        self.profile_name = profile_name
        self.user_id = user_id
        self.status = JobStatus.QUEUED
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error_message: Optional[str] = None
        self.progress_data: Dict[str, Any] = {}
        self.result_data: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary for serialization"""
        return {
            "job_id": self.job_id,
            "case_id": self.case_id,
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "profile_name": self.profile_name,
            "user_id": self.user_id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "progress_data": self.progress_data,
            "result_data": self.result_data
        }

    def update_status(self, status: JobStatus, progress_data: Dict[str, Any] = None):
        """Update job status and progress"""
        self.status = status

        if status == JobStatus.RUNNING and not self.started_at:
            self.started_at = datetime.utcnow()
        elif status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
            self.completed_at = datetime.utcnow()

        if progress_data:
            self.progress_data.update(progress_data)


class EnrichmentJobManager:
    """
    Manages enrichment job lifecycle and status tracking.
    In production, this would integrate with Redis or database for persistence.
    For now, using in-memory storage with optional file persistence.
    """

    def __init__(self, storage_type: str = "memory"):
        """
        Initialize job manager

        Args:
            storage_type: "memory", "file", or "redis" (future)
        """
        self.storage_type = storage_type
        self._jobs: Dict[str, EnrichmentJob] = {}
        self._job_history: List[Dict[str, Any]] = []

    def start_job(self, job_id: str, case_id: int, ioc_type: str, ioc_value: str,
                  profile_name: str, user_id: int = None) -> EnrichmentJob:
        """
        Create and start tracking a new enrichment job

        Args:
            job_id: Unique job identifier
            case_id: Case ID
            ioc_type: IOC type
            ioc_value: IOC value
            profile_name: Profile name
            user_id: User ID (optional)

        Returns:
            EnrichmentJob instance
        """
        job = EnrichmentJob(
            job_id=job_id,
            case_id=case_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            profile_name=profile_name,
            user_id=user_id
        )

        self._jobs[job_id] = job
        log.info(f"Started tracking job {job_id} for {ioc_type}:{ioc_value}")

        return job

    def get_job(self, job_id: str) -> Optional[EnrichmentJob]:
        """Get job by ID"""
        return self._jobs.get(job_id)

    def update_job_status(self, job_id: str, status: str, progress_data: Dict[str, Any] = None) -> bool:
        """
        Update job status and progress

        Args:
            job_id: Job ID
            status: New status string
            progress_data: Progress metadata

        Returns:
            True if successful, False if job not found
        """
        job = self._jobs.get(job_id)
        if not job:
            log.warning(f"Job {job_id} not found for status update")
            return False

        try:
            job_status = JobStatus(status)
            job.update_status(job_status, progress_data)
            log.debug(f"Updated job {job_id} status to {status}")
            return True

        except ValueError:
            log.error(f"Invalid status '{status}' for job {job_id}")
            return False

    def complete_job(self, job_id: str, result_data: Dict[str, Any]) -> bool:
        """
        Mark job as completed with result data

        Args:
            job_id: Job ID
            result_data: Job results

        Returns:
            True if successful
        """
        job = self._jobs.get(job_id)
        if not job:
            log.warning(f"Job {job_id} not found for completion")
            return False

        job.update_status(JobStatus.COMPLETED)
        job.result_data = result_data

        # Move to history for cleanup
        self._job_history.append(job.to_dict())

        log.info(f"Completed job {job_id}")
        return True

    def fail_job(self, job_id: str, error_message: str) -> bool:
        """
        Mark job as failed with error message

        Args:
            job_id: Job ID
            error_message: Error description

        Returns:
            True if successful
        """
        job = self._jobs.get(job_id)
        if not job:
            log.warning(f"Job {job_id} not found for failure")
            return False

        job.update_status(JobStatus.FAILED)
        job.error_message = error_message

        # Move to history
        self._job_history.append(job.to_dict())

        log.warning(f"Failed job {job_id}: {error_message}")
        return True

    def get_case_jobs(self, case_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get all jobs for a specific case

        Args:
            case_id: Case ID
            limit: Maximum number of jobs to return

        Returns:
            List of job dictionaries
        """
        case_jobs = []

        # Active jobs
        for job in self._jobs.values():
            if job.case_id == case_id:
                case_jobs.append(job.to_dict())

        # Historical jobs
        for job_data in self._job_history:
            if job_data.get("case_id") == case_id:
                case_jobs.append(job_data)

        # Sort by creation time (newest first) and limit
        case_jobs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return case_jobs[:limit]

    def get_user_jobs(self, user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get all jobs for a specific user

        Args:
            user_id: User ID
            limit: Maximum number of jobs to return

        Returns:
            List of job dictionaries
        """
        user_jobs = []

        # Active jobs
        for job in self._jobs.values():
            if job.user_id == user_id:
                user_jobs.append(job.to_dict())

        # Historical jobs
        for job_data in self._job_history:
            if job_data.get("user_id") == user_id:
                user_jobs.append(job_data)

        # Sort by creation time (newest first) and limit
        user_jobs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return user_jobs[:limit]

    def get_jobs_for_case(self, case_id: int) -> List['EnrichmentJob']:
        """Get all jobs for a case (returns job objects for GraphQL)"""
        jobs = []
        for job in self._jobs.values():
            if job.case_id == case_id:
                jobs.append(job)
        return jobs

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running job"""
        job = self._jobs.get(job_id)
        if not job:
            return False

        if job.status in [JobStatus.QUEUED, JobStatus.RUNNING]:
            job.update_status(JobStatus.CANCELLED)
            # Move to history
            self._job_history.append(job.to_dict())
            log.info(f"Cancelled job {job_id}")
            return True

        return False

    def get_running_jobs(self) -> List[Dict[str, Any]]:
        """Get all currently running jobs"""
        running_jobs = []

        for job in self._jobs.values():
            if job.status == JobStatus.RUNNING:
                running_jobs.append(job.to_dict())

        return running_jobs

    def cleanup_old_jobs(self, max_age_hours: int = 24) -> int:
        """
        Clean up old completed/failed jobs from active memory

        Args:
            max_age_hours: Maximum age in hours before cleanup

        Returns:
            Number of jobs cleaned up
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        cleaned_count = 0

        jobs_to_remove = []

        for job_id, job in self._jobs.items():
            if (job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED] and
                job.completed_at and job.completed_at < cutoff_time):

                # Move to history if not already there
                job_dict = job.to_dict()
                if job_dict not in self._job_history:
                    self._job_history.append(job_dict)

                jobs_to_remove.append(job_id)

        # Remove from active jobs
        for job_id in jobs_to_remove:
            del self._jobs[job_id]
            cleaned_count += 1

        if cleaned_count > 0:
            log.info(f"Cleaned up {cleaned_count} old enrichment jobs")

        return cleaned_count

    def get_job_statistics(self) -> Dict[str, Any]:
        """Get job statistics for monitoring"""
        stats = {
            "active_jobs": len(self._jobs),
            "historical_jobs": len(self._job_history),
            "status_breakdown": {status.value: 0 for status in JobStatus}
        }

        # Count active job statuses
        for job in self._jobs.values():
            stats["status_breakdown"][job.status.value] += 1

        # Count historical job statuses
        for job_data in self._job_history:
            status = job_data.get("status", "unknown")
            if status in stats["status_breakdown"]:
                stats["status_breakdown"][status] += 1

        return stats

    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a running job (mark as cancelled)

        Args:
            job_id: Job ID to cancel

        Returns:
            True if successful
        """
        job = self._jobs.get(job_id)
        if not job:
            log.warning(f"Job {job_id} not found for cancellation")
            return False

        if job.status not in [JobStatus.QUEUED, JobStatus.RUNNING]:
            log.warning(f"Job {job_id} cannot be cancelled (status: {job.status.value})")
            return False

        job.update_status(JobStatus.CANCELLED)
        log.info(f"Cancelled job {job_id}")
        return True


# Global job manager instance
_job_manager = None


def get_job_manager() -> EnrichmentJobManager:
    """Get the global job manager instance"""
    global _job_manager
    if _job_manager is None:
        _job_manager = EnrichmentJobManager()
    return _job_manager