"""
GraphQL Schema for IOC Enrichment
Provides GraphQL queries and mutations for enrichment operations
"""

import logging
from typing import Dict, Any, List

import graphene
from graphene import ObjectType, String, Int, Float, Boolean, Field, List as GrapheneList, Mutation
from graphene.types.generic import GenericScalar
from flask_login import current_user

from app.iris_engine.enrichment.tasks import run_ioc_enrichment, batch_ioc_enrichment
from app.iris_engine.enrichment.job_manager import get_job_manager
from app.iris_engine.enrichment.profiles import list_profiles, get_profiles_for_ioc_type
from app.iris_engine.enrichment.sources import SOURCES

log = logging.getLogger(__name__)


# GraphQL Object Types
class EnrichmentSourceType(ObjectType):
    """Represents an enrichment source"""
    name = String(required=True, description="Source name")
    ioc_support = GrapheneList(String, description="Supported IOC types")
    description = String(description="Source description")
    configured = Boolean(description="Whether source is properly configured")


class EnrichmentProfileType(ObjectType):
    """Represents an enrichment profile"""
    name = String(required=True, description="Profile name")
    ioc_type = String(required=True, description="Supported IOC type")
    description = String(description="Profile description")
    sources = GrapheneList(String, description="Source names in this profile")
    cache_ttl = Int(description="Cache TTL in seconds")
    timeout_s = Int(description="Timeout in seconds")


class JobStatusType(ObjectType):
    """Represents job status information"""
    job_id = String(required=True, description="Unique job identifier")
    status = String(required=True, description="Job status (queued, running, completed, failed, cancelled)")
    case_id = Int(description="Associated case ID")
    ioc_type = String(description="IOC type being enriched")
    ioc_value = String(description="IOC value being enriched")
    profile_name = String(description="Enrichment profile used")
    user_id = Int(description="User who started the job")
    created_at = String(description="Job creation timestamp")
    updated_at = String(description="Last update timestamp")
    progress = Float(description="Job progress percentage (0-100)")
    current_phase = String(description="Current processing phase")
    current_source = String(description="Currently processing source")
    error_message = String(description="Error message if job failed")


class EnrichmentResultType(ObjectType):
    """Represents enrichment job results"""
    job_id = String(required=True, description="Job identifier")
    status = String(required=True, description="Final job status")
    case_id = Int(description="Case ID")
    ioc_type = String(description="IOC type")
    ioc_value = String(description="IOC value")
    profile_name = String(description="Profile used")
    note_id = String(description="Created note ID")
    artifact_ids = GrapheneList(String, description="Created artifact IDs")
    risk_score = Int(description="Calculated risk score (0-100)")
    risk_level = String(description="Risk level (minimal, low, medium, high, critical)")
    sources_succeeded = Int(description="Number of sources that succeeded")
    sources_failed = Int(description="Number of sources that failed")
    completed_at = String(description="Completion timestamp")
    error = String(description="Error message if failed")


class JobStatisticsType(ObjectType):
    """Job statistics and metrics"""
    active_jobs = Int(description="Number of currently active jobs")
    historical_jobs = Int(description="Total historical jobs")
    status_breakdown = GenericScalar(description="Breakdown by status")


# GraphQL Mutations
class StartEnrichment(Mutation):
    """Start an IOC enrichment job"""

    class Arguments:
        case_id = Int(required=True, description="Case ID to enrich")
        ioc_type = String(required=True, description="IOC type (ip, domain, hash, url)")
        ioc_value = String(required=True, description="IOC value to enrich")
        profile_name = String(required=True, description="Enrichment profile to use")

    Output = JobStatusType

    @staticmethod
    def mutate(root, info, case_id, ioc_type, ioc_value, profile_name):
        """Start an enrichment job"""
        try:
            if not current_user or not current_user.is_authenticated:
                raise Exception("Authentication required")

            log.info(f"Starting enrichment job for {ioc_type}:{ioc_value} via GraphQL")

            # Start the enrichment job
            result = run_ioc_enrichment(
                case_id=case_id,
                ioc_type=ioc_type,
                ioc_value=ioc_value,
                profile_name=profile_name,
                user_id=current_user.id
            )

            # Get job status from job manager
            job_manager = get_job_manager()
            job = job_manager.get_job(result['job_id'])

            if job:
                return JobStatusType(
                    job_id=job.job_id,
                    status=job.status.value,
                    case_id=job.case_id,
                    ioc_type=job.ioc_type,
                    ioc_value=job.ioc_value,
                    profile_name=job.profile_name,
                    user_id=job.user_id,
                    created_at=job.created_at.isoformat() if job.created_at else None,
                    updated_at=job.updated_at.isoformat() if job.updated_at else None,
                    progress=job.progress_data.get('progress', 0) if job.progress_data else 0,
                    current_phase=job.progress_data.get('phase') if job.progress_data else None,
                    current_source=job.progress_data.get('current_source') if job.progress_data else None,
                    error_message=result.get('error')
                )
            else:
                # Return basic info if job not found in manager
                return JobStatusType(
                    job_id=result['job_id'],
                    status=result['status'],
                    case_id=case_id,
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    profile_name=profile_name,
                    user_id=current_user.id,
                    error_message=result.get('error')
                )

        except Exception as e:
            log.error(f"GraphQL enrichment mutation failed: {str(e)}")
            raise Exception(f"Failed to start enrichment: {str(e)}")


class StartBatchEnrichment(Mutation):
    """Start batch IOC enrichment jobs"""

    class Arguments:
        case_id = Int(required=True, description="Case ID to enrich")
        iocs = GenericScalar(required=True, description="List of IOCs with type and value")
        profile_name = String(required=True, description="Enrichment profile to use")

    Output = GrapheneList(String, description="List of job IDs")

    @staticmethod
    def mutate(root, info, case_id, iocs, profile_name):
        """Start batch enrichment jobs"""
        try:
            if not current_user or not current_user.is_authenticated:
                raise Exception("Authentication required")

            log.info(f"Starting batch enrichment for {len(iocs)} IOCs via GraphQL")

            # Start batch enrichment
            job_ids = batch_ioc_enrichment(
                case_id=case_id,
                ioc_list=iocs,
                profile_name=profile_name,
                user_id=current_user.id
            )

            return job_ids

        except Exception as e:
            log.error(f"GraphQL batch enrichment mutation failed: {str(e)}")
            raise Exception(f"Failed to start batch enrichment: {str(e)}")


class CancelEnrichmentJob(Mutation):
    """Cancel a running enrichment job"""

    class Arguments:
        job_id = String(required=True, description="Job ID to cancel")

    Output = Boolean

    @staticmethod
    def mutate(root, info, job_id):
        """Cancel an enrichment job"""
        try:
            if not current_user or not current_user.is_authenticated:
                raise Exception("Authentication required")

            job_manager = get_job_manager()
            success = job_manager.cancel_job(job_id)

            log.info(f"GraphQL job cancellation for {job_id}: {'success' if success else 'failed'}")
            return success

        except Exception as e:
            log.error(f"GraphQL job cancellation failed: {str(e)}")
            raise Exception(f"Failed to cancel job: {str(e)}")


# GraphQL Query Resolvers
class EnrichmentQuery(ObjectType):
    """GraphQL queries for enrichment operations"""

    # Profile and source queries
    enrichment_profiles = GrapheneList(EnrichmentProfileType, description="List all enrichment profiles")
    enrichment_profiles_for_ioc_type = GrapheneList(
        EnrichmentProfileType,
        ioc_type=String(required=True),
        description="Get profiles that support a specific IOC type"
    )
    enrichment_sources = GrapheneList(EnrichmentSourceType, description="List all enrichment sources")

    # Job status queries
    enrichment_job_status = Field(
        JobStatusType,
        job_id=String(required=True),
        description="Get status of a specific enrichment job"
    )
    enrichment_job_result = Field(
        EnrichmentResultType,
        job_id=String(required=True),
        description="Get results of a completed enrichment job"
    )
    enrichment_jobs_for_case = GrapheneList(
        JobStatusType,
        case_id=Int(required=True),
        description="Get all enrichment jobs for a case"
    )
    enrichment_job_statistics = Field(
        JobStatisticsType,
        description="Get enrichment job statistics"
    )

    @staticmethod
    def resolve_enrichment_profiles(root, info):
        """Get all enrichment profiles"""
        try:
            profiles = list_profiles()
            return [
                EnrichmentProfileType(
                    name=profile.name,
                    ioc_type=profile.ioc_type,
                    description=profile.description,
                    sources=profile.sources,
                    cache_ttl=profile.cache_ttl,
                    timeout_s=profile.timeout_s
                )
                for profile in profiles.values()
            ]
        except Exception as e:
            log.error(f"Failed to get enrichment profiles: {str(e)}")
            return []

    @staticmethod
    def resolve_enrichment_profiles_for_ioc_type(root, info, ioc_type):
        """Get profiles for specific IOC type"""
        try:
            profiles = get_profiles_for_ioc_type(ioc_type)
            return [
                EnrichmentProfileType(
                    name=profile.name,
                    ioc_type=profile.ioc_type,
                    description=profile.description,
                    sources=profile.sources,
                    cache_ttl=profile.cache_ttl,
                    timeout_s=profile.timeout_s
                )
                for profile in profiles
            ]
        except Exception as e:
            log.error(f"Failed to get profiles for IOC type {ioc_type}: {str(e)}")
            return []

    @staticmethod
    def resolve_enrichment_sources(root, info):
        """Get all enrichment sources"""
        try:
            return [
                EnrichmentSourceType(
                    name=source_class.name,
                    ioc_support=list(source_class.ioc_support),
                    description=getattr(source_class, 'description', ''),
                    configured=source_class().is_configured() if hasattr(source_class(), 'is_configured') else True
                )
                for source_class in SOURCES.values()
            ]
        except Exception as e:
            log.error(f"Failed to get enrichment sources: {str(e)}")
            return []

    @staticmethod
    def resolve_enrichment_job_status(root, info, job_id):
        """Get job status"""
        try:
            job_manager = get_job_manager()
            job = job_manager.get_job(job_id)

            if not job:
                return None

            return JobStatusType(
                job_id=job.job_id,
                status=job.status.value,
                case_id=job.case_id,
                ioc_type=job.ioc_type,
                ioc_value=job.ioc_value,
                profile_name=job.profile_name,
                user_id=job.user_id,
                created_at=job.created_at.isoformat() if job.created_at else None,
                updated_at=job.updated_at.isoformat() if job.updated_at else None,
                progress=job.progress_data.get('progress', 0) if job.progress_data else 0,
                current_phase=job.progress_data.get('phase') if job.progress_data else None,
                current_source=job.progress_data.get('current_source') if job.progress_data else None,
                error_message=getattr(job, 'error_message', None)
            )

        except Exception as e:
            log.error(f"Failed to get job status for {job_id}: {str(e)}")
            return None

    @staticmethod
    def resolve_enrichment_job_result(root, info, job_id):
        """Get job results"""
        try:
            job_manager = get_job_manager()
            job = job_manager.get_job(job_id)

            if not job or not job.result_data:
                return None

            result = job.result_data

            return EnrichmentResultType(
                job_id=job_id,
                status=result.get('status', 'unknown'),
                case_id=result.get('case_id'),
                ioc_type=result.get('ioc_type'),
                ioc_value=result.get('ioc_value'),
                profile_name=result.get('profile_name'),
                note_id=result.get('note_id'),
                artifact_ids=result.get('artifact_ids', []),
                risk_score=result.get('risk_score'),
                risk_level=result.get('risk_level'),
                sources_succeeded=result.get('sources_succeeded'),
                sources_failed=result.get('sources_failed'),
                completed_at=result.get('completed_at'),
                error=result.get('error')
            )

        except Exception as e:
            log.error(f"Failed to get job result for {job_id}: {str(e)}")
            return None

    @staticmethod
    def resolve_enrichment_jobs_for_case(root, info, case_id):
        """Get all jobs for a case"""
        try:
            job_manager = get_job_manager()
            jobs = job_manager.get_jobs_for_case(case_id)

            return [
                JobStatusType(
                    job_id=job.job_id,
                    status=job.status.value,
                    case_id=job.case_id,
                    ioc_type=job.ioc_type,
                    ioc_value=job.ioc_value,
                    profile_name=job.profile_name,
                    user_id=job.user_id,
                    created_at=job.created_at.isoformat() if job.created_at else None,
                    updated_at=job.updated_at.isoformat() if job.updated_at else None,
                    progress=job.progress_data.get('progress', 0) if job.progress_data else 0,
                    current_phase=job.progress_data.get('phase') if job.progress_data else None,
                    current_source=job.progress_data.get('current_source') if job.progress_data else None,
                    error_message=getattr(job, 'error_message', None)
                )
                for job in jobs
            ]

        except Exception as e:
            log.error(f"Failed to get jobs for case {case_id}: {str(e)}")
            return []

    @staticmethod
    def resolve_enrichment_job_statistics(root, info):
        """Get job statistics"""
        try:
            job_manager = get_job_manager()
            stats = job_manager.get_job_statistics()

            return JobStatisticsType(
                active_jobs=stats.get('active_jobs', 0),
                historical_jobs=stats.get('historical_jobs', 0),
                status_breakdown=stats.get('status_breakdown', {})
            )

        except Exception as e:
            log.error(f"Failed to get job statistics: {str(e)}")
            return JobStatisticsType(active_jobs=0, historical_jobs=0, status_breakdown={})


# GraphQL Mutations
class EnrichmentMutation(ObjectType):
    """GraphQL mutations for enrichment operations"""

    start_enrichment = StartEnrichment.Field()
    start_batch_enrichment = StartBatchEnrichment.Field()
    cancel_enrichment_job = CancelEnrichmentJob.Field()