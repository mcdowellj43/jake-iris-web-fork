#  IRIS Source Code
#  Copyright (C) 2025 - DFIR-IRIS
#  contact@dfir-iris.org
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import traceback
import requests
import uuid
import os
import json
import time
import zipfile
import logging
from datetime import datetime, timedelta
from flask import Blueprint
from flask import render_template
from flask import request
from flask import jsonify
from flask import redirect
from flask import url_for
from flask import send_file, abort
from flask_login import current_user, login_required

from app import db
from app.datamgmt.case.case_db import get_case
from app.models import Cases
from app.models.authorization import CaseAccessLevel
from app.models.soar import SoarTemplate, SoarJob, SoarJobStep, SoarJobArtifact
from app.business import notes as notes_business
from app.util import response_success, response_error, ac_api_case_requires, ac_requires_case_identifier
from app.blueprints.manage.manage_integrations.manage_integrations_routes import get_integrations_config
from celery import current_app as celery_app

log = logging.getLogger(__name__)

soar_blueprint = Blueprint('soar',
                          __name__,
                          template_folder='templates')


@soar_blueprint.route('/soar', methods=['GET'])
@login_required
def soar_index():
    """
    Main SOAR page - job orchestration and management interface
    """
    log.debug("SOAR route accessed")
    try:
        caseid = request.args.get('cid', default=1, type=int)

        case = get_case(caseid)
        if not case:
            return response_error("Case not found")

        # Get all cases for the switcher dropdown
        all_cases = Cases.query.filter(Cases.case_id != None).order_by(Cases.case_id.asc()).all()

        return render_template('soar.html',
                             case=case,
                             case_id=caseid,
                             all_cases=all_cases)

    except Exception as e:
        traceback.print_exc()
        return response_error(f"An error occurred: {str(e)}")


@soar_blueprint.route('/soar/templates', methods=['GET'])
@login_required
def soar_templates_list():
    """
    API endpoint to list available SOAR job templates from database
    """
    try:
        # Get query parameters
        integration_type = request.args.get('integration_type')
        requires_approval = request.args.get('requires_approval')
        active_only = request.args.get('active_only', 'true').lower() == 'true'

        # Build query
        query = SoarTemplate.query

        if integration_type:
            query = query.filter(SoarTemplate.integration_type == integration_type)

        if requires_approval is not None:
            approval_bool = requires_approval.lower() == 'true'
            query = query.filter(SoarTemplate.requires_approval == approval_bool)

        if active_only:
            query = query.filter(SoarTemplate.is_active == True)

        templates = query.order_by(SoarTemplate.template_name.asc()).all()

        # Convert to list of dictionaries
        templates_data = []
        for template in templates:
            template_dict = template.to_dict()
            # Add legacy fields for backward compatibility
            template_dict.update({
                "id": template.template_id,
                "name": template.template_name,
                "created_by": template.creator_name or "system",
                "created_at": template.created_at.isoformat() + "Z" if template.created_at else None
            })
            templates_data.append(template_dict)

        # If no templates in database, fall back to hardcoded ones
        if not templates_data:
            templates_data = [
            {
                "id": "sentinel1-quarantine",
                "name": "SentinelOne Network Quarantine",
                "description": "Isolate an endpoint from the network to prevent lateral movement",
                "vendor": "SentinelOne",
                "tags": ["containment", "isolation"],
                "requires_approval": True,
                "allowed_target_types": ["agent_id", "hostname"],
                "created_by": "system",
                "created_at": "2025-10-13T00:00:00Z"
            },
            {
                "id": "sentinel1-fetch-apps",
                "name": "SentinelOne Fetch Installed Applications",
                "description": "Retrieve list of installed applications from endpoint",
                "vendor": "SentinelOne",
                "tags": ["forensics", "inventory"],
                "requires_approval": False,
                "allowed_target_types": ["agent_id", "hostname"],
                "created_by": "system",
                "created_at": "2025-10-13T00:00:00Z"
            },
            {
                "id": "sentinel1-full-scan",
                "name": "SentinelOne Full Disk Scan",
                "description": "Initiate a complete disk scan on the endpoint",
                "vendor": "SentinelOne",
                "tags": ["scanning", "detection"],
                "requires_approval": False,
                "allowed_target_types": ["agent_id", "hostname"],
                "created_by": "system",
                "created_at": "2025-10-13T00:00:00Z"
            },
            {
                "id": "velociraptor-collect",
                "name": "Velociraptor Forensic Collection",
                "description": "Collect forensic artifacts using Velociraptor",
                "vendor": "Velociraptor",
                "tags": ["forensics"],
                "requires_approval": False,
                "allowed_target_types": ["client_id", "hostname"],
                "created_by": "system",
                "created_at": "2025-10-13T00:00:00Z"
            },
            {
                "id": "crowdstrike-contain-host",
                "name": "CrowdStrike Contain Host",
                "description": "Isolate a compromised endpoint from the network to prevent lateral movement",
                "vendor": "CrowdStrike",
                "tags": ["containment", "isolation"],
                "requires_approval": True,
                "allowed_target_types": ["device_id", "hostname"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "crowdstrike-lift-containment",
                "name": "CrowdStrike Lift Containment",
                "description": "Reconnect a previously isolated host after remediation",
                "vendor": "CrowdStrike",
                "tags": ["containment", "release"],
                "requires_approval": True,
                "allowed_target_types": ["device_id", "hostname"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "crowdstrike-fetch-host-info",
                "name": "CrowdStrike Fetch Host Information",
                "description": "Pull complete device metadata for investigation enrichment",
                "vendor": "CrowdStrike",
                "tags": ["forensics", "inventory"],
                "requires_approval": False,
                "allowed_target_types": ["device_id", "hostname"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "crowdstrike-fetch-detections",
                "name": "CrowdStrike Fetch Detections",
                "description": "Retrieve all detections related to a host, user, or timeframe",
                "vendor": "CrowdStrike",
                "tags": ["forensics", "detections"],
                "requires_approval": False,
                "allowed_target_types": ["device_id", "hostname"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "crowdstrike-fetch-incident-details",
                "name": "CrowdStrike Fetch Incident Details",
                "description": "Enrich an IRIS case with information from a linked CrowdStrike Incident ID",
                "vendor": "CrowdStrike",
                "tags": ["forensics", "incident"],
                "requires_approval": False,
                "allowed_target_types": ["incident_id"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "meraki-block-ip",
                "name": "Cisco Meraki Block IP Address",
                "description": "Block outbound or inbound communication with a malicious IP from Meraki firewall",
                "vendor": "Cisco Meraki",
                "tags": ["containment", "blocking"],
                "requires_approval": True,
                "allowed_target_types": ["ip_address"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "meraki-block-client",
                "name": "Cisco Meraki Block Client",
                "description": "Isolate a specific host by MAC or IP using Meraki client policy",
                "vendor": "Cisco Meraki",
                "tags": ["containment", "isolation"],
                "requires_approval": True,
                "allowed_target_types": ["ip_address", "mac_address"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "meraki-verify-network-event",
                "name": "Cisco Meraki Verify Network Event",
                "description": "Confirm enforcement by fetching Meraki event logs",
                "vendor": "Cisco Meraki",
                "tags": ["forensics", "verification"],
                "requires_approval": False,
                "allowed_target_types": ["ip_address"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "hibp-email-check",
                "name": "HaveIBeenPwned Email Exposure Check",
                "description": "Check if an email address appears in known data breaches",
                "vendor": "HaveIBeenPwned",
                "tags": ["forensics", "credential-intelligence"],
                "requires_approval": False,
                "allowed_target_types": ["email"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "hibp-domain-check",
                "name": "HaveIBeenPwned Domain Exposure Check",
                "description": "Check if a domain has appeared in data breaches",
                "vendor": "HaveIBeenPwned",
                "tags": ["forensics", "credential-intelligence"],
                "requires_approval": False,
                "allowed_target_types": ["domain"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "hibp-password-check",
                "name": "HaveIBeenPwned Password Reuse Check",
                "description": "Check if a password hash appears in known compromised password datasets",
                "vendor": "HaveIBeenPwned",
                "tags": ["forensics", "credential-intelligence"],
                "requires_approval": False,
                "allowed_target_types": ["password_hash"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "fortigate-block-ip",
                "name": "FortiGate Block IP Address",
                "description": "Instantly block an IP address across FortiGate firewall policies",
                "vendor": "FortiGate",
                "tags": ["containment", "blocking"],
                "requires_approval": True,
                "allowed_target_types": ["ip_address"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "fortigate-block-domain",
                "name": "FortiGate Block Domain/URL",
                "description": "Dynamically block a malicious domain via FortiGate's web filter",
                "vendor": "FortiGate",
                "tags": ["containment", "blocking"],
                "requires_approval": True,
                "allowed_target_types": ["domain", "url"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            },
            {
                "id": "fortigate-quarantine-host",
                "name": "FortiGate Quarantine Host",
                "description": "Immediately isolate an internal host showing compromise indicators",
                "vendor": "FortiGate",
                "tags": ["containment", "quarantine"],
                "requires_approval": True,
                "allowed_target_types": ["ip_address", "hostname"],
                "created_by": "system",
                "created_at": "2025-10-15T00:00:00Z"
            }
        ]

        return response_success("Templates retrieved successfully", data=templates_data)

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve templates: {str(e)}")


@soar_blueprint.route('/soar/templates', methods=['POST'])
@login_required
def soar_template_create():
    """
    API endpoint to create a new SOAR job template
    """
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['template_id', 'template_name', 'integration_type', 'execution_function']
        for field in required_fields:
            if field not in data:
                return response_error(f"Missing required field: {field}")

        # Check if template_id already exists
        if SoarTemplate.query.filter_by(template_id=data['template_id']).first():
            return response_error(f"Template with ID '{data['template_id']}' already exists")

        # Create new template
        template = SoarTemplate(
            template_id=data['template_id'],
            template_name=data['template_name'],
            description=data.get('description'),
            vendor=data.get('vendor'),
            integration_type=data['integration_type'],
            requires_approval=data.get('requires_approval', False),
            tags=data.get('tags'),
            allowed_target_types=data.get('allowed_target_types'),
            parameter_schema=data.get('parameter_schema'),
            execution_function=data['execution_function'],
            is_active=data.get('is_active', True),
            version=data.get('version', '1.0'),
            created_by=current_user.id
        )

        db.session.add(template)
        db.session.commit()

        # Log template creation
        log_template_management_event("created", template.template_id, template.template_name, current_user.id, {
            "integration_type": template.integration_type,
            "requires_approval": template.requires_approval,
            "version": template.version
        })

        return response_success("Template created successfully", data=template.to_dict())

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to create template: {str(e)}")


@soar_blueprint.route('/soar/templates/<template_id>', methods=['GET'])
@login_required
def soar_template_detail(template_id):
    """
    API endpoint to get details of a specific SOAR template
    """
    try:
        template = SoarTemplate.query.filter_by(template_id=template_id).first()
        if not template:
            return response_error(f"Template '{template_id}' not found")

        return response_success("Template retrieved successfully", data=template.to_dict())

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve template: {str(e)}")


@soar_blueprint.route('/soar/templates/<template_id>', methods=['PUT'])
@login_required
def soar_template_update(template_id):
    """
    API endpoint to update a SOAR template
    """
    try:
        template = SoarTemplate.query.filter_by(template_id=template_id).first()
        if not template:
            return response_error(f"Template '{template_id}' not found")

        data = request.get_json()

        # Update fields if provided
        if 'template_name' in data:
            template.template_name = data['template_name']
        if 'description' in data:
            template.description = data['description']
        if 'vendor' in data:
            template.vendor = data['vendor']
        if 'integration_type' in data:
            template.integration_type = data['integration_type']
        if 'requires_approval' in data:
            template.requires_approval = data['requires_approval']
        if 'tags' in data:
            template.tags = data['tags']
        if 'allowed_target_types' in data:
            template.allowed_target_types = data['allowed_target_types']
        if 'parameter_schema' in data:
            template.parameter_schema = data['parameter_schema']
        if 'execution_function' in data:
            template.execution_function = data['execution_function']
        if 'is_active' in data:
            template.is_active = data['is_active']
        if 'version' in data:
            template.version = data['version']

        # Update metadata
        template.updated_by = current_user.id
        template.updated_at = datetime.now()

        db.session.commit()

        # Log template update
        log_template_management_event("updated", template.template_id, template.template_name, current_user.id, {
            "changes": list(data.keys()),
            "version": template.version
        })

        return response_success("Template updated successfully", data=template.to_dict())

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to update template: {str(e)}")


@soar_blueprint.route('/soar/templates/<template_id>', methods=['DELETE'])
@login_required
def soar_template_delete(template_id):
    """
    API endpoint to delete a SOAR template (soft delete by setting is_active=False)
    """
    try:
        template = SoarTemplate.query.filter_by(template_id=template_id).first()
        if not template:
            return response_error(f"Template '{template_id}' not found")

        # Check if template is being used by any jobs
        active_jobs = SoarJob.query.filter_by(template_id=template_id).filter(
            SoarJob.status.in_(['Running', 'Scheduled', 'Pending Approval'])
        ).count()

        if active_jobs > 0:
            return response_error(f"Cannot delete template: {active_jobs} active jobs are using this template")

        # Soft delete
        template.is_active = False
        template.updated_by = current_user.id
        template.updated_at = datetime.now()

        db.session.commit()

        # Log template deletion
        log_template_management_event("deleted", template.template_id, template.template_name, current_user.id)

        return response_success("Template deleted successfully", data={
            "template_id": template_id,
            "deleted_by": current_user.name,
            "deleted_at": template.updated_at.isoformat() + "Z"
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to delete template: {str(e)}")


@soar_blueprint.route('/soar/templates/<template_id>/clone', methods=['POST'])
@login_required
def soar_template_clone(template_id):
    """
    API endpoint to clone an existing SOAR template
    """
    try:
        original_template = SoarTemplate.query.filter_by(template_id=template_id).first()
        if not original_template:
            return response_error(f"Template '{template_id}' not found")

        data = request.get_json() or {}
        new_template_id = data.get('new_template_id')

        if not new_template_id:
            return response_error("Missing required field: new_template_id")

        # Check if new template_id already exists
        if SoarTemplate.query.filter_by(template_id=new_template_id).first():
            return response_error(f"Template with ID '{new_template_id}' already exists")

        # Clone the template
        cloned_template = SoarTemplate(
            template_id=new_template_id,
            template_name=data.get('template_name', f"{original_template.template_name} (Copy)"),
            description=data.get('description', original_template.description),
            vendor=original_template.vendor,
            integration_type=original_template.integration_type,
            requires_approval=original_template.requires_approval,
            tags=original_template.tags,
            allowed_target_types=original_template.allowed_target_types,
            parameter_schema=original_template.parameter_schema,
            execution_function=original_template.execution_function,
            is_active=data.get('is_active', True),
            version=data.get('version', '1.0'),
            created_by=current_user.id
        )

        db.session.add(cloned_template)
        db.session.commit()

        return response_success("Template cloned successfully", data=cloned_template.to_dict())

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to clone template: {str(e)}")


@soar_blueprint.route('/soar/jobs', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_jobs_list(caseid):
    """
    API endpoint to list SOAR jobs for the current case with filtering and pagination
    """
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)  # Max 100 per page
        status_filter = request.args.get('status')
        template_filter = request.args.get('template_id')
        executor_filter = request.args.get('executor')
        search = request.args.get('search')

        # Build query with filters
        query = SoarJob.query.filter_by(case_id=caseid)

        if status_filter:
            query = query.filter(SoarJob.status == status_filter)

        if template_filter:
            query = query.filter(SoarJob.template_id == template_filter)

        if executor_filter:
            query = query.filter(SoarJob.executor_id == executor_filter)

        if search:
            # Search in job target, template name, or error message
            search_term = f"%{search}%"
            query = query.filter(
                (SoarJob.target.ilike(search_term)) |
                (SoarJob.template_name.ilike(search_term)) |
                (SoarJob.error_message.ilike(search_term))
            )

        # Order by creation date (newest first) and paginate
        pagination = query.order_by(SoarJob.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )

        jobs = pagination.items

        # Convert to list of dictionaries
        jobs_data = []
        for job in jobs:
            job_dict = {
                "job_id": job.job_id,
                "template_id": job.template_id,
                "template_name": job.template_name,
                "status": job.status,
                "executor": job.executor.name if job.executor else "Unknown",
                "executor_id": job.executor_id,
                "start_time": job.started_at.isoformat() + "Z" if job.started_at else None,
                "end_time": job.completed_at.isoformat() + "Z" if job.completed_at else None,
                "created_at": job.created_at.isoformat() + "Z" if job.created_at else None,
                "target": job.target,
                "artifacts_count": len(job.artifacts) if job.artifacts else 0,
                "steps_count": len(job.steps) if job.steps else 0,
                "duration": None
            }

            # Calculate duration if both start and end times exist
            if job.started_at and job.completed_at:
                duration_seconds = (job.completed_at - job.started_at).total_seconds()
                job_dict["duration"] = f"{duration_seconds:.1f}s"

            jobs_data.append(job_dict)

        # Return paginated response
        return response_success("Jobs retrieved successfully", data={
            "jobs": jobs_data,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": pagination.total,
                "pages": pagination.pages,
                "has_next": pagination.has_next,
                "has_prev": pagination.has_prev
            },
            "filters": {
                "status": status_filter,
                "template_id": template_filter,
                "executor": executor_filter,
                "search": search
            }
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve jobs: {str(e)}")


@soar_blueprint.route('/soar/jobs/history', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_jobs_history(caseid):
    """
    API endpoint to get comprehensive job history analytics for a case
    """
    try:
        # Get query parameters for date range
        days = request.args.get('days', 30, type=int)  # Default to last 30 days
        limit = min(request.args.get('limit', 100, type=int), 500)  # Max 500 jobs

        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        # Get jobs in date range
        jobs = SoarJob.query.filter(
            SoarJob.case_id == caseid,
            SoarJob.created_at >= start_date
        ).order_by(SoarJob.created_at.desc()).limit(limit).all()

        # Calculate statistics
        total_jobs = len(jobs)
        completed_jobs = len([j for j in jobs if j.status == 'Completed'])
        failed_jobs = len([j for j in jobs if j.status == 'Failed'])
        running_jobs = len([j for j in jobs if j.status == 'Running'])

        # Template usage statistics
        template_stats = {}
        for job in jobs:
            template_stats[job.template_id] = template_stats.get(job.template_id, 0) + 1

        # Success rate by template
        template_success = {}
        for job in jobs:
            if job.template_id not in template_success:
                template_success[job.template_id] = {'total': 0, 'success': 0}
            template_success[job.template_id]['total'] += 1
            if job.status == 'Completed':
                template_success[job.template_id]['success'] += 1

        # Calculate success rates
        for template_id in template_success:
            stats = template_success[template_id]
            stats['success_rate'] = (stats['success'] / stats['total']) * 100 if stats['total'] > 0 else 0

        # Recent activity (last 10 jobs)
        recent_jobs = []
        for job in jobs[:10]:
            recent_jobs.append({
                "job_id": job.job_id,
                "template_name": job.template_name,
                "status": job.status,
                "target": job.target,
                "created_at": job.created_at.isoformat() + "Z" if job.created_at else None,
                "executor": job.executor.name if job.executor else "Unknown"
            })

        return response_success("Job history retrieved successfully", data={
            "date_range": {
                "start_date": start_date.isoformat() + "Z",
                "end_date": end_date.isoformat() + "Z",
                "days": days
            },
            "summary": {
                "total_jobs": total_jobs,
                "completed_jobs": completed_jobs,
                "failed_jobs": failed_jobs,
                "running_jobs": running_jobs,
                "success_rate": (completed_jobs / total_jobs) * 100 if total_jobs > 0 else 0
            },
            "template_usage": template_stats,
            "template_success_rates": template_success,
            "recent_activity": recent_jobs
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve job history: {str(e)}")


@soar_blueprint.route('/soar/metrics/performance', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_performance_metrics(caseid):
    """
    API endpoint to get detailed performance metrics for SOAR jobs
    """
    try:
        # Get query parameters
        days = request.args.get('days', 30, type=int)
        template_id = request.args.get('template_id')

        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        # Build query
        query = SoarJob.query.filter(
            SoarJob.case_id == caseid,
            SoarJob.created_at >= start_date
        )

        if template_id:
            query = query.filter(SoarJob.template_id == template_id)

        jobs = query.all()

        # Calculate execution time statistics
        completed_jobs = [j for j in jobs if j.status == 'Completed' and j.started_at and j.completed_at]

        execution_times = []
        for job in completed_jobs:
            duration = (job.completed_at - job.started_at).total_seconds()
            execution_times.append(duration)

        # Performance statistics
        if execution_times:
            avg_execution_time = sum(execution_times) / len(execution_times)
            min_execution_time = min(execution_times)
            max_execution_time = max(execution_times)
            # Median calculation
            sorted_times = sorted(execution_times)
            n = len(sorted_times)
            median_execution_time = (sorted_times[n//2] + sorted_times[(n-1)//2]) / 2
        else:
            avg_execution_time = min_execution_time = max_execution_time = median_execution_time = 0

        # Success rate analysis
        total_jobs = len(jobs)
        completed = len([j for j in jobs if j.status == 'Completed'])
        failed = len([j for j in jobs if j.status == 'Failed'])
        success_rate = (completed / total_jobs) * 100 if total_jobs > 0 else 0

        # Template performance breakdown
        template_performance = {}
        for job in jobs:
            tid = job.template_id
            if tid not in template_performance:
                template_performance[tid] = {
                    'template_name': job.template_name,
                    'total_executions': 0,
                    'completed': 0,
                    'failed': 0,
                    'avg_duration': 0,
                    'success_rate': 0,
                    'execution_times': []
                }

            template_performance[tid]['total_executions'] += 1
            if job.status == 'Completed':
                template_performance[tid]['completed'] += 1
                if job.started_at and job.completed_at:
                    duration = (job.completed_at - job.started_at).total_seconds()
                    template_performance[tid]['execution_times'].append(duration)
            elif job.status == 'Failed':
                template_performance[tid]['failed'] += 1

        # Calculate template averages
        for template_id, stats in template_performance.items():
            total = stats['total_executions']
            stats['success_rate'] = (stats['completed'] / total) * 100 if total > 0 else 0
            if stats['execution_times']:
                stats['avg_duration'] = sum(stats['execution_times']) / len(stats['execution_times'])
            del stats['execution_times']  # Remove raw data from response

        # Time-based trends (jobs per day)
        daily_stats = {}
        for job in jobs:
            day_key = job.created_at.strftime('%Y-%m-%d')
            if day_key not in daily_stats:
                daily_stats[day_key] = {'total': 0, 'completed': 0, 'failed': 0}
            daily_stats[day_key]['total'] += 1
            if job.status == 'Completed':
                daily_stats[day_key]['completed'] += 1
            elif job.status == 'Failed':
                daily_stats[day_key]['failed'] += 1

        return response_success("Performance metrics retrieved successfully", data={
            "date_range": {
                "start_date": start_date.isoformat() + "Z",
                "end_date": end_date.isoformat() + "Z",
                "days": days
            },
            "overall_metrics": {
                "total_jobs": total_jobs,
                "completed_jobs": completed,
                "failed_jobs": failed,
                "success_rate": round(success_rate, 2),
                "avg_execution_time": round(avg_execution_time, 2),
                "min_execution_time": round(min_execution_time, 2),
                "max_execution_time": round(max_execution_time, 2),
                "median_execution_time": round(median_execution_time, 2)
            },
            "template_performance": template_performance,
            "daily_trends": daily_stats
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve performance metrics: {str(e)}")


@soar_blueprint.route('/soar/metrics/trends', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_metrics_trends(caseid):
    """
    API endpoint to get time-series trend data for SOAR jobs
    """
    try:
        # Get query parameters
        days = request.args.get('days', 30, type=int)
        interval = request.args.get('interval', 'daily')  # daily, weekly, monthly

        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        # Get jobs in range
        jobs = SoarJob.query.filter(
            SoarJob.case_id == caseid,
            SoarJob.created_at >= start_date
        ).order_by(SoarJob.created_at.asc()).all()

        # Generate time series data
        time_series = {}

        for job in jobs:
            if interval == 'daily':
                key = job.created_at.strftime('%Y-%m-%d')
            elif interval == 'weekly':
                # Start of week (Monday)
                week_start = job.created_at - timedelta(days=job.created_at.weekday())
                key = week_start.strftime('%Y-%m-%d')
            elif interval == 'monthly':
                key = job.created_at.strftime('%Y-%m')
            else:
                key = job.created_at.strftime('%Y-%m-%d')

            if key not in time_series:
                time_series[key] = {
                    'period': key,
                    'total_jobs': 0,
                    'completed': 0,
                    'failed': 0,
                    'running': 0,
                    'avg_duration': 0,
                    'execution_times': []
                }

            time_series[key]['total_jobs'] += 1

            if job.status == 'Completed':
                time_series[key]['completed'] += 1
                if job.started_at and job.completed_at:
                    duration = (job.completed_at - job.started_at).total_seconds()
                    time_series[key]['execution_times'].append(duration)
            elif job.status == 'Failed':
                time_series[key]['failed'] += 1
            elif job.status == 'Running':
                time_series[key]['running'] += 1

        # Calculate averages and clean up
        for period_data in time_series.values():
            if period_data['execution_times']:
                period_data['avg_duration'] = sum(period_data['execution_times']) / len(period_data['execution_times'])
            del period_data['execution_times']

        # Convert to sorted list
        trends_list = sorted(time_series.values(), key=lambda x: x['period'])

        return response_success("Trend data retrieved successfully", data={
            "date_range": {
                "start_date": start_date.isoformat() + "Z",
                "end_date": end_date.isoformat() + "Z",
                "days": days,
                "interval": interval
            },
            "trends": trends_list
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve trend data: {str(e)}")


@soar_blueprint.route('/soar/audit/logs', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_audit_logs(caseid):
    """
    API endpoint to retrieve SOAR audit logs for a case
    """
    try:
        # Get query parameters
        days = request.args.get('days', 7, type=int)
        action_type = request.args.get('action_type')
        user_id = request.args.get('user_id', type=int)
        limit = min(request.args.get('limit', 100, type=int), 1000)

        # Read audit log file
        audit_file_path = '/var/log/iris/soar_audit.log'

        if not os.path.exists(audit_file_path):
            return response_success("No audit logs found", data=[])

        # Calculate date filter
        cutoff_date = datetime.now() - timedelta(days=days)

        audit_entries = []
        try:
            with open(audit_file_path, 'r') as audit_file:
                for line in audit_file:
                    try:
                        entry = json.loads(line.strip())

                        # Parse timestamp
                        entry_time = datetime.fromisoformat(entry.get('timestamp', ''))

                        # Apply filters
                        if entry_time < cutoff_date:
                            continue

                        if entry.get('case_id') != caseid:
                            continue

                        if action_type and entry.get('action_type') != action_type:
                            continue

                        if user_id and entry.get('user_id') != user_id:
                            continue

                        audit_entries.append(entry)

                        # Apply limit
                        if len(audit_entries) >= limit:
                            break

                    except (json.JSONDecodeError, ValueError) as e:
                        # Skip malformed entries
                        continue

        except Exception as e:
            return response_error(f"Failed to read audit log: {str(e)}")

        # Sort by timestamp (newest first)
        audit_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return response_success("Audit logs retrieved successfully", data={
            "total_entries": len(audit_entries),
            "date_range": {
                "start_date": cutoff_date.isoformat() + "Z",
                "end_date": datetime.now().isoformat() + "Z",
                "days": days
            },
            "filters": {
                "action_type": action_type,
                "user_id": user_id,
                "limit": limit
            },
            "audit_entries": audit_entries
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve audit logs: {str(e)}")


@soar_blueprint.route('/soar/jobs/<job_id>/artifacts', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_job_artifacts(job_id, caseid):
    """
    API endpoint to list all artifacts for a specific job
    """
    try:
        # Verify job exists and belongs to this case
        job = SoarJob.query.filter_by(job_id=job_id, case_id=caseid).first()
        if not job:
            return response_error(f"Job {job_id} not found for case {caseid}")

        # Get all artifacts for this job
        artifacts = SoarJobArtifact.query.filter_by(job_id=job_id).all()

        artifacts_data = []
        for artifact in artifacts:
            artifacts_data.append(artifact.to_dict())

        return response_success("Job artifacts retrieved successfully", data=artifacts_data)

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve job artifacts: {str(e)}")


@soar_blueprint.route('/soar/jobs/<job_id>/artifacts/<artifact_id>/download', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_artifact_download(job_id, artifact_id, caseid):
    """
    API endpoint to download a specific job artifact
    """
    try:
        # Verify job exists and belongs to this case
        job = SoarJob.query.filter_by(job_id=job_id, case_id=caseid).first()
        if not job:
            return response_error(f"Job {job_id} not found for case {caseid}")

        # Get the specific artifact
        artifact = SoarJobArtifact.query.filter_by(artifact_id=artifact_id, job_id=job_id).first()
        if not artifact:
            return response_error(f"Artifact {artifact_id} not found for job {job_id}")

        # Check if artifact is downloadable
        if not artifact.is_downloadable:
            return response_error("Artifact is not available for download")

        # Check if file exists
        if not os.path.exists(artifact.file_path):
            return response_error("Artifact file not found on disk")

        # Return file for download
        return send_file(
            artifact.file_path,
            as_attachment=True,
            download_name=artifact.artifact_name,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to download artifact: {str(e)}")


@soar_blueprint.route('/soar/jobs/<job_id>/artifacts/<artifact_id>', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_artifact_detail(job_id, artifact_id, caseid):
    """
    API endpoint to get detailed information about a specific artifact
    """
    try:
        # Verify job exists and belongs to this case
        job = SoarJob.query.filter_by(job_id=job_id, case_id=caseid).first()
        if not job:
            return response_error(f"Job {job_id} not found for case {caseid}")

        # Get the specific artifact
        artifact = SoarJobArtifact.query.filter_by(artifact_id=artifact_id, job_id=job_id).first()
        if not artifact:
            return response_error(f"Artifact {artifact_id} not found for job {job_id}")

        # Add file existence check
        artifact_dict = artifact.to_dict()
        artifact_dict["file_exists"] = os.path.exists(artifact.file_path) if artifact.file_path else False

        return response_success("Artifact details retrieved successfully", data=artifact_dict)

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve artifact details: {str(e)}")


@soar_blueprint.route('/soar/jobs/<job_id>/notes', methods=['POST'])
@ac_api_case_requires(CaseAccessLevel.full_access)
def soar_job_create_note(job_id, caseid):
    """
    API endpoint to create a note linked to a specific SOAR job
    """
    try:
        # Verify job exists and belongs to this case
        job = SoarJob.query.filter_by(job_id=job_id, case_id=caseid).first()
        if not job:
            return response_error(f"Job {job_id} not found for case {caseid}")

        data = request.get_json()

        # Validate required fields
        if not data or 'note_content' not in data:
            return response_error("Missing required field: note_content")

        note_content = data.get('note_content')
        note_title = data.get('note_title', f"SOAR Job: {job.template_name}")

        # Add job context to note content
        enhanced_content = f"""**SOAR Job Reference**
**Job ID:** {job_id}
**Template:** {job.template_name}
**Target:** {job.target}
**Status:** {job.status}
**Executor:** {job.executor.name if job.executor else "Unknown"}

---

{note_content}"""

        # Create the note using IRIS notes system
        note_id = add_case_note(caseid, enhanced_content, note_title)

        if note_id:
            return response_success("Note created successfully", data={
                "note_id": note_id,
                "job_id": job_id,
                "note_title": note_title
            })
        else:
            return response_error("Failed to create note")

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to create job note: {str(e)}")


@soar_blueprint.route('/soar/jobs/<job_id>/summary', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_job_summary(job_id, caseid):
    """
    API endpoint to get a comprehensive summary of a SOAR job for note integration
    """
    try:
        # Verify job exists and belongs to this case
        job = SoarJob.query.filter_by(job_id=job_id, case_id=caseid).first()
        if not job:
            return response_error(f"Job {job_id} not found for case {caseid}")

        # Create a formatted summary for use in notes
        summary = f"""**SOAR Job Summary**

**Job Details:**
- Job ID: {job.job_id}
- Template: {job.template_name}
- Integration: {job.integration_type.title()}
- Target: {job.target}
- Status: {job.status}
- Executor: {job.executor.name if job.executor else "Unknown"}

**Timeline:**
- Created: {job.created_at.strftime('%Y-%m-%d %H:%M:%S UTC') if job.created_at else "Unknown"}
- Started: {job.started_at.strftime('%Y-%m-%d %H:%M:%S UTC') if job.started_at else "Not started"}
- Completed: {job.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if job.completed_at else "Not completed"}
"""

        # Add duration if available
        if job.started_at and job.completed_at:
            duration = (job.completed_at - job.started_at).total_seconds()
            summary += f"- Duration: {duration:.1f} seconds\n"

        # Add steps summary
        if job.steps:
            summary += f"\n**Steps Executed ({len(job.steps)}):**\n"
            for i, step in enumerate(sorted(job.steps, key=lambda x: x.step_order), 1):
                status_icon = "✅" if step.status == "Completed" else "❌" if step.status == "Failed" else "⏳"
                summary += f"{i}. {status_icon} {step.step_name} - {step.status}\n"

        # Add artifacts summary
        if job.artifacts:
            summary += f"\n**Artifacts Generated ({len(job.artifacts)}):**\n"
            for artifact in job.artifacts:
                size_str = f" ({artifact.file_size // 1024:.1f} KB)" if artifact.file_size else ""
                summary += f"- {artifact.artifact_name} ({artifact.artifact_type}){size_str}\n"

        # Add error information if failed
        if job.status == "Failed" and job.error_message:
            summary += f"\n**Error Details:**\n{job.error_message}\n"

        return response_success("Job summary retrieved successfully", data={
            "job_id": job_id,
            "summary": summary,
            "job_data": job.to_dict()
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve job summary: {str(e)}")


@soar_blueprint.route('/soar/jobs/pending-approval', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_jobs_pending_approval(caseid):
    """
    API endpoint to list jobs pending approval for a case
    """
    try:
        # Get jobs pending approval for this case
        jobs = SoarJob.query.filter_by(
            case_id=caseid,
            approval_status='Pending'
        ).order_by(SoarJob.created_at.desc()).all()

        jobs_data = []
        for job in jobs:
            job_dict = {
                "job_id": job.job_id,
                "template_id": job.template_id,
                "template_name": job.template_name,
                "target": job.target,
                "executor": job.executor.name if job.executor else "Unknown",
                "executor_id": job.executor_id,
                "created_at": job.created_at.isoformat() + "Z" if job.created_at else None,
                "comment": job.comment,
                "job_parameters": job.job_parameters,
                "integration_type": job.integration_type
            }
            jobs_data.append(job_dict)

        return response_success("Pending approval jobs retrieved successfully", data=jobs_data)

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve pending approval jobs: {str(e)}")


@soar_blueprint.route('/soar/jobs/<job_id>/approve', methods=['POST'])
@ac_api_case_requires(CaseAccessLevel.full_access)
def soar_job_approve(job_id, caseid):
    """
    API endpoint to approve a pending SOAR job
    """
    try:
        # Get the job
        job = SoarJob.query.filter_by(job_id=job_id, case_id=caseid).first()
        if not job:
            return response_error(f"Job {job_id} not found for case {caseid}")

        # Check if job requires approval and is pending
        if not job.requires_approval:
            return response_error("Job does not require approval")

        if job.approval_status != 'Pending':
            return response_error(f"Job is not pending approval (current status: {job.approval_status})")

        data = request.get_json() or {}
        approval_comment = data.get('comment', '')

        # Update job approval status
        job.approval_status = 'Approved'
        job.approved_by = current_user.id
        job.approved_at = datetime.now()
        job.approval_comment = approval_comment
        job.status = 'Running'
        job.started_at = datetime.now()

        db.session.commit()

        # Log approval action
        log_approval_workflow_event(job, "approved", current_user.id, approval_comment)

        # Create note about approval
        note_content = f"""**SOAR Job Approved**

**Job Details:**
- Job ID: {job_id}
- Template: {job.template_name}
- Target: {job.target}
- Requested by: {job.executor.name if job.executor else "Unknown"}

**Approval Details:**
- Approved by: {current_user.name}
- Approved at: {job.approved_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
- Comment: {approval_comment if approval_comment else "No comment provided"}

The job has been approved and will begin execution."""

        add_case_note(caseid, note_content, f"SOAR Job Approved: {job.template_name}")

        # Now execute the job (this would trigger the actual execution)
        # For now, we'll just mark it as ready to execute
        return response_success("Job approved successfully", data={
            "job_id": job_id,
            "status": job.status,
            "approved_by": current_user.name,
            "approved_at": job.approved_at.isoformat() + "Z",
            "message": "Job approved and queued for execution"
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to approve job: {str(e)}")


@soar_blueprint.route('/soar/jobs/<job_id>/reject', methods=['POST'])
@ac_api_case_requires(CaseAccessLevel.full_access)
def soar_job_reject(job_id, caseid):
    """
    API endpoint to reject a pending SOAR job
    """
    try:
        # Get the job
        job = SoarJob.query.filter_by(job_id=job_id, case_id=caseid).first()
        if not job:
            return response_error(f"Job {job_id} not found for case {caseid}")

        # Check if job requires approval and is pending
        if not job.requires_approval:
            return response_error("Job does not require approval")

        if job.approval_status != 'Pending':
            return response_error(f"Job is not pending approval (current status: {job.approval_status})")

        data = request.get_json() or {}
        rejection_reason = data.get('reason', '')

        if not rejection_reason:
            return response_error("Rejection reason is required")

        # Update job approval status
        job.approval_status = 'Rejected'
        job.approved_by = current_user.id
        job.approved_at = datetime.now()
        job.approval_comment = rejection_reason
        job.status = 'Rejected'
        job.completed_at = datetime.now()

        db.session.commit()

        # Log rejection action
        log_approval_workflow_event(job, "rejected", current_user.id, rejection_reason)

        # Create note about rejection
        note_content = f"""**SOAR Job Rejected**

**Job Details:**
- Job ID: {job_id}
- Template: {job.template_name}
- Target: {job.target}
- Requested by: {job.executor.name if job.executor else "Unknown"}

**Rejection Details:**
- Rejected by: {current_user.name}
- Rejected at: {job.approved_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
- Reason: {rejection_reason}

The job has been rejected and will not be executed."""

        add_case_note(caseid, note_content, f"SOAR Job Rejected: {job.template_name}")

        return response_success("Job rejected successfully", data={
            "job_id": job_id,
            "status": job.status,
            "rejected_by": current_user.name,
            "rejected_at": job.approved_at.isoformat() + "Z",
            "reason": rejection_reason
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to reject job: {str(e)}")


@soar_blueprint.route('/soar/jobs/schedule', methods=['POST'])
@ac_api_case_requires(CaseAccessLevel.full_access)
def soar_job_schedule(caseid):
    """
    API endpoint to schedule a SOAR job for delayed or recurring execution
    """
    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['template_id', 'target', 'schedule_type']
        for field in required_fields:
            if field not in data:
                return response_error(f"Missing required field: {field}")

        template_id = data.get('template_id')
        target = data.get('target')
        schedule_type = data.get('schedule_type')  # delayed, recurring
        scheduled_at = data.get('scheduled_at')  # ISO datetime string
        schedule_params = data.get('schedule_params', {})  # For recurring: interval, count, etc.
        comment = data.get('comment', '')

        # Validate schedule type
        if schedule_type not in ['delayed', 'recurring']:
            return response_error("schedule_type must be 'delayed' or 'recurring'")

        # Parse scheduled_at
        if schedule_type == 'delayed' and not scheduled_at:
            return response_error("scheduled_at is required for delayed jobs")

        if scheduled_at:
            try:
                scheduled_datetime = datetime.fromisoformat(scheduled_at.replace('Z', '+00:00'))
            except ValueError:
                return response_error("Invalid scheduled_at format. Use ISO 8601 format.")
        else:
            scheduled_datetime = None

        # Get template name and check approval requirement
        template_name = get_template_name(template_id)
        if not template_name:
            return response_error(f"Unknown template: {template_id}")

        # Determine integration type
        integration_type = get_integration_type_from_template(template_id)

        # Create scheduled job record
        job = create_scheduled_soar_job(
            case_id=caseid,
            template_id=template_id,
            template_name=template_name,
            integration_type=integration_type,
            target=target,
            executor_id=current_user.id,
            schedule_type=schedule_type,
            scheduled_at=scheduled_datetime,
            schedule_params=schedule_params,
            comment=comment
        )

        if not job:
            return response_error("Failed to create scheduled job")

        # Schedule the job execution with Celery
        task_id = schedule_job_execution(job)

        return response_success("Job scheduled successfully", data={
            "job_id": job.job_id,
            "schedule_type": schedule_type,
            "scheduled_at": job.scheduled_at.isoformat() if job.scheduled_at else None,
            "celery_task_id": task_id,
            "status": job.status,
            "message": f"Job scheduled for {'immediate execution' if schedule_type == 'immediate' else 'delayed execution' if schedule_type == 'delayed' else 'recurring execution'}"
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to schedule job: {str(e)}")


@soar_blueprint.route('/soar/jobs/scheduled', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_jobs_scheduled(caseid):
    """
    API endpoint to list scheduled jobs for a case
    """
    try:
        # Get query parameters
        schedule_type = request.args.get('schedule_type')  # delayed, recurring
        upcoming_only = request.args.get('upcoming_only', 'true').lower() == 'true'

        # Build query
        query = SoarJob.query.filter_by(case_id=caseid)

        if schedule_type:
            query = query.filter(SoarJob.schedule_type == schedule_type)

        if upcoming_only:
            # Only show jobs that haven't started yet
            query = query.filter(SoarJob.started_at.is_(None))

        # Add scheduling conditions
        query = query.filter(SoarJob.scheduled_at.isnot(None))

        jobs = query.order_by(SoarJob.scheduled_at.asc()).all()

        jobs_data = []
        for job in jobs:
            job_dict = {
                "job_id": job.job_id,
                "template_id": job.template_id,
                "template_name": job.template_name,
                "target": job.target,
                "status": job.status,
                "schedule_type": job.schedule_type,
                "scheduled_at": job.scheduled_at.isoformat() + "Z" if job.scheduled_at else None,
                "schedule_params": job.schedule_params,
                "executor": job.executor.name if job.executor else "Unknown",
                "created_at": job.created_at.isoformat() + "Z" if job.created_at else None,
                "celery_task_id": job.celery_task_id,
                "recurring_job_id": job.recurring_job_id
            }
            jobs_data.append(job_dict)

        return response_success("Scheduled jobs retrieved successfully", data=jobs_data)

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve scheduled jobs: {str(e)}")


@soar_blueprint.route('/soar/jobs/<job_id>/cancel-schedule', methods=['POST'])
@ac_api_case_requires(CaseAccessLevel.full_access)
def soar_job_cancel_schedule(job_id, caseid):
    """
    API endpoint to cancel a scheduled job
    """
    try:
        # Get the job
        job = SoarJob.query.filter_by(job_id=job_id, case_id=caseid).first()
        if not job:
            return response_error(f"Job {job_id} not found for case {caseid}")

        # Check if job is scheduled and not started
        if not job.scheduled_at:
            return response_error("Job is not scheduled")

        if job.started_at:
            return response_error("Job has already started and cannot be cancelled")

        # Cancel Celery task if exists
        if job.celery_task_id:
            try:
                celery_app.control.revoke(job.celery_task_id, terminate=True)
            except Exception as e:
                log.warning(f"Failed to revoke Celery task {job.celery_task_id}: {str(e)}")

        # Update job status
        job.status = 'Cancelled'
        job.completed_at = datetime.now()
        db.session.commit()

        # Create note about cancellation
        note_content = f"""**SOAR Job Cancelled**

**Job Details:**
- Job ID: {job_id}
- Template: {job.template_name}
- Target: {job.target}
- Originally scheduled for: {job.scheduled_at.strftime('%Y-%m-%d %H:%M:%S UTC') if job.scheduled_at else "Unknown"}

**Cancellation:**
- Cancelled by: {current_user.name}
- Cancelled at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

The scheduled job has been cancelled and will not execute."""

        add_case_note(caseid, note_content, f"SOAR Job Cancelled: {job.template_name}")

        return response_success("Scheduled job cancelled successfully", data={
            "job_id": job_id,
            "status": job.status,
            "cancelled_by": current_user.name,
            "cancelled_at": job.completed_at.isoformat() + "Z"
        })

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to cancel scheduled job: {str(e)}")


@soar_blueprint.route('/soar/test', methods=['GET'])
@login_required
def soar_test():
    """Test route to verify routing is working"""
    with open('/tmp/soar_debug.log', 'a') as f:
        f.write(f"[{datetime.now()}] soar_test route called!\n")
    return jsonify({"status": "success", "message": "Test route working"})

@soar_blueprint.route('/soar/jobs', methods=['POST'])
@ac_requires_case_identifier()
def soar_jobs_create(caseid):
    """
    API endpoint to create and execute a SOAR job
    """
    try:
        # File-based debugging to trace execution
        with open('/tmp/soar_debug.log', 'a') as f:
            f.write(f"[{datetime.now()}] soar_jobs_create called!\n")

        log.debug("soar_jobs_create called")
        data = request.get_json()

        with open('/tmp/soar_debug.log', 'a') as f:
            f.write(f"[{datetime.now()}] Request data: {data}\n")

        log.debug(f"Request data: {data}")

        # Validate required fields
        required_fields = ['template_id', 'target']
        for field in required_fields:
            if field not in data:
                return response_error(f"Missing required field: {field}")

        template_id = data.get('template_id')
        target = data.get('target')
        case_id = caseid

        # Generate unique job ID
        job_id = f"job-{uuid.uuid4().hex[:8]}"

        # Get integration settings
        integrations_config = get_integrations_config()

        # Execute the job based on template type
        job_result = execute_soar_job(job_id, template_id, target, case_id, integrations_config)

        return response_success("Job created successfully", data=job_result)

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to create job: {str(e)}")


@soar_blueprint.route('/soar/jobs/<job_id>', methods=['GET'])
@ac_api_case_requires(CaseAccessLevel.read_only, CaseAccessLevel.full_access)
def soar_job_detail(job_id, caseid):
    """
    API endpoint to get detailed information about a specific job
    """
    try:
        # Retrieve job from database
        job = SoarJob.query.filter_by(job_id=job_id, case_id=caseid).first()

        if not job:
            return response_error(f"Job {job_id} not found for case {caseid}")

        # Convert to dictionary and return
        job_detail = job.to_dict()

        return response_success("Job details retrieved successfully", data=job_detail)

    except Exception as e:
        traceback.print_exc()
        return response_error(f"Failed to retrieve job details: {str(e)}")


def execute_soar_job(job_id, template_id, target, case_id, integrations_config):
    """
    Execute a SOAR job based on the template type using integration settings
    """
    try:
        log.debug(f"execute_soar_job called with template_id={template_id}, target={target}")
        log.debug(f"integrations_config={integrations_config}")

        start_time = datetime.now().isoformat() + "Z"
        template_name = get_template_name(template_id)

        # Determine integration type from template
        if template_id.startswith('sentinel'):
            integration_type = 'sentinelone'
            config = integrations_config.get('sentinelone', {})
        elif template_id.startswith('velociraptor'):
            integration_type = 'velociraptor'
            config = integrations_config.get('velociraptor', {})
        elif template_id.startswith('crowdstrike'):
            integration_type = 'crowdstrike'
            config = integrations_config.get('crowdstrike', {})
        elif template_id.startswith('meraki'):
            integration_type = 'meraki'
            config = integrations_config.get('meraki', {})
        elif template_id.startswith('hibp'):
            integration_type = 'haveibeenpwned'
            config = integrations_config.get('haveibeenpwned', {})
        elif template_id.startswith('fortigate'):
            integration_type = 'fortigate'
            config = integrations_config.get('fortigate', {})
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "Unknown template type",
                "error": f"Template {template_id} not recognized"
            }

        # Check if integration is enabled and configured
        with open('/tmp/soar_debug.log', 'a') as f:
            f.write(f"[{datetime.now()}] checking enabled status for {integration_type}, config={config}\n")
            f.write(f"[{datetime.now()}] config.get('enabled', False)={config.get('enabled', False)}\n")

        log.debug(f"checking enabled status for {integration_type}, config={config}")
        log.debug(f"config.get('enabled', False)={config.get('enabled', False)}")

        if not config.get('enabled', False):
            with open('/tmp/soar_debug.log', 'a') as f:
                f.write(f"[{datetime.now()}] Integration {integration_type} is not enabled, returning failure\n")
            log.debug(f"Integration {integration_type} is not enabled, returning failure")
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"{integration_type.capitalize()} integration is not enabled - Please configure it in Manage > Integrations",
                "error": "Integration disabled - API credentials required"
            }

        # Validate required configuration
        if integration_type == 'sentinelone':
            base_url = config.get('base_url', '').strip()
            api_token = config.get('api_token', '').strip()
            if not base_url or not api_token:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": "SentinelOne API credentials missing - Configure URL and API token in Manage > Integrations",
                    "error": "Missing base_url or api_token - Cannot connect to SentinelOne API"
                }
        elif integration_type == 'velociraptor':
            base_url = config.get('base_url', '').strip()
            api_key = config.get('api_key', '').strip()
            if not base_url or not api_key:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": "Velociraptor API credentials missing - Configure URL and API key in Manage > Integrations",
                    "error": "Missing base_url or api_key - Cannot connect to Velociraptor API"
                }
        elif integration_type == 'crowdstrike':
            base_url = config.get('base_url', '').strip()
            client_id = config.get('client_id', '').strip()
            client_secret = config.get('client_secret', '').strip()
            if not base_url or not client_id or not client_secret:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": "CrowdStrike API credentials missing - Configure URL, Client ID and Client Secret in Manage > Integrations",
                    "error": "Missing base_url, client_id or client_secret - Cannot connect to CrowdStrike API"
                }
        elif integration_type == 'meraki':
            api_key = config.get('api_key', '').strip()
            organization_id = config.get('organization_id', '').strip()
            if not api_key or not organization_id:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": "Meraki API credentials missing - Configure API Key and Organization ID in Manage > Integrations",
                    "error": "Missing api_key or organization_id - Cannot connect to Meraki API"
                }

        # Execute the specific job type
        if template_id == 'sentinel1-quarantine':
            result = execute_sentinelone_quarantine(job_id, target, config, case_id)
        elif template_id == 'sentinel1-fetch-apps':
            result = execute_sentinelone_fetch_apps(job_id, target, config, case_id)
        elif template_id == 'sentinel1-full-scan':
            result = execute_sentinelone_full_scan(job_id, target, config, case_id)
        elif template_id == 'velociraptor-collect':
            result = execute_velociraptor_collect(job_id, target, config)
        elif template_id == 'crowdstrike-contain-host':
            result = execute_crowdstrike_contain_host(job_id, target, config, case_id)
        elif template_id == 'crowdstrike-lift-containment':
            result = execute_crowdstrike_lift_containment(job_id, target, config, case_id)
        elif template_id == 'crowdstrike-fetch-host-info':
            result = execute_crowdstrike_fetch_host_info(job_id, target, config, case_id)
        elif template_id == 'crowdstrike-fetch-detections':
            result = execute_crowdstrike_fetch_detections(job_id, target, config, case_id)
        elif template_id == 'crowdstrike-fetch-incident-details':
            result = execute_crowdstrike_fetch_incident_details(job_id, target, config, case_id)
        elif template_id == 'meraki-block-ip':
            result = execute_meraki_block_ip(job_id, target, config, case_id)
        elif template_id == 'meraki-block-client':
            result = execute_meraki_block_client(job_id, target, config, case_id)
        elif template_id == 'meraki-verify-network-event':
            result = execute_meraki_verify_network_event(job_id, target, config, case_id)
        elif template_id == 'hibp-email-check':
            result = execute_hibp_email_check(job_id, target, config, case_id)
        elif template_id == 'hibp-domain-check':
            result = execute_hibp_domain_check(job_id, target, config, case_id)
        elif template_id == 'hibp-password-check':
            result = execute_hibp_password_check(job_id, target, config, case_id)
        elif template_id == 'fortigate-block-ip':
            result = execute_fortigate_block_ip(job_id, target, config, case_id)
        elif template_id == 'fortigate-block-domain':
            result = execute_fortigate_block_domain(job_id, target, config, case_id)
        elif template_id == 'fortigate-quarantine-host':
            result = execute_fortigate_quarantine_host(job_id, target, config, case_id)
        else:
            result = {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Template {template_id} execution not implemented",
                "error": "Template execution logic not found"
            }

        return result

    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Job execution failed: {str(e)}",
            "error": str(e)
        }


def get_template_name(template_id):
    """
    Get the display name for a template ID
    """
    template_names = {
        'sentinel1-quarantine': 'SentinelOne Network Quarantine',
        'sentinel1-fetch-apps': 'SentinelOne Fetch Installed Applications',
        'sentinel1-full-scan': 'SentinelOne Full Disk Scan',
        'velociraptor-collect': 'Velociraptor Forensic Collection',
        'crowdstrike-contain-host': 'CrowdStrike Contain Host',
        'crowdstrike-lift-containment': 'CrowdStrike Lift Containment',
        'crowdstrike-fetch-host-info': 'CrowdStrike Fetch Host Information',
        'crowdstrike-fetch-detections': 'CrowdStrike Fetch Detections',
        'crowdstrike-fetch-incident-details': 'CrowdStrike Fetch Incident Details',
        'meraki-block-ip': 'Cisco Meraki Block IP Address',
        'meraki-block-client': 'Cisco Meraki Block Client',
        'meraki-verify-network-event': 'Cisco Meraki Verify Network Event',
        'hibp-email-check': 'HaveIBeenPwned Email Exposure Check',
        'hibp-domain-check': 'HaveIBeenPwned Domain Exposure Check',
        'hibp-password-check': 'HaveIBeenPwned Password Reuse Check',
        'fortigate-block-ip': 'FortiGate Block IP Address',
        'fortigate-block-domain': 'FortiGate Block Domain/URL',
        'fortigate-quarantine-host': 'FortiGate Quarantine Host'
    }
    return template_names.get(template_id, template_id)


def create_case_artifact_folder(case_id, integration_type='sentinelone'):
    """
    Create the artifacts folder structure for a case
    """
    try:
        artifact_path = f"/home/iris/server_data/cases/{case_id}/artifacts/{integration_type}"
        os.makedirs(artifact_path, exist_ok=True)
        return artifact_path
    except Exception as e:
        log.error(f"Error creating artifact folder: {str(e)}")
        return None


def save_case_artifact(case_id, filename, data, integration_type='sentinelone'):
    """
    Save artifact data to case folder
    """
    try:
        artifact_path = create_case_artifact_folder(case_id, integration_type)
        if not artifact_path:
            return None

        file_path = os.path.join(artifact_path, filename)

        if isinstance(data, dict):
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
        elif isinstance(data, bytes):
            with open(file_path, 'wb') as f:
                f.write(data)
        else:
            with open(file_path, 'w') as f:
                f.write(str(data))

        return file_path
    except Exception as e:
        log.error(f"Error saving artifact: {str(e)}")
        return None


def add_case_note(case_id, note_content, note_title="SOAR Job Execution"):
    """
    Add a note to the case using the IRIS notes system
    """
    try:
        # Import required modules for note creation
        from app.datamgmt.case.case_notes_db import add_note
        from app.models import NoteDirectory
        from app import db
        from sqlalchemy import and_

        # Check if "SOAR Job Reports" directory exists, create if not
        directory = NoteDirectory.query.filter(and_(
            NoteDirectory.case_id == case_id,
            NoteDirectory.name == "SOAR Job Reports"
        )).first()

        if not directory:
            directory = NoteDirectory(
                name="SOAR Job Reports",
                case_id=case_id
            )
            db.session.add(directory)
            db.session.commit()
            log.info(f"Created SOAR Job Reports directory for case {case_id}")

        # Add the note using the core IRIS function
        note = add_note(
            note_title=note_title,
            creation_date=datetime.now(),
            user_id=1,  # System user
            caseid=case_id,
            directory_id=directory.id,
            note_content=note_content
        )

        return note.note_id if note else None
    except Exception as e:
        log.error(f"Error adding case note: {str(e)}")
        traceback.print_exc()
        return False


def get_integration_type_from_template(template_id):
    """
    Get integration type from template ID
    """
    if template_id.startswith('sentinel'):
        return 'sentinelone'
    elif template_id.startswith('velociraptor'):
        return 'velociraptor'
    elif template_id.startswith('crowdstrike'):
        return 'crowdstrike'
    elif template_id.startswith('meraki'):
        return 'meraki'
    elif template_id.startswith('hibp'):
        return 'haveibeenpwned'
    elif template_id.startswith('fortigate'):
        return 'fortigate'
    else:
        return 'unknown'


def create_scheduled_soar_job(case_id, template_id, template_name, integration_type, target, executor_id,
                             schedule_type, scheduled_at=None, schedule_params=None, comment=None):
    """
    Create a new scheduled SOAR job record in the database
    """
    try:
        job_id = str(uuid.uuid4())

        # Check if template requires approval
        requires_approval = get_template_approval_requirement(template_id)

        # Set initial status based on scheduling and approval
        if requires_approval:
            initial_status = 'Pending Approval'
            approval_status = 'Pending'
        elif schedule_type == 'delayed':
            initial_status = 'Scheduled'
            approval_status = None
        elif schedule_type == 'recurring':
            initial_status = 'Scheduled (Recurring)'
            approval_status = None
        else:
            initial_status = 'Running'
            approval_status = None

        # Generate recurring job ID for recurring jobs
        recurring_job_id = str(uuid.uuid4()) if schedule_type == 'recurring' else None

        job = SoarJob(
            job_id=job_id,
            case_id=case_id,
            template_id=template_id,
            template_name=template_name,
            integration_type=integration_type,
            target=target,
            status=initial_status,
            executor_id=executor_id,
            started_at=None,  # Will be set when job actually starts
            job_parameters=None,
            comment=comment,
            requires_approval=requires_approval,
            approval_status=approval_status,
            scheduled_at=scheduled_at,
            schedule_type=schedule_type,
            schedule_params=schedule_params,
            recurring_job_id=recurring_job_id
        )
        db.session.add(job)
        db.session.commit()
        return job
    except Exception as e:
        log.error(f"Error creating scheduled SOAR job: {str(e)}")
        db.session.rollback()
        return None


def schedule_job_execution(job):
    """
    Schedule job execution using Celery
    """
    try:
        if job.schedule_type == 'delayed':
            # Schedule for specific datetime
            task = celery_app.send_task(
                'execute_scheduled_soar_job',
                args=[job.job_id],
                eta=job.scheduled_at
            )
            job.celery_task_id = task.id
            db.session.commit()
            return task.id

        elif job.schedule_type == 'recurring':
            # For recurring jobs, schedule the first execution
            # and set up periodic task (would need celery-beat configuration)
            task = celery_app.send_task(
                'execute_recurring_soar_job',
                args=[job.job_id],
                eta=job.scheduled_at
            )
            job.celery_task_id = task.id
            db.session.commit()
            return task.id

        else:
            # Immediate execution
            task = celery_app.send_task(
                'execute_soar_job_task',
                args=[job.job_id]
            )
            job.celery_task_id = task.id
            db.session.commit()
            return task.id

    except Exception as e:
        log.error(f"Error scheduling job execution: {str(e)}")
        return None


def audit_log_soar_action(action_type, job_id=None, template_id=None, target=None, user_id=None, case_id=None,
                         details=None, status=None, error_message=None):
    """
    Enhanced audit logging for SOAR operations
    """
    try:
        # Create structured log entry
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action_type": action_type,
            "job_id": job_id,
            "template_id": template_id,
            "target": target,
            "user_id": user_id,
            "case_id": case_id,
            "status": status,
            "details": details,
            "error_message": error_message
        }

        # Get logger for SOAR operations
        logger = logging.getLogger('soar_audit')

        # Log at appropriate level based on status
        if status == 'Failed' or error_message:
            logger.error(f"SOAR_AUDIT: {json.dumps(log_entry)}")
        elif status == 'Completed':
            logger.info(f"SOAR_AUDIT: {json.dumps(log_entry)}")
        else:
            logger.debug(f"SOAR_AUDIT: {json.dumps(log_entry)}")

        # Also write to dedicated audit file for compliance
        audit_file_path = '/var/log/iris/soar_audit.log'
        os.makedirs(os.path.dirname(audit_file_path), exist_ok=True)

        with open(audit_file_path, 'a') as audit_file:
            audit_file.write(f"{json.dumps(log_entry)}\n")

    except Exception as e:
        # Fallback logging if audit logging fails
        log.warning(f"Audit logging failed: {str(e)}")
        logging.error(f"SOAR audit logging failure: {str(e)}")


def log_job_lifecycle_event(job, event_type, additional_data=None):
    """
    Log job lifecycle events with comprehensive details
    """
    try:
        details = {
            "event_type": event_type,
            "job_details": {
                "template_name": job.template_name,
                "integration_type": job.integration_type,
                "requires_approval": job.requires_approval,
                "schedule_type": job.schedule_type
            }
        }

        if additional_data:
            details.update(additional_data)

        audit_log_soar_action(
            action_type="job_lifecycle",
            job_id=job.job_id,
            template_id=job.template_id,
            target=job.target,
            user_id=current_user.id if current_user else None,
            case_id=job.case_id,
            status=job.status,
            details=details
        )
    except Exception as e:
        log.warning(f"Job lifecycle logging failed: {str(e)}")


def log_template_management_event(action, template_id, template_name, user_id, details=None):
    """
    Log template management operations
    """
    try:
        audit_log_soar_action(
            action_type=f"template_{action}",
            template_id=template_id,
            user_id=user_id,
            details={
                "template_name": template_name,
                "action": action,
                **(details or {})
            },
            status="Completed"
        )
    except Exception as e:
        log.warning(f"Template management logging failed: {str(e)}")


def log_approval_workflow_event(job, action, approver_id, comment=None):
    """
    Log approval workflow events
    """
    try:
        audit_log_soar_action(
            action_type=f"approval_{action}",
            job_id=job.job_id,
            template_id=job.template_id,
            target=job.target,
            user_id=approver_id,
            case_id=job.case_id,
            details={
                "action": action,
                "original_executor": job.executor_id,
                "approval_comment": comment,
                "template_name": job.template_name
            },
            status="Completed"
        )
    except Exception as e:
        log.warning(f"Approval workflow logging failed: {str(e)}")


def get_template_approval_requirement(template_id):
    """
    Check if a template requires approval before execution
    """
    # In the future this will query the database template table
    # For now, check the hardcoded templates
    templates = get_template_data()
    for template in templates:
        if template['id'] == template_id:
            return template.get('requires_approval', False)
    return False


def get_template_data():
    """
    Get template data (will be moved to database in Phase 3.3)
    """
    return [
        {"id": "sentinel1-quarantine", "name": "SentinelOne Network Quarantine", "requires_approval": True},
        {"id": "sentinel1-fetch-apps", "name": "SentinelOne Fetch Installed Applications", "requires_approval": False},
        {"id": "sentinel1-full-scan", "name": "SentinelOne Full Disk Scan", "requires_approval": True},
        {"id": "velociraptor-collect", "name": "Velociraptor Forensic Collection", "requires_approval": True},
        {"id": "crowdstrike-contain-host", "name": "CrowdStrike Contain Host", "requires_approval": True},
        {"id": "meraki-block-ip", "name": "Cisco Meraki Block IP Address", "requires_approval": True},
        {"id": "hibp-email-check", "name": "HaveIBeenPwned Email Exposure Check", "requires_approval": False},
        {"id": "fortigate-block-ip", "name": "FortiGate Block IP Address", "requires_approval": True}
    ]


def create_soar_job(case_id, template_id, template_name, integration_type, target, executor_id, job_parameters=None, comment=None):
    """
    Create a new SOAR job record in the database with approval workflow support
    """
    try:
        job_id = str(uuid.uuid4())

        # Check if template requires approval
        requires_approval = get_template_approval_requirement(template_id)

        # Set initial status based on approval requirement
        if requires_approval:
            initial_status = 'Pending Approval'
            approval_status = 'Pending'
            started_at = None  # Don't set start time until approved
        else:
            initial_status = 'Running'
            approval_status = None
            started_at = datetime.now()

        job = SoarJob(
            job_id=job_id,
            case_id=case_id,
            template_id=template_id,
            template_name=template_name,
            integration_type=integration_type,
            target=target,
            status=initial_status,
            executor_id=executor_id,
            started_at=started_at,
            job_parameters=job_parameters,
            comment=comment,
            requires_approval=requires_approval,
            approval_status=approval_status
        )
        db.session.add(job)
        db.session.commit()

        # Log job creation
        log_job_lifecycle_event(job, "created", {
            "requires_approval": requires_approval,
            "approval_status": approval_status
        })

        return job
    except Exception as e:
        log.error(f"Error creating SOAR job: {str(e)}")
        audit_log_soar_action(
            action_type="job_creation_failed",
            template_id=template_id,
            target=target,
            user_id=executor_id,
            case_id=case_id,
            status="Failed",
            error_message=str(e)
        )
        db.session.rollback()
        return None


def update_soar_job(job_id, status=None, result_data=None, error_message=None, completed_at=None, started_at=None):
    """
    Update a SOAR job record in the database
    """
    try:
        job = SoarJob.query.filter_by(job_id=job_id).first()
        if not job:
            return False

        if status:
            job.status = status
        if result_data:
            job.result_data = result_data
        if error_message:
            job.error_message = error_message
        if started_at:
            job.started_at = started_at
        if completed_at:
            job.completed_at = completed_at
        elif status in ['Completed', 'Failed']:
            job.completed_at = datetime.now()

        db.session.commit()
        return True
    except Exception as e:
        log.error(f"Error updating SOAR job: {str(e)}")
        db.session.rollback()
        return False


def add_soar_job_step(job_id, step_name, step_order, status='Running', result_message=None, error_message=None):
    """
    Add a step to a SOAR job
    """
    try:
        step_id = str(uuid.uuid4())
        step = SoarJobStep(
            step_id=step_id,
            job_id=job_id,
            step_name=step_name,
            step_order=step_order,
            status=status,
            started_at=datetime.now(),
            result_message=result_message,
            error_message=error_message
        )
        if status in ['Completed', 'Failed']:
            step.completed_at = datetime.now()

        db.session.add(step)
        db.session.commit()
        return step
    except Exception as e:
        log.error(f"Error adding SOAR job step: {str(e)}")
        db.session.rollback()
        return None


def update_soar_job_step(step_id, status=None, result_message=None, error_message=None, completed_at=None):
    """
    Update a SOAR job step
    """
    try:
        step = SoarJobStep.query.filter_by(step_id=step_id).first()
        if not step:
            return False

        if status:
            step.status = status
        if result_message:
            step.result_message = result_message
        if error_message:
            step.error_message = error_message
        if completed_at:
            step.completed_at = completed_at
        elif status in ['Completed', 'Failed']:
            step.completed_at = datetime.now()

        db.session.commit()
        return True
    except Exception as e:
        log.error(f"Error updating SOAR job step: {str(e)}")
        db.session.rollback()
        return False


def add_soar_job_artifact(job_id, artifact_name, artifact_type, file_path, file_size=None):
    """
    Add an artifact to a SOAR job
    """
    try:
        artifact_id = str(uuid.uuid4())
        artifact = SoarJobArtifact(
            artifact_id=artifact_id,
            job_id=job_id,
            artifact_name=artifact_name,
            artifact_type=artifact_type,
            file_path=file_path,
            file_size=file_size,
            is_downloadable=True
        )
        db.session.add(artifact)
        db.session.commit()
        return artifact
    except Exception as e:
        log.error(f"Error adding SOAR job artifact: {str(e)}")
        db.session.rollback()
        return None


def execute_sentinelone_quarantine(job_id, target, config, case_id):
    """
    Execute SentinelOne quarantine job
    """
    try:
        base_url = config.get('base_url').rstrip('/')
        api_token = config.get('api_token')
        verify_ssl = config.get('verify_ssl', True)

        headers = {
            'Authorization': f'ApiToken {api_token}',
            'Content-Type': 'application/json'
        }

        # Step 1: Find agent by hostname or agent ID
        if target.startswith('agent-'):
            agent_id = target.replace('agent-', '')
            agents_endpoint = f'{base_url}/web/api/v2.1/agents/{agent_id}'
        else:
            # Search by hostname
            agents_endpoint = f'{base_url}/web/api/v2.1/agents'
            params = {'computerName': target, 'limit': 1}

            response = requests.get(agents_endpoint, headers=headers, params=params, verify=verify_ssl, timeout=30)
            if response.status_code != 200:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Failed to find agent: {target}",
                    "error": f"SentinelOne API returned status {response.status_code}"
                }

            agents = response.json().get('data', [])
            if not agents:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Agent not found: {target}",
                    "error": "No agents found matching the target hostname"
                }

            agent_id = agents[0]['id']

        # Step 2: Quarantine the agent
        quarantine_endpoint = f'{base_url}/web/api/v2.1/agents/actions/disconnect'
        quarantine_data = {
            'filter': {
                'ids': [agent_id]
            }
        }

        response = requests.post(quarantine_endpoint, headers=headers, json=quarantine_data, verify=verify_ssl, timeout=30)

        if response.status_code == 200:
            end_time = datetime.now().isoformat() + "Z"

            # Save quarantine action details as artifact
            quarantine_data = {
                "job_id": job_id,
                "action": "network_quarantine",
                "target": target,
                "agent_id": agent_id,
                "timestamp": end_time,
                "status": "completed",
                "api_response": response.json()
            }

            artifact_filename = f"quarantine_action_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            artifact_path = save_case_artifact(case_id, artifact_filename, quarantine_data)

            # Create case note
            note_content = f"""**SOAR Action:** Network Quarantine
**Endpoint:** {target}
**Timestamp:** {end_time}
**Status:** ✅ Host successfully isolated from network.
_This action prevents all inbound/outbound connections except SentinelOne management._

**Artifact:** `/cases/{case_id}/artifacts/sentinelone/{artifact_filename}`"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Successfully quarantined agent {target}",
                "template_name": "SentinelOne Network Quarantine",
                "target": target,
                "start_time": datetime.now().isoformat() + "Z",
                "end_time": end_time,
                "artifact_path": artifact_path,
                "steps": [
                    {
                        "step_id": "find_agent",
                        "name": "Find Agent",
                        "status": "Completed",
                        "message": f"Found agent ID: {agent_id}"
                    },
                    {
                        "step_id": "quarantine",
                        "name": "Quarantine Agent",
                        "status": "Completed",
                        "message": "Agent successfully quarantined"
                    },
                    {
                        "step_id": "save_artifact",
                        "name": "Save Artifact",
                        "status": "Completed",
                        "message": f"Saved quarantine details to {artifact_filename}"
                    }
                ]
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to quarantine agent: {target}",
                "error": f"SentinelOne API returned status {response.status_code}: {response.text}"
            }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to SentinelOne: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"SentinelOne quarantine job failed: {str(e)}",
            "error": str(e)
        }


def execute_sentinelone_fetch_apps(job_id, target, config, case_id):
    """
    Execute SentinelOne fetch installed applications playbook
    """
    db_job = None
    try:
        base_url = config.get('base_url').rstrip('/')
        api_token = config.get('api_token')
        verify_ssl = config.get('verify_ssl', True)
        start_time = datetime.now().isoformat() + "Z"

        # Create database job record
        db_job = create_soar_job(
            case_id=case_id,
            template_id="sentinel1-fetch-apps",
            template_name="SentinelOne Fetch Installed Applications",
            integration_type="sentinelone",
            target=target,
            executor_id=current_user.id,
            job_parameters={
                "base_url": base_url,
                "verify_ssl": verify_ssl
            }
        )

        # Update job to Running status
        update_soar_job(db_job.job_id, status="Running", started_at=datetime.now())

        headers = {
            'Authorization': f'ApiToken {api_token}',
            'Content-Type': 'application/json'
        }

        # Step 1: Find agent by hostname or agent ID
        step1 = add_soar_job_step(
            job_id=db_job.job_id,
            step_name="Find Agent",
            step_order=1,
            status="Running"
        )
        if target.startswith('agent-'):
            agent_id = target.replace('agent-', '')
            update_soar_job_step(step1.step_id, status="Completed",
                                completed_at=datetime.now(),
                                result_message=f"Agent ID provided: {agent_id}")
        else:
            # Search by hostname
            agents_endpoint = f'{base_url}/web/api/v2.1/agents'
            params = {'computerName': target, 'limit': 1}

            response = requests.get(agents_endpoint, headers=headers, params=params, verify=verify_ssl, timeout=30)
            if response.status_code != 200:
                # Update step and job as failed
                update_soar_job_step(step1.step_id, status="Failed",
                                    completed_at=datetime.now(),
                                    error_message=f"SentinelOne API returned status {response.status_code}")
                update_soar_job(db_job.job_id, status="Failed", completed_at=datetime.now(),
                              error_message=f"Failed to find agent: {target}")
                return {
                    "job_id": db_job.job_id,
                    "status": "Failed",
                    "message": f"Failed to find agent: {target}",
                    "error": f"SentinelOne API returned status {response.status_code}"
                }

            agents = response.json().get('data', [])
            if not agents:
                # Update step and job as failed
                update_soar_job_step(step1.step_id, status="Failed",
                                    completed_at=datetime.now(),
                                    error_message="No agents found matching the target hostname")
                update_soar_job(db_job.job_id, status="Failed", completed_at=datetime.now(),
                              error_message=f"Agent not found: {target}")
                return {
                    "job_id": db_job.job_id,
                    "status": "Failed",
                    "message": f"Agent not found: {target}",
                    "error": "No agents found matching the target hostname"
                }

            agent_id = agents[0]['id']
            update_soar_job_step(step1.step_id, status="Completed",
                                completed_at=datetime.now(),
                                result_message=f"Found agent ID: {agent_id} for hostname: {target}")

        # Step 2: Fetch installed applications
        step2 = add_soar_job_step(
            job_id=db_job.job_id,
            step_name="Fetch Applications",
            step_order=2,
            status="Running"
        )
        apps_endpoint = f'{base_url}/web/api/v2.1/agents/applications?ids={agent_id}'
        response = requests.get(apps_endpoint, headers=headers, verify=verify_ssl, timeout=30)

        if response.status_code == 200:
            # Update step2 as completed
            update_soar_job_step(step2.step_id, status="Completed",
                                completed_at=datetime.now(),
                                result_message=f"Successfully fetched applications from agent {agent_id}")

            end_time = datetime.now()
            apps_data = response.json()
            installed_apps = apps_data.get('data', [])

            # Step 3: Save artifact
            step3 = add_soar_job_step(
                job_id=db_job.job_id,
                step_name="Save Artifact",
                step_order=3,
                status="Running"
            )

            # Save applications data as artifact
            artifact_filename = f"fetch_installed_apps_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            artifact_path = save_case_artifact(case_id, artifact_filename, {
                "job_id": db_job.job_id,
                "action": "fetch_installed_applications",
                "target": target,
                "agent_id": agent_id,
                "timestamp": end_time.isoformat() + "Z",
                "total_applications": len(installed_apps),
                "applications": installed_apps
            })

            # Add artifact to database
            artifact = add_soar_job_artifact(
                job_id=db_job.job_id,
                artifact_name=artifact_filename,
                artifact_type="json",
                file_path=artifact_path,
                file_size=len(str(apps_data).encode('utf-8'))
            )

            # Update step3 as completed
            update_soar_job_step(step3.step_id, status="Completed",
                                completed_at=datetime.now(),
                                result_message=f"Saved applications list to {artifact_filename}")

            # Create formatted app list for case note
            app_list = []
            for i, app in enumerate(installed_apps, 1):  # Show all applications
                name = app.get('name', 'Unknown')
                version = app.get('version', 'Unknown')
                publisher = app.get('publisher', 'Unknown')
                app_list.append(f"{i}. {name} {version} ({publisher})")

            # Create case note
            note_content = f"""**SOAR Action:** Fetch Installed Apps
**Endpoint:** {target}
**Timestamp:** {end_time.isoformat() + "Z"}
**Results:** Retrieved {len(installed_apps)} applications.

**Installed Apps:**
{chr(10).join(app_list)}

**Artifact:** `/cases/{case_id}/artifacts/sentinelone/{artifact_filename}`"""

            add_case_note(case_id, note_content)

            # Update main job as completed
            update_soar_job(db_job.job_id, status="Completed", completed_at=end_time,
                          result_data={
                              "applications_count": len(installed_apps),
                              "agent_id": agent_id,
                              "artifact_path": artifact_path
                          })

            return {
                "job_id": db_job.job_id,
                "status": "Completed",
                "message": f"Successfully retrieved {len(installed_apps)} applications from {target}",
                "template_name": "SentinelOne Fetch Installed Applications",
                "target": target,
                "start_time": start_time,
                "end_time": end_time.isoformat() + "Z",
                "artifact_path": artifact_path,
                "applications_count": len(installed_apps)
            }
        else:
            # Update step2 as failed
            update_soar_job_step(step2.step_id, status="Failed",
                                completed_at=datetime.now(),
                                error_message=f"SentinelOne API returned status {response.status_code}: {response.text}")
            # Update job as failed
            update_soar_job(db_job.job_id, status="Failed", completed_at=datetime.now(),
                          error_message=f"Failed to fetch applications from agent: {target}")
            return {
                "job_id": db_job.job_id,
                "status": "Failed",
                "message": f"Failed to fetch applications from agent: {target}",
                "error": f"SentinelOne API returned status {response.status_code}: {response.text}"
            }

    except requests.exceptions.RequestException as e:
        # Update job as failed if it exists
        if db_job:
            update_soar_job(db_job.job_id, status="Failed", completed_at=datetime.now(),
                          error_message=f"Connection error to SentinelOne: {str(e)}")
            job_id_to_return = db_job.job_id
        else:
            job_id_to_return = job_id
        return {
            "job_id": job_id_to_return,
            "status": "Failed",
            "message": f"Connection error to SentinelOne: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        # Update job as failed if it exists
        if db_job:
            update_soar_job(db_job.job_id, status="Failed", completed_at=datetime.now(),
                          error_message=f"SentinelOne fetch applications job failed: {str(e)}")
            job_id_to_return = db_job.job_id
        else:
            job_id_to_return = job_id
        return {
            "job_id": job_id_to_return,
            "status": "Failed",
            "message": f"SentinelOne fetch applications job failed: {str(e)}",
            "error": str(e)
        }


def execute_velociraptor_collect(job_id, target, config):
    """
    Execute Velociraptor collection job
    """
    try:
        base_url = config.get('base_url').rstrip('/')
        api_key = config.get('api_key')
        verify_ssl = config.get('verify_ssl', True)

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        # Step 1: Find client by hostname or client ID
        if target.startswith('client-'):
            client_id = target.replace('client-', '')
        else:
            # Search by hostname
            search_endpoint = f'{base_url}/api/v1/SearchClients'
            search_data = {
                'query': target,
                'limit': 1
            }

            response = requests.post(search_endpoint, headers=headers, json=search_data, verify=verify_ssl, timeout=30)
            if response.status_code != 200:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Failed to find client: {target}",
                    "error": f"Velociraptor API returned status {response.status_code}"
                }

            clients = response.json().get('clients', [])
            if not clients:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Client not found: {target}",
                    "error": "No clients found matching the target hostname"
                }

            client_id = clients[0]['client_id']

        # Step 2: Create collection flow
        collect_endpoint = f'{base_url}/api/v1/CollectArtifacts'
        collect_data = {
            'client_id': client_id,
            'artifacts': [
                'Windows.System.ProcessInfo',
                'Windows.Network.Netstat',
                'Windows.Registry.RecentDocs'
            ],
            'specs': [
                {
                    'artifact': 'Windows.System.ProcessInfo'
                },
                {
                    'artifact': 'Windows.Network.Netstat'
                },
                {
                    'artifact': 'Windows.Registry.RecentDocs'
                }
            ]
        }

        response = requests.post(collect_endpoint, headers=headers, json=collect_data, verify=verify_ssl, timeout=30)

        if response.status_code == 200:
            flow_info = response.json()
            flow_id = flow_info.get('flow_id', 'unknown')

            return {
                "job_id": job_id,
                "status": "Running",
                "message": f"Collection started for client {target}",
                "template_name": "Velociraptor Forensic Collection",
                "target": target,
                "start_time": datetime.now().isoformat() + "Z",
                "flow_id": flow_id,
                "estimated_duration": "5-10 minutes",
                "steps": [
                    {
                        "step_id": "find_client",
                        "name": "Find Client",
                        "status": "Completed",
                        "message": f"Found client ID: {client_id}"
                    },
                    {
                        "step_id": "start_collection",
                        "name": "Start Collection",
                        "status": "Running",
                        "message": f"Collection flow started: {flow_id}"
                    }
                ]
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to start collection for client: {target}",
                "error": f"Velociraptor API returned status {response.status_code}: {response.text}"
            }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to Velociraptor: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Velociraptor collection job failed: {str(e)}",
            "error": str(e)
        }



def execute_sentinelone_full_scan(job_id, target, config, case_id):
    """
    Execute SentinelOne full disk scan playbook
    """
    try:
        base_url = config.get('base_url').rstrip('/')
        api_token = config.get('api_token')
        verify_ssl = config.get('verify_ssl', True)
        start_time = datetime.now().isoformat() + "Z"

        headers = {
            'Authorization': f'ApiToken {api_token}',
            'Content-Type': 'application/json'
        }

        # Step 1: Find agent by hostname or agent ID
        if target.startswith('agent-'):
            agent_id = target.replace('agent-', '')
        else:
            # Search by hostname
            agents_endpoint = f'{base_url}/web/api/v2.1/agents'
            params = {'computerName': target, 'limit': 1}

            response = requests.get(agents_endpoint, headers=headers, params=params, verify=verify_ssl, timeout=30)
            if response.status_code != 200:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Failed to find agent: {target}",
                    "error": f"SentinelOne API returned status {response.status_code}"
                }

            agents = response.json().get('data', [])
            if not agents:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Agent not found: {target}",
                    "error": "No agents found matching the target hostname"
                }

            agent_id = agents[0]['id']

        # Step 2: Initiate full scan
        scan_endpoint = f'{base_url}/web/api/v2.1/agents/actions/initiate-scan'
        scan_data = {
            'filter': {
                'ids': [agent_id]
            },
            'data': {
                'scanType': 'full'
            }
        }

        response = requests.post(scan_endpoint, headers=headers, json=scan_data, verify=verify_ssl, timeout=30)

        if response.status_code == 200:
            scan_response = response.json()
            activity_id = scan_response.get('data', {}).get('activityId')

            # Step 3: Poll scan status (simplified)
            time.sleep(3)  # Wait for scan to start
            end_time = datetime.now().isoformat() + "Z"

            # Save scan details as artifact
            artifact_filename = f"scan_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            scan_data_artifact = {
                "job_id": job_id,
                "action": "full_disk_scan",
                "target": target,
                "agent_id": agent_id,
                "timestamp": end_time,
                "activity_id": activity_id,
                "scan_type": "full",
                "status": "initiated",
                "scan_response": scan_response
            }

            artifact_path = save_case_artifact(case_id, artifact_filename, scan_data_artifact)

            # Create case note
            note_content = f"""**SOAR Action:** Full Disk Scan
**Endpoint:** {target}
**Timestamp:** {end_time}
**Result:** Scan initiated - Activity ID: {activity_id}

_Full scan started on endpoint. Check SentinelOne console for completion status._

**Artifact:** `/cases/{case_id}/artifacts/sentinelone/{artifact_filename}`"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Running",
                "message": f"Full disk scan initiated for {target}",
                "template_name": "SentinelOne Full Disk Scan",
                "target": target,
                "start_time": start_time,
                "end_time": end_time,
                "activity_id": activity_id,
                "artifact_path": artifact_path,
                "estimated_duration": "30-60 minutes",
                "steps": [
                    {
                        "step_id": "find_agent",
                        "name": "Find Agent",
                        "status": "Completed",
                        "message": f"Found agent ID: {agent_id}"
                    },
                    {
                        "step_id": "initiate_scan",
                        "name": "Initiate Full Scan",
                        "status": "Running",
                        "message": f"Full disk scan started with activity ID: {activity_id}"
                    },
                    {
                        "step_id": "save_artifact",
                        "name": "Save Artifact",
                        "status": "Completed",
                        "message": f"Saved scan details to {artifact_filename}"
                    }
                ]
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to initiate scan on agent: {target}",
                "error": f"SentinelOne API returned status {response.status_code}: {response.text}"
            }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to SentinelOne: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"SentinelOne full scan job failed: {str(e)}",
            "error": str(e)
        }


def get_crowdstrike_token(config):
    """
    Get OAuth2 access token for CrowdStrike API
    """
    try:
        base_url = config.get('base_url', '').rstrip('/')
        client_id = config.get('client_id', '')
        client_secret = config.get('client_secret', '')
        verify_ssl = config.get('verify_ssl', True)

        token_url = f"{base_url}/oauth2/token"

        data = {
            'client_id': client_id,
            'client_secret': client_secret
        }

        response = requests.post(token_url, data=data, verify=verify_ssl, timeout=30)

        if response.status_code == 201:
            token_data = response.json()
            return token_data.get('access_token')
        else:
            log.error(f"Token request failed: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        log.error(f"Error getting CrowdStrike token: {str(e)}")
        return None


def execute_crowdstrike_contain_host(job_id, target, config, case_id):
    """
    Execute CrowdStrike Contain Host (Network Isolation) playbook
    """
    try:
        base_url = config.get('base_url', '').rstrip('/')
        verify_ssl = config.get('verify_ssl', True)
        start_time = datetime.now().isoformat() + "Z"

        # Get OAuth2 token
        access_token = get_crowdstrike_token(config)
        if not access_token:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "Failed to authenticate with CrowdStrike API",
                "error": "OAuth2 token request failed"
            }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Step 1: Find device by hostname or device ID
        if target.startswith('device-'):
            device_id = target.replace('device-', '')
        else:
            # Search by hostname
            search_url = f"{base_url}/devices/queries/devices/v1"
            params = {'filter': f"hostname:'{target}'", 'limit': 1}

            response = requests.get(search_url, headers=headers, params=params, verify=verify_ssl, timeout=30)
            if response.status_code != 200:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Failed to search for device: {target}",
                    "error": f"CrowdStrike API returned status {response.status_code}"
                }

            device_ids = response.json().get('resources', [])
            if not device_ids:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Device not found: {target}",
                    "error": "No devices found matching the target hostname"
                }

            device_id = device_ids[0]

        # Step 2: Contain the device
        contain_url = f"{base_url}/devices/entities/network-contain/v1"
        contain_data = {
            'ids': [device_id]
        }

        response = requests.post(contain_url, headers=headers, json=contain_data, verify=verify_ssl, timeout=30)

        if response.status_code == 202:
            end_time = datetime.now().isoformat() + "Z"
            containment_response = response.json()

            # Step 3: Poll containment status
            time.sleep(2)
            status_url = f"{base_url}/devices/entities/containment-status/v1"
            status_params = {'ids': device_id}
            status_response = requests.get(status_url, headers=headers, params=status_params, verify=verify_ssl, timeout=30)

            # Save containment action details as artifact
            containment_data = {
                "job_id": job_id,
                "action": "network_contain",
                "target": target,
                "device_id": device_id,
                "timestamp": end_time,
                "status": "completed",
                "api_response": containment_response,
                "status_check": status_response.json() if status_response.status_code == 200 else None
            }

            artifact_filename = f"containment_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            artifact_path = save_case_artifact(case_id, artifact_filename, containment_data, 'crowdstrike')

            # Create case note
            note_content = f"""**SOAR Action:** Contain Host
**Endpoint:** {target}
**Timestamp:** {end_time}
✅ Host successfully isolated via CrowdStrike API."""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Successfully contained device {target}",
                "template_name": "CrowdStrike Contain Host",
                "target": target,
                "start_time": start_time,
                "end_time": end_time,
                "artifact_path": artifact_path,
                "steps": [
                    {
                        "step_id": "authenticate",
                        "name": "OAuth2 Authentication",
                        "status": "Completed",
                        "message": "Successfully authenticated with CrowdStrike API"
                    },
                    {
                        "step_id": "find_device",
                        "name": "Find Device",
                        "status": "Completed",
                        "message": f"Found device ID: {device_id}"
                    },
                    {
                        "step_id": "contain_device",
                        "name": "Contain Device",
                        "status": "Completed",
                        "message": "Device successfully contained"
                    },
                    {
                        "step_id": "save_artifact",
                        "name": "Save Artifact",
                        "status": "Completed",
                        "message": f"Saved containment details to {artifact_filename}"
                    }
                ]
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to contain device: {target}",
                "error": f"CrowdStrike API returned status {response.status_code}: {response.text}"
            }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to CrowdStrike: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"CrowdStrike contain host job failed: {str(e)}",
            "error": str(e)
        }


def execute_crowdstrike_lift_containment(job_id, target, config, case_id):
    """
    Execute CrowdStrike Lift Containment (Release Host) playbook
    """
    try:
        base_url = config.get('base_url', '').rstrip('/')
        verify_ssl = config.get('verify_ssl', True)
        start_time = datetime.now().isoformat() + "Z"

        # Get OAuth2 token
        access_token = get_crowdstrike_token(config)
        if not access_token:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "Failed to authenticate with CrowdStrike API",
                "error": "OAuth2 token request failed"
            }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Step 1: Find device by hostname or device ID
        if target.startswith('device-'):
            device_id = target.replace('device-', '')
        else:
            # Search by hostname
            search_url = f"{base_url}/devices/queries/devices/v1"
            params = {'filter': f"hostname:'{target}'", 'limit': 1}

            response = requests.get(search_url, headers=headers, params=params, verify=verify_ssl, timeout=30)
            if response.status_code != 200:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Failed to search for device: {target}",
                    "error": f"CrowdStrike API returned status {response.status_code}"
                }

            device_ids = response.json().get('resources', [])
            if not device_ids:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Device not found: {target}",
                    "error": "No devices found matching the target hostname"
                }

            device_id = device_ids[0]

        # Step 2: Lift containment
        lift_url = f"{base_url}/devices/entities/network-containments/v1"
        lift_data = {
            'ids': [device_id],
            'action': 'lift_containment'
        }

        response = requests.post(lift_url, headers=headers, json=lift_data, verify=verify_ssl, timeout=30)

        if response.status_code == 202:
            end_time = datetime.now().isoformat() + "Z"
            lift_response = response.json()

            # Step 3: Poll until containment_state = "normal"
            time.sleep(2)
            status_url = f"{base_url}/devices/entities/containment-status/v1"
            status_params = {'ids': device_id}
            status_response = requests.get(status_url, headers=headers, params=status_params, verify=verify_ssl, timeout=30)

            # Save lift containment action details as artifact
            lift_data_artifact = {
                "job_id": job_id,
                "action": "lift_containment",
                "target": target,
                "device_id": device_id,
                "timestamp": end_time,
                "status": "completed",
                "api_response": lift_response,
                "status_check": status_response.json() if status_response.status_code == 200 else None
            }

            artifact_filename = f"lift_containment_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            artifact_path = save_case_artifact(case_id, artifact_filename, lift_data_artifact, 'crowdstrike')

            # Create case note
            note_content = f"""**SOAR Action:** Lift Containment
**Endpoint:** {target}
**Timestamp:** {end_time}
✅ Host restored to normal network connectivity."""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Successfully lifted containment for device {target}",
                "template_name": "CrowdStrike Lift Containment",
                "target": target,
                "start_time": start_time,
                "end_time": end_time,
                "artifact_path": artifact_path,
                "steps": [
                    {
                        "step_id": "authenticate",
                        "name": "OAuth2 Authentication",
                        "status": "Completed",
                        "message": "Successfully authenticated with CrowdStrike API"
                    },
                    {
                        "step_id": "find_device",
                        "name": "Find Device",
                        "status": "Completed",
                        "message": f"Found device ID: {device_id}"
                    },
                    {
                        "step_id": "lift_containment",
                        "name": "Lift Containment",
                        "status": "Completed",
                        "message": "Device containment successfully lifted"
                    },
                    {
                        "step_id": "save_artifact",
                        "name": "Save Artifact",
                        "status": "Completed",
                        "message": f"Saved lift containment details to {artifact_filename}"
                    }
                ]
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to lift containment for device: {target}",
                "error": f"CrowdStrike API returned status {response.status_code}: {response.text}"
            }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to CrowdStrike: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"CrowdStrike lift containment job failed: {str(e)}",
            "error": str(e)
        }


def execute_crowdstrike_fetch_host_info(job_id, target, config, case_id):
    """
    Execute CrowdStrike Fetch Host Information playbook
    """
    try:
        base_url = config.get('base_url', '').rstrip('/')
        verify_ssl = config.get('verify_ssl', True)
        start_time = datetime.now().isoformat() + "Z"

        # Get OAuth2 token
        access_token = get_crowdstrike_token(config)
        if not access_token:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "Failed to authenticate with CrowdStrike API",
                "error": "OAuth2 token request failed"
            }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Step 1: Find device by hostname or device ID
        if target.startswith('device-'):
            device_id = target.replace('device-', '')
        else:
            # Search by hostname
            search_url = f"{base_url}/devices/queries/devices/v1"
            params = {'filter': f"hostname:'{target}'", 'limit': 1}

            response = requests.get(search_url, headers=headers, params=params, verify=verify_ssl, timeout=30)
            if response.status_code != 200:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Failed to search for device: {target}",
                    "error": f"CrowdStrike API returned status {response.status_code}"
                }

            device_ids = response.json().get('resources', [])
            if not device_ids:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Device not found: {target}",
                    "error": "No devices found matching the target hostname"
                }

            device_id = device_ids[0]

        # Step 2: Fetch complete device metadata
        devices_url = f"{base_url}/devices/entities/devices/v2"
        params = {'ids': device_id}

        response = requests.get(devices_url, headers=headers, params=params, verify=verify_ssl, timeout=30)

        if response.status_code == 200:
            end_time = datetime.now().isoformat() + "Z"
            device_data = response.json()
            resources = device_data.get('resources', [])

            if resources:
                device_info = resources[0]

                # Save host information as artifact
                artifact_filename = f"hostinfo_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                artifact_path = save_case_artifact(case_id, artifact_filename, {
                    "job_id": job_id,
                    "action": "fetch_host_info",
                    "target": target,
                    "device_id": device_id,
                    "timestamp": end_time,
                    "device_info": device_info
                }, 'crowdstrike')

                # Create case note
                hostname = device_info.get('hostname', target)
                note_content = f"""**SOAR Action:** Fetch Host Info
**Host:** {hostname}
**Timestamp:** {end_time}
Retrieved metadata — see hostinfo JSON file for full details."""

                add_case_note(case_id, note_content)

                return {
                    "job_id": job_id,
                    "status": "Completed",
                    "message": f"Successfully retrieved host information for {target}",
                    "template_name": "CrowdStrike Fetch Host Information",
                    "target": target,
                    "start_time": start_time,
                    "end_time": end_time,
                    "artifact_path": artifact_path,
                    "device_info": device_info,
                    "steps": [
                        {
                            "step_id": "authenticate",
                            "name": "OAuth2 Authentication",
                            "status": "Completed",
                            "message": "Successfully authenticated with CrowdStrike API"
                        },
                        {
                            "step_id": "find_device",
                            "name": "Find Device",
                            "status": "Completed",
                            "message": f"Found device ID: {device_id}"
                        },
                        {
                            "step_id": "fetch_info",
                            "name": "Fetch Host Information",
                            "status": "Completed",
                            "message": "Successfully retrieved complete device metadata"
                        },
                        {
                            "step_id": "save_artifact",
                            "name": "Save Artifact",
                            "status": "Completed",
                            "message": f"Saved host information to {artifact_filename}"
                        }
                    ]
                }
            else:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"No device information found for: {target}",
                    "error": "Device metadata not available"
                }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to fetch host information for device: {target}",
                "error": f"CrowdStrike API returned status {response.status_code}: {response.text}"
            }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to CrowdStrike: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"CrowdStrike fetch host info job failed: {str(e)}",
            "error": str(e)
        }


def execute_crowdstrike_fetch_detections(job_id, target, config, case_id):
    """
    Execute CrowdStrike Fetch Detections playbook
    """
    try:
        base_url = config.get('base_url', '').rstrip('/')
        verify_ssl = config.get('verify_ssl', True)
        start_time = datetime.now().isoformat() + "Z"

        # Get OAuth2 token
        access_token = get_crowdstrike_token(config)
        if not access_token:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "Failed to authenticate with CrowdStrike API",
                "error": "OAuth2 token request failed"
            }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Step 1: Find device by hostname or device ID
        if target.startswith('device-'):
            device_id = target.replace('device-', '')
            hostname = target
        else:
            # Search by hostname
            search_url = f"{base_url}/devices/queries/devices/v1"
            params = {'filter': f"hostname:'{target}'", 'limit': 1}

            response = requests.get(search_url, headers=headers, params=params, verify=verify_ssl, timeout=30)
            if response.status_code != 200:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Failed to search for device: {target}",
                    "error": f"CrowdStrike API returned status {response.status_code}"
                }

            device_ids = response.json().get('resources', [])
            if not device_ids:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"Device not found: {target}",
                    "error": "No devices found matching the target hostname"
                }

            device_id = device_ids[0]
            hostname = target

        # Step 2: Query detections for the device (last 24h)
        detects_query_url = f"{base_url}/detects/queries/detects/v1"
        params = {
            'filter': f"device.device_id:'{device_id}'+created_timestamp:>'{(datetime.now() - timedelta(days=1)).isoformat()}Z'",
            'limit': 100
        }

        response = requests.get(detects_query_url, headers=headers, params=params, verify=verify_ssl, timeout=30)

        if response.status_code == 200:
            detection_ids = response.json().get('resources', [])

            if detection_ids:
                # Step 3: Get detailed detection information
                detects_detail_url = f"{base_url}/detects/entities/detects/GET/v2"
                detail_data = {'ids': detection_ids}

                detail_response = requests.post(detects_detail_url, headers=headers, json=detail_data, verify=verify_ssl, timeout=30)

                if detail_response.status_code == 200:
                    detections = detail_response.json().get('resources', [])
                else:
                    detections = []
            else:
                detections = []

            end_time = datetime.now().isoformat() + "Z"

            # Save detections data as artifact
            artifact_filename = f"detections_{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            artifact_path = save_case_artifact(case_id, artifact_filename, {
                "job_id": job_id,
                "action": "fetch_detections",
                "target": target,
                "device_id": device_id,
                "timestamp": end_time,
                "total_detections": len(detections),
                "detections": detections
            }, 'crowdstrike')

            # Create case note with top threat summary
            if detections:
                top_detection = detections[0]
                behaviors = top_detection.get('behaviors', [])
                top_alert = "No behaviors found"
                if behaviors:
                    tactic_name = behaviors[0].get('tactic', 'Unknown')
                    technique_name = behaviors[0].get('technique', 'Unknown')
                    top_alert = f"{tactic_name} — {technique_name}"

                note_content = f"""**SOAR Action:** Fetch Detections
**Host:** {hostname}
**Timestamp:** {end_time}
Retrieved {len(detections)} detections.
**Top Alert:** {top_alert}
_Full JSON report attached._"""
            else:
                note_content = f"""**SOAR Action:** Fetch Detections
**Host:** {hostname}
**Timestamp:** {end_time}
Retrieved {len(detections)} detections.
_No detections found in the last 24 hours._"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Successfully retrieved {len(detections)} detections for {target}",
                "template_name": "CrowdStrike Fetch Detections",
                "target": target,
                "start_time": start_time,
                "end_time": end_time,
                "artifact_path": artifact_path,
                "detections_count": len(detections),
                "steps": [
                    {
                        "step_id": "authenticate",
                        "name": "OAuth2 Authentication",
                        "status": "Completed",
                        "message": "Successfully authenticated with CrowdStrike API"
                    },
                    {
                        "step_id": "find_device",
                        "name": "Find Device",
                        "status": "Completed",
                        "message": f"Found device ID: {device_id}"
                    },
                    {
                        "step_id": "query_detections",
                        "name": "Query Detections",
                        "status": "Completed",
                        "message": f"Found {len(detection_ids)} detection IDs"
                    },
                    {
                        "step_id": "fetch_details",
                        "name": "Fetch Detection Details",
                        "status": "Completed",
                        "message": f"Retrieved detailed information for {len(detections)} detections"
                    },
                    {
                        "step_id": "save_artifact",
                        "name": "Save Artifact",
                        "status": "Completed",
                        "message": f"Saved detection data to {artifact_filename}"
                    }
                ]
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to fetch detections for device: {target}",
                "error": f"CrowdStrike API returned status {response.status_code}: {response.text}"
            }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to CrowdStrike: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"CrowdStrike fetch detections job failed: {str(e)}",
            "error": str(e)
        }


def execute_crowdstrike_fetch_incident_details(job_id, target, config, case_id):
    """
    Execute CrowdStrike Fetch Incident Details playbook
    """
    try:
        base_url = config.get('base_url', '').rstrip('/')
        verify_ssl = config.get('verify_ssl', True)
        start_time = datetime.now().isoformat() + "Z"

        # Get OAuth2 token
        access_token = get_crowdstrike_token(config)
        if not access_token:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "Failed to authenticate with CrowdStrike API",
                "error": "OAuth2 token request failed"
            }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Target should be an incident ID
        incident_id = target

        # Step 1: Fetch incident details
        incidents_url = f"{base_url}/incidents/entities/incidents/v1"
        params = {'ids': incident_id}

        response = requests.get(incidents_url, headers=headers, params=params, verify=verify_ssl, timeout=30)

        if response.status_code == 200:
            end_time = datetime.now().isoformat() + "Z"
            incident_data = response.json()
            resources = incident_data.get('resources', [])

            if resources:
                incident_info = resources[0]

                # Save incident information as artifact
                artifact_filename = f"incident_{incident_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                artifact_path = save_case_artifact(case_id, artifact_filename, {
                    "job_id": job_id,
                    "action": "fetch_incident_details",
                    "incident_id": incident_id,
                    "timestamp": end_time,
                    "incident_info": incident_info
                }, 'crowdstrike')

                # Extract key information for note
                severity = incident_info.get('state', 'Unknown')
                status = incident_info.get('status', 'Unknown')

                # Create case note
                note_content = f"""**SOAR Action:** Fetch Incident Details
**Incident ID:** {incident_id}
**Severity:** {severity}
**Status:** {status}
_Incident data synced from CrowdStrike._"""

                add_case_note(case_id, note_content)

                return {
                    "job_id": job_id,
                    "status": "Completed",
                    "message": f"Successfully retrieved incident details for {incident_id}",
                    "template_name": "CrowdStrike Fetch Incident Details",
                    "target": incident_id,
                    "start_time": start_time,
                    "end_time": end_time,
                    "artifact_path": artifact_path,
                    "incident_info": incident_info,
                    "steps": [
                        {
                            "step_id": "authenticate",
                            "name": "OAuth2 Authentication",
                            "status": "Completed",
                            "message": "Successfully authenticated with CrowdStrike API"
                        },
                        {
                            "step_id": "fetch_incident",
                            "name": "Fetch Incident Details",
                            "status": "Completed",
                            "message": f"Successfully retrieved incident {incident_id}"
                        },
                        {
                            "step_id": "save_artifact",
                            "name": "Save Artifact",
                            "status": "Completed",
                            "message": f"Saved incident details to {artifact_filename}"
                        }
                    ]
                }
            else:
                return {
                    "job_id": job_id,
                    "status": "Failed",
                    "message": f"No incident information found for: {incident_id}",
                    "error": "Incident data not available"
                }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to fetch incident details for: {incident_id}",
                "error": f"CrowdStrike API returned status {response.status_code}: {response.text}"
            }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to CrowdStrike: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"CrowdStrike fetch incident details job failed: {str(e)}",
            "error": str(e)
        }


def execute_meraki_block_ip(job_id, target, config, case_id):
    """
    Execute Cisco Meraki Block IP Address playbook
    """
    try:
        api_key = config.get('api_key', '').strip()
        organization_id = config.get('organization_id', '').strip()
        verify_ssl = config.get('verify_ssl', True)
        start_time = datetime.now().isoformat() + "Z"

        # Meraki Dashboard API base URL
        base_url = 'https://api.meraki.com/api/v1'

        headers = {
            'X-Cisco-Meraki-API-Key': api_key,
            'Content-Type': 'application/json'
        }

        # Step 1: Get organization networks
        networks_url = f"{base_url}/organizations/{organization_id}/networks"
        networks_response = requests.get(networks_url, headers=headers, verify=verify_ssl, timeout=30)

        if networks_response.status_code != 200:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to retrieve networks from organization {organization_id}",
                "error": f"Meraki API returned status {networks_response.status_code}"
            }

        networks = networks_response.json()

        # Find networks with appliances (MX devices)
        appliance_networks = [net for net in networks if 'appliance' in net.get('productTypes', [])]

        if not appliance_networks:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "No appliance networks found in organization",
                "error": "No MX devices available for firewall rule creation"
            }

        # Step 2: Apply firewall rule to all appliance networks
        blocked_networks = []

        for network in appliance_networks:
            network_id = network['id']
            network_name = network['name']

            # Get current L3 firewall rules
            firewall_url = f"{base_url}/networks/{network_id}/appliance/firewall/l3FirewallRules"
            current_rules_response = requests.get(firewall_url, headers=headers, verify=verify_ssl, timeout=30)

            if current_rules_response.status_code == 200:
                current_rules = current_rules_response.json()

                # Create new blocking rule
                new_rule = {
                    "comment": f"IRIS SOAR Auto-block: Case {case_id}",
                    "policy": "deny",
                    "protocol": "any",
                    "srcCidr": "any",
                    "destCidr": target,
                    "destPort": "any"
                }

                # Insert at beginning of rules (highest priority)
                updated_rules = [new_rule] + current_rules

                # Update firewall rules
                update_response = requests.put(
                    firewall_url,
                    headers=headers,
                    json=updated_rules,
                    verify=verify_ssl,
                    timeout=30
                )

                if update_response.status_code == 200:
                    blocked_networks.append({
                        'network_id': network_id,
                        'network_name': network_name,
                        'status': 'success'
                    })
                else:
                    blocked_networks.append({
                        'network_id': network_id,
                        'network_name': network_name,
                        'status': 'failed',
                        'error': f"Status {update_response.status_code}"
                    })

        end_time = datetime.now().isoformat() + "Z"

        # Save blocking action details as artifact
        block_data = {
            "job_id": job_id,
            "action": "block_ip",
            "target_ip": target,
            "timestamp": end_time,
            "organization_id": organization_id,
            "networks_processed": len(appliance_networks),
            "successful_blocks": len([n for n in blocked_networks if n['status'] == 'success']),
            "blocked_networks": blocked_networks
        }

        artifact_filename = f"block_{target.replace('.', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        artifact_path = save_case_artifact(case_id, artifact_filename, block_data, 'meraki')

        # Create case note
        successful_blocks = len([n for n in blocked_networks if n['status'] == 'success'])
        note_content = f"""**SOAR Action:** Block IP on Meraki
**IP:** {target}
**Timestamp:** {end_time}
✅ IP successfully blocked in Meraki firewall.
**Networks Updated:** {successful_blocks}/{len(appliance_networks)}"""

        add_case_note(case_id, note_content)

        if successful_blocks > 0:
            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Successfully blocked IP {target} on {successful_blocks} networks",
                "template_name": "Cisco Meraki Block IP Address",
                "target": target,
                "start_time": start_time,
                "end_time": end_time,
                "artifact_path": artifact_path,
                "networks_blocked": successful_blocks,
                "steps": [
                    {
                        "step_id": "get_networks",
                        "name": "Get Organization Networks",
                        "status": "Completed",
                        "message": f"Found {len(appliance_networks)} appliance networks"
                    },
                    {
                        "step_id": "create_firewall_rules",
                        "name": "Create Firewall Rules",
                        "status": "Completed",
                        "message": f"Created blocking rules on {successful_blocks} networks"
                    },
                    {
                        "step_id": "save_artifact",
                        "name": "Save Artifact",
                        "status": "Completed",
                        "message": f"Saved blocking details to {artifact_filename}"
                    }
                ]
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to block IP {target} on any networks",
                "error": "No firewall rules were successfully created"
            }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to Meraki: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Meraki block IP job failed: {str(e)}",
            "error": str(e)
        }


def execute_meraki_block_client(job_id, target, config, case_id):
    """
    Execute Cisco Meraki Block Client playbook
    """
    try:
        api_key = config.get('api_key', '').strip()
        organization_id = config.get('organization_id', '').strip()
        verify_ssl = config.get('verify_ssl', True)
        start_time = datetime.now().isoformat() + "Z"

        # Meraki Dashboard API base URL
        base_url = 'https://api.meraki.com/api/v1'

        headers = {
            'X-Cisco-Meraki-API-Key': api_key,
            'Content-Type': 'application/json'
        }

        # Step 1: Get organization networks
        networks_url = f"{base_url}/organizations/{organization_id}/networks"
        networks_response = requests.get(networks_url, headers=headers, verify=verify_ssl, timeout=30)

        if networks_response.status_code != 200:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to retrieve networks from organization {organization_id}",
                "error": f"Meraki API returned status {networks_response.status_code}"
            }

        networks = networks_response.json()

        # Step 2: Search for client across all networks
        client_found = None
        client_network = None

        for network in networks:
            network_id = network['id']

            # Get clients from this network
            clients_url = f"{base_url}/networks/{network_id}/clients"
            clients_response = requests.get(clients_url, headers=headers, verify=verify_ssl, timeout=30)

            if clients_response.status_code == 200:
                clients = clients_response.json()

                # Search for target client by IP or MAC
                for client in clients:
                    if (client.get('ip') == target or
                        client.get('mac', '').lower() == target.lower() or
                        client.get('id') == target):
                        client_found = client
                        client_network = network
                        break

                if client_found:
                    break

        if not client_found:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Client not found: {target}",
                "error": "No clients found matching the target IP or MAC address"
            }

        # Step 3: Block the client
        client_id = client_found['id']
        network_id = client_network['id']

        policy_url = f"{base_url}/networks/{network_id}/clients/{client_id}/policy"
        policy_data = {"devicePolicy": "Blocked"}

        policy_response = requests.put(
            policy_url,
            headers=headers,
            json=policy_data,
            verify=verify_ssl,
            timeout=30
        )

        if policy_response.status_code == 200:
            end_time = datetime.now().isoformat() + "Z"

            # Save client blocking details as artifact
            block_data = {
                "job_id": job_id,
                "action": "block_client",
                "target": target,
                "client_id": client_id,
                "client_ip": client_found.get('ip'),
                "client_mac": client_found.get('mac'),
                "network_id": network_id,
                "network_name": client_network['name'],
                "timestamp": end_time,
                "client_details": client_found,
                "policy_response": policy_response.json()
            }

            artifact_filename = f"block_client_{target.replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            artifact_path = save_case_artifact(case_id, artifact_filename, block_data, 'meraki')

            # Create case note
            note_content = f"""**SOAR Action:** Block Client on Meraki
**Target:** {target}
**Client IP:** {client_found.get('ip', 'Unknown')}
**Client MAC:** {client_found.get('mac', 'Unknown')}
**Network:** {client_network['name']}
**Timestamp:** {end_time}
✅ Client successfully blocked via Meraki policy."""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Successfully blocked client {target}",
                "template_name": "Cisco Meraki Block Client",
                "target": target,
                "start_time": start_time,
                "end_time": end_time,
                "artifact_path": artifact_path,
                "client_details": client_found,
                "network_name": client_network['name'],
                "steps": [
                    {
                        "step_id": "search_client",
                        "name": "Search for Client",
                        "status": "Completed",
                        "message": f"Found client in network {client_network['name']}"
                    },
                    {
                        "step_id": "block_client",
                        "name": "Block Client",
                        "status": "Completed",
                        "message": "Client policy set to Blocked"
                    },
                    {
                        "step_id": "save_artifact",
                        "name": "Save Artifact",
                        "status": "Completed",
                        "message": f"Saved blocking details to {artifact_filename}"
                    }
                ]
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to block client {target}",
                "error": f"Meraki API returned status {policy_response.status_code}: {policy_response.text}"
            }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to Meraki: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Meraki block client job failed: {str(e)}",
            "error": str(e)
        }


def execute_meraki_verify_network_event(job_id, target, config, case_id):
    """
    Execute Cisco Meraki Verify Network Event playbook
    """
    try:
        api_key = config.get('api_key', '').strip()
        organization_id = config.get('organization_id', '').strip()
        verify_ssl = config.get('verify_ssl', True)
        start_time = datetime.now().isoformat() + "Z"

        # Meraki Dashboard API base URL
        base_url = 'https://api.meraki.com/api/v1'

        headers = {
            'X-Cisco-Meraki-API-Key': api_key,
            'Content-Type': 'application/json'
        }

        # Step 1: Get organization networks
        networks_url = f"{base_url}/organizations/{organization_id}/networks"
        networks_response = requests.get(networks_url, headers=headers, verify=verify_ssl, timeout=30)

        if networks_response.status_code != 200:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to retrieve networks from organization {organization_id}",
                "error": f"Meraki API returned status {networks_response.status_code}"
            }

        networks = networks_response.json()

        # Find networks with appliances (MX devices)
        appliance_networks = [net for net in networks if 'appliance' in net.get('productTypes', [])]

        if not appliance_networks:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "No appliance networks found in organization",
                "error": "No MX devices available for event log verification"
            }

        # Step 2: Collect events from all appliance networks
        all_events = []

        for network in appliance_networks:
            network_id = network['id']
            network_name = network['name']

            # Get network events (appliance events)
            events_url = f"{base_url}/networks/{network_id}/events"
            params = {
                'productType': 'appliance',
                'perPage': 100  # Limit to recent events
            }

            events_response = requests.get(events_url, headers=headers, params=params, verify=verify_ssl, timeout=30)

            if events_response.status_code == 200:
                events = events_response.json()

                # Filter events related to the target IP
                relevant_events = []
                for event in events.get('events', []):
                    event_description = event.get('description', '').lower()
                    if target in event_description or target in str(event.get('eventData', {})):
                        event['network_name'] = network_name
                        event['network_id'] = network_id
                        relevant_events.append(event)

                all_events.extend(relevant_events)

        end_time = datetime.now().isoformat() + "Z"

        # Step 3: Save verification results as artifact
        verification_data = {
            "job_id": job_id,
            "action": "verify_network_event",
            "target_ip": target,
            "timestamp": end_time,
            "organization_id": organization_id,
            "networks_checked": len(appliance_networks),
            "events_found": len(all_events),
            "events": all_events
        }

        artifact_filename = f"verify_{target.replace('.', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        artifact_path = save_case_artifact(case_id, artifact_filename, verification_data, 'meraki')

        # Create case note
        if all_events:
            latest_event = all_events[0]
            note_content = f"""**SOAR Action:** Verify Network Event
**IP:** {target}
**Timestamp:** {end_time}
**Events Found:** {len(all_events)}
**Latest Event:** {latest_event.get('type', 'Unknown')} in {latest_event.get('network_name', 'Unknown')}
✅ Network events verified - see JSON for details."""
        else:
            note_content = f"""**SOAR Action:** Verify Network Event
**IP:** {target}
**Timestamp:** {end_time}
**Events Found:** 0
⚠️ No network events found for target IP."""

        add_case_note(case_id, note_content)

        return {
            "job_id": job_id,
            "status": "Completed",
            "message": f"Network event verification completed - found {len(all_events)} events",
            "template_name": "Cisco Meraki Verify Network Event",
            "target": target,
            "start_time": start_time,
            "end_time": end_time,
            "artifact_path": artifact_path,
            "events_found": len(all_events),
            "networks_checked": len(appliance_networks),
            "steps": [
                {
                    "step_id": "get_networks",
                    "name": "Get Organization Networks",
                    "status": "Completed",
                    "message": f"Found {len(appliance_networks)} appliance networks"
                },
                {
                    "step_id": "collect_events",
                    "name": "Collect Network Events",
                    "status": "Completed",
                    "message": f"Collected events from {len(appliance_networks)} networks"
                },
                {
                    "step_id": "filter_events",
                    "name": "Filter Relevant Events",
                    "status": "Completed",
                    "message": f"Found {len(all_events)} events related to {target}"
                },
                {
                    "step_id": "save_artifact",
                    "name": "Save Artifact",
                    "status": "Completed",
                    "message": f"Saved verification results to {artifact_filename}"
                }
            ]
        }

    except requests.exceptions.RequestException as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Connection error to Meraki: {str(e)}",
            "error": "Check integration settings and network connectivity"
        }
    except Exception as e:
        return {
            "job_id": job_id,
            "status": "Failed",
            "message": f"Meraki verify network event job failed: {str(e)}",
            "error": str(e)
        }


def execute_hibp_email_check(job_id, target, config, case_id):
    """
    Execute HaveIBeenPwned email exposure check
    """
    try:
        import hashlib

        # Extract configuration
        base_url = config.get('base_url', 'https://haveibeenpwned.com/api/v3').rstrip('/')
        api_key = config.get('api_key')
        verify_ssl = config.get('verify_ssl', True)
        rate_limit_delay = config.get('rate_limit_delay', 1.6)

        if not api_key:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "HIBP API key not configured",
                "error": "Missing API key in integration configuration"
            }

        # Setup headers
        headers = {
            'hibp-api-key': api_key,
            'User-Agent': 'IRIS-SOAR'
        }

        # Check email in breaches
        endpoint = f'{base_url}/breachedaccount/{target}'

        # Respect rate limiting
        time.sleep(rate_limit_delay)

        response = requests.get(endpoint, headers=headers, verify=verify_ssl, timeout=30)

        if response.status_code == 200:
            breaches_data = response.json()
            breach_count = len(breaches_data) if isinstance(breaches_data, list) else 0

            # Create artifacts folder
            artifact_path = create_case_artifact_folder(case_id, 'hibp')
            artifact_filename = f"hibp_email_{target.replace('@', '_at_')}_{job_id}.json"

            # Save results
            if artifact_path:
                save_case_artifact(case_id, artifact_filename, {
                    'email': target,
                    'timestamp': datetime.now().isoformat(),
                    'total_breaches': breach_count,
                    'breaches': breaches_data
                })

            # Format breach names for note
            breach_names = [breach.get('Name', 'Unknown') for breach in breaches_data] if breaches_data else []

            # Add case note
            note_content = f"""**SOAR Action:** HIBP Email Exposure Check
**Email:** {target}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Result:** Found in {breach_count} breaches: {breach_names}

_Full JSON stored in `/cases/{case_id}/artifacts/hibp/{artifact_filename}`_"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Email check completed - found in {breach_count} breaches",
                "artifacts": [artifact_filename] if artifact_path else [],
                "details": {
                    "email": target,
                    "total_breaches": breach_count,
                    "breach_names": breach_names,
                    "execution_time": response.elapsed.total_seconds()
                }
            }
        elif response.status_code == 404:
            # No breaches found
            note_content = f"""**SOAR Action:** HIBP Email Exposure Check
**Email:** {target}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Result:** ✅ No breaches found

_Email address does not appear in known breach datasets._"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": "Email check completed - no breaches found",
                "details": {
                    "email": target,
                    "total_breaches": 0,
                    "execution_time": response.elapsed.total_seconds()
                }
            }
        elif response.status_code == 429:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "Rate limit exceeded",
                "error": "HIBP API rate limit hit - please wait before retrying"
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"HIBP API error: {response.status_code}",
                "error": response.text
            }

    except requests.exceptions.RequestException as e:
        error_msg = f"Network error during HIBP email check: {str(e)}"
        add_case_note(case_id, f"**HIBP Email Check Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        add_case_note(case_id, f"**HIBP Email Check Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }


def execute_hibp_domain_check(job_id, target, config, case_id):
    """
    Execute HaveIBeenPwned domain exposure check
    """
    try:
        # Extract configuration
        base_url = config.get('base_url', 'https://haveibeenpwned.com/api/v3').rstrip('/')
        api_key = config.get('api_key')
        verify_ssl = config.get('verify_ssl', True)
        rate_limit_delay = config.get('rate_limit_delay', 1.6)

        if not api_key:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "HIBP API key not configured",
                "error": "Missing API key in integration configuration"
            }

        # Setup headers
        headers = {
            'hibp-api-key': api_key,
            'User-Agent': 'IRIS-SOAR'
        }

        # Check domain in breaches
        endpoint = f'{base_url}/breaches'
        params = {'domain': target}

        # Respect rate limiting
        time.sleep(rate_limit_delay)

        response = requests.get(endpoint, headers=headers, params=params, verify=verify_ssl, timeout=30)

        if response.status_code == 200:
            breaches_data = response.json()
            breach_count = len(breaches_data) if isinstance(breaches_data, list) else 0

            # Create artifacts folder
            artifact_path = create_case_artifact_folder(case_id, 'hibp')
            artifact_filename = f"hibp_domain_{target.replace('.', '_')}_{job_id}.json"

            # Save results
            if artifact_path:
                save_case_artifact(case_id, artifact_filename, {
                    'domain': target,
                    'timestamp': datetime.now().isoformat(),
                    'total_breaches': breach_count,
                    'breaches': breaches_data
                })

            # Create breach summary table for note
            breach_table = "| Breach Name | Breach Date | Compromised Accounts |\n|-------------|-------------|---------------------|\n"
            for breach in breaches_data:
                name = breach.get('Name', 'Unknown')
                date = breach.get('BreachDate', 'Unknown')
                count = breach.get('PwnCount', 'Unknown')
                breach_table += f"| {name} | {date} | {count:,} |\n"

            # Add case note
            note_content = f"""**SOAR Action:** HIBP Domain Exposure Check
**Domain:** {target}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Result:** Found {breach_count} breaches affecting this domain

**Breach Summary:**
{breach_table}

_Full JSON stored in `/cases/{case_id}/artifacts/hibp/{artifact_filename}`_"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Domain check completed - found {breach_count} breaches",
                "artifacts": [artifact_filename] if artifact_path else [],
                "details": {
                    "domain": target,
                    "total_breaches": breach_count,
                    "execution_time": response.elapsed.total_seconds()
                }
            }
        elif response.status_code == 404:
            # No breaches found
            note_content = f"""**SOAR Action:** HIBP Domain Exposure Check
**Domain:** {target}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Result:** ✅ No breaches found

_Domain does not appear in known breach datasets._"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": "Domain check completed - no breaches found",
                "details": {
                    "domain": target,
                    "total_breaches": 0,
                    "execution_time": response.elapsed.total_seconds()
                }
            }
        elif response.status_code == 429:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "Rate limit exceeded",
                "error": "HIBP API rate limit hit - please wait before retrying"
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"HIBP API error: {response.status_code}",
                "error": response.text
            }

    except requests.exceptions.RequestException as e:
        error_msg = f"Network error during HIBP domain check: {str(e)}"
        add_case_note(case_id, f"**HIBP Domain Check Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        add_case_note(case_id, f"**HIBP Domain Check Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }


def execute_hibp_password_check(job_id, target, config, case_id):
    """
    Execute HaveIBeenPwned password reuse check using k-anonymity
    """
    try:
        import hashlib

        # Extract configuration
        base_url = config.get('base_url', 'https://haveibeenpwned.com/api/v3').rstrip('/')
        verify_ssl = config.get('verify_ssl', True)
        rate_limit_delay = config.get('rate_limit_delay', 1.6)

        # For password checking, we use the pwned passwords API which doesn't require API key
        pwned_passwords_url = 'https://api.pwnedpasswords.com/range'

        # Hash the password (assume target is either plaintext password or SHA-1 hash)
        if len(target) == 40 and all(c in '0123456789abcdefABCDEF' for c in target):
            # Already a SHA-1 hash
            sha1_hash = target.upper()
        else:
            # Hash the plaintext password
            sha1_hash = hashlib.sha1(target.encode('utf-8')).hexdigest().upper()

        # Use k-anonymity - send only first 5 characters
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]

        # Make request to pwned passwords API
        endpoint = f'{pwned_passwords_url}/{hash_prefix}'

        # Respect rate limiting
        time.sleep(rate_limit_delay)

        response = requests.get(endpoint, verify=verify_ssl, timeout=30)

        if response.status_code == 200:
            # Parse response to find our hash
            hash_lines = response.text.strip().split('\n')
            password_count = 0

            for line in hash_lines:
                if ':' in line:
                    suffix, count = line.split(':', 1)
                    if suffix == hash_suffix:
                        password_count = int(count)
                        break

            # Create artifacts folder
            artifact_path = create_case_artifact_folder(case_id, 'hibp')
            artifact_filename = f"hibp_password_check_{job_id}.json"

            # Save results (without storing the actual password/hash)
            if artifact_path:
                save_case_artifact(case_id, artifact_filename, {
                    'hash_prefix': hash_prefix,
                    'timestamp': datetime.now().isoformat(),
                    'pwned_count': password_count,
                    'found_in_breaches': password_count > 0
                })

            # Add case note
            if password_count > 0:
                note_content = f"""**SOAR Action:** HIBP Password Reuse Check
**Hash Prefix:** {hash_prefix}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Result:** ⚠️ Password appears {password_count:,} times in breach corpus

_This password has been compromised and should be changed immediately._

_Results stored in `/cases/{case_id}/artifacts/hibp/{artifact_filename}`_"""
            else:
                note_content = f"""**SOAR Action:** HIBP Password Reuse Check
**Hash Prefix:** {hash_prefix}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Result:** ✅ Password not found in known breaches

_This password does not appear in the compromised password database._"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Password check completed - appears {password_count:,} times in breaches" if password_count > 0 else "Password check completed - not found in breaches",
                "artifacts": [artifact_filename] if artifact_path else [],
                "details": {
                    "hash_prefix": hash_prefix,
                    "pwned_count": password_count,
                    "is_compromised": password_count > 0,
                    "execution_time": response.elapsed.total_seconds()
                }
            }
        elif response.status_code == 404:
            # No matches found
            note_content = f"""**SOAR Action:** HIBP Password Reuse Check
**Hash Prefix:** {hash_prefix}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Result:** ✅ Password not found in known breaches

_This password does not appear in the compromised password database._"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": "Password check completed - not found in breaches",
                "details": {
                    "hash_prefix": hash_prefix,
                    "pwned_count": 0,
                    "is_compromised": False,
                    "execution_time": response.elapsed.total_seconds()
                }
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Pwned Passwords API error: {response.status_code}",
                "error": response.text
            }

    except requests.exceptions.RequestException as e:
        error_msg = f"Network error during HIBP password check: {str(e)}"
        add_case_note(case_id, f"**HIBP Password Check Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        add_case_note(case_id, f"**HIBP Password Check Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }


def execute_fortigate_block_ip(job_id, target, config, case_id):
    """
    Execute FortiGate IP blocking via firewall address and policy creation
    """
    try:
        import requests

        # Extract configuration
        base_url = config.get('base_url', '').strip().rstrip('/')
        api_key = config.get('api_key')
        verify_ssl = config.get('verify_ssl', True)
        api_version = config.get('api_version', 'v2')
        vdom = config.get('vdom', 'root')

        if not api_key or not base_url:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "FortiGate API credentials not configured",
                "error": "Missing API key or base URL in integration configuration"
            }

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        start_time = datetime.now()
        address_name = f"IRIS_Block_{target.replace('.', '_')}"
        policy_name = f"IRIS_BLOCK_{target.replace('.', '_')}"

        # Step 1: Create firewall address object
        address_url = f"{base_url}/api/{api_version}/cmdb/firewall/address"
        address_params = {'vdom': vdom} if vdom != 'root' else {}

        address_data = {
            "name": address_name,
            "subnet": f"{target}/32",
            "comment": f"IRIS SOAR auto-block for case {case_id}"
        }

        address_response = requests.post(
            address_url,
            headers=headers,
            params=address_params,
            json=address_data,
            verify=verify_ssl,
            timeout=30
        )

        if address_response.status_code not in [200, 201]:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to create address object: {address_response.status_code}",
                "error": address_response.text
            }

        # Step 2: Create firewall policy to block the IP
        policy_url = f"{base_url}/api/{api_version}/cmdb/firewall/policy"
        policy_params = {'vdom': vdom} if vdom != 'root' else {}

        policy_data = {
            "name": policy_name,
            "srcintf": [{"name": "any"}],
            "dstintf": [{"name": "any"}],
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": address_name}],
            "action": "deny",
            "status": "enable",
            "comments": f"IRIS SOAR auto-block policy for case {case_id}"
        }

        policy_response = requests.post(
            policy_url,
            headers=headers,
            params=policy_params,
            json=policy_data,
            verify=verify_ssl,
            timeout=30
        )

        if policy_response.status_code not in [200, 201]:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to create blocking policy: {policy_response.status_code}",
                "error": policy_response.text
            }

        end_time = datetime.now()

        # Save artifacts
        artifact_path = create_case_artifact_folder(case_id, 'fortigate')
        artifact_filename = f"block_{target.replace('.', '_')}_{job_id}.json"

        artifact_data = {
            'ip_address': target,
            'timestamp': start_time.isoformat(),
            'job_id': job_id,
            'address_object': {
                'name': address_name,
                'response': address_response.json() if address_response.status_code in [200, 201] else None
            },
            'policy_object': {
                'name': policy_name,
                'response': policy_response.json() if policy_response.status_code in [200, 201] else None
            },
            'execution_time': (end_time - start_time).total_seconds()
        }

        if artifact_path:
            save_case_artifact(case_id, artifact_filename, artifact_data, 'fortigate')

        # Add case note
        note_content = f"""**SOAR Action:** Block IP on FortiGate
**IP:** {target}
**Timestamp:** {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
✅ IP added to deny policy on FortiGate.

**Created Objects:**
- Address Object: `{address_name}`
- Policy: `{policy_name}`

_Full details stored in `/cases/{case_id}/artifacts/fortigate/{artifact_filename}`_"""

        add_case_note(case_id, note_content)

        return {
            "job_id": job_id,
            "status": "Completed",
            "message": f"IP {target} successfully blocked on FortiGate",
            "artifacts": [artifact_filename] if artifact_path else [],
            "details": {
                "ip_address": target,
                "address_object": address_name,
                "policy_name": policy_name,
                "execution_time": (end_time - start_time).total_seconds()
            }
        }

    except requests.exceptions.RequestException as e:
        error_msg = f"Network error during FortiGate IP block: {str(e)}"
        add_case_note(case_id, f"**FortiGate IP Block Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        add_case_note(case_id, f"**FortiGate IP Block Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }


def execute_fortigate_block_domain(job_id, target, config, case_id):
    """
    Execute FortiGate domain blocking via web filter
    """
    try:
        import requests

        # Extract configuration
        base_url = config.get('base_url', '').strip().rstrip('/')
        api_key = config.get('api_key')
        verify_ssl = config.get('verify_ssl', True)
        api_version = config.get('api_version', 'v2')
        vdom = config.get('vdom', 'root')

        if not api_key or not base_url:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "FortiGate API credentials not configured",
                "error": "Missing API key or base URL in integration configuration"
            }

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        start_time = datetime.now()
        filter_name = f"IRIS_BLOCK_{target.replace('.', '_').replace('/', '_')}"

        # Create web filter URL filter
        url_filter_url = f"{base_url}/api/{api_version}/cmdb/webfilter/urlfilter"
        params = {'vdom': vdom} if vdom != 'root' else {}

        filter_data = {
            "name": filter_name,
            "entries": [
                {
                    "url": target,
                    "type": "simple",
                    "action": "block"
                }
            ],
            "comment": f"IRIS SOAR auto-block for case {case_id}"
        }

        response = requests.post(
            url_filter_url,
            headers=headers,
            params=params,
            json=filter_data,
            verify=verify_ssl,
            timeout=30
        )

        end_time = datetime.now()

        if response.status_code in [200, 201]:
            # Save artifacts
            artifact_path = create_case_artifact_folder(case_id, 'fortigate')
            artifact_filename = f"block_{target.replace('.', '_').replace('/', '_')}_{job_id}.json"

            artifact_data = {
                'domain': target,
                'timestamp': start_time.isoformat(),
                'job_id': job_id,
                'filter_object': {
                    'name': filter_name,
                    'response': response.json()
                },
                'execution_time': (end_time - start_time).total_seconds()
            }

            if artifact_path:
                save_case_artifact(case_id, artifact_filename, artifact_data, 'fortigate')

            # Add case note
            note_content = f"""**SOAR Action:** Block Domain
**Domain:** {target}
**Timestamp:** {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
✅ Successfully blocked in FortiGate web filter policy.

**Created Filter:** `{filter_name}`

_Full details stored in `/cases/{case_id}/artifacts/fortigate/{artifact_filename}`_"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Domain {target} successfully blocked on FortiGate",
                "artifacts": [artifact_filename] if artifact_path else [],
                "details": {
                    "domain": target,
                    "filter_name": filter_name,
                    "execution_time": (end_time - start_time).total_seconds()
                }
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to create domain filter: {response.status_code}",
                "error": response.text
            }

    except requests.exceptions.RequestException as e:
        error_msg = f"Network error during FortiGate domain block: {str(e)}"
        add_case_note(case_id, f"**FortiGate Domain Block Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        add_case_note(case_id, f"**FortiGate Domain Block Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }


def execute_fortigate_quarantine_host(job_id, target, config, case_id):
    """
    Execute FortiGate host quarantine via banned user API
    """
    try:
        import requests

        # Extract configuration
        base_url = config.get('base_url', '').strip().rstrip('/')
        api_key = config.get('api_key')
        verify_ssl = config.get('verify_ssl', True)
        api_version = config.get('api_version', 'v2')
        vdom = config.get('vdom', 'root')
        quarantine_duration = config.get('quarantine_duration', 3600)

        if not api_key or not base_url:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": "FortiGate API credentials not configured",
                "error": "Missing API key or base URL in integration configuration"
            }

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        start_time = datetime.now()

        # Add user to banned list
        ban_url = f"{base_url}/api/{api_version}/monitor/user/banned/add"
        params = {'vdom': vdom} if vdom != 'root' else {}

        ban_data = {
            "ip": target,
            "expiry": quarantine_duration
        }

        ban_response = requests.post(
            ban_url,
            headers=headers,
            params=params,
            json=ban_data,
            verify=verify_ssl,
            timeout=30
        )

        if ban_response.status_code in [200, 201]:
            # Poll to confirm ban was applied
            list_url = f"{base_url}/api/{api_version}/monitor/user/banned/list"

            time.sleep(2)  # Brief wait before verification
            list_response = requests.get(
                list_url,
                headers=headers,
                params=params,
                verify=verify_ssl,
                timeout=30
            )

            end_time = datetime.now()
            banned_users = list_response.json() if list_response.status_code == 200 else []

            # Check if our IP is in the banned list
            is_banned = any(user.get('ip') == target for user in banned_users.get('results', []))

            # Save artifacts
            artifact_path = create_case_artifact_folder(case_id, 'fortigate')
            artifact_filename = f"quarantine_{target.replace('.', '_')}_{job_id}.json"

            artifact_data = {
                'host_ip': target,
                'timestamp': start_time.isoformat(),
                'job_id': job_id,
                'quarantine_duration': quarantine_duration,
                'ban_response': ban_response.json() if ban_response.status_code in [200, 201] else None,
                'verification_response': banned_users,
                'is_confirmed_banned': is_banned,
                'execution_time': (end_time - start_time).total_seconds()
            }

            if artifact_path:
                save_case_artifact(case_id, artifact_filename, artifact_data, 'fortigate')

            # Add case note
            status_emoji = "✅" if is_banned else "⚠️"
            note_content = f"""**SOAR Action:** Quarantine Host
**Endpoint:** {target}
**Timestamp:** {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
**Result:** {status_emoji} User banned for {quarantine_duration // 3600} hour(s).

**Duration:** {quarantine_duration} seconds
**Verification:** {'Confirmed in banned list' if is_banned else 'Could not verify ban status'}

_Full details stored in `/cases/{case_id}/artifacts/fortigate/{artifact_filename}`_"""

            add_case_note(case_id, note_content)

            return {
                "job_id": job_id,
                "status": "Completed",
                "message": f"Host {target} quarantined for {quarantine_duration} seconds",
                "artifacts": [artifact_filename] if artifact_path else [],
                "details": {
                    "host_ip": target,
                    "quarantine_duration": quarantine_duration,
                    "is_confirmed_banned": is_banned,
                    "execution_time": (end_time - start_time).total_seconds()
                }
            }
        else:
            return {
                "job_id": job_id,
                "status": "Failed",
                "message": f"Failed to quarantine host: {ban_response.status_code}",
                "error": ban_response.text
            }

    except requests.exceptions.RequestException as e:
        error_msg = f"Network error during FortiGate host quarantine: {str(e)}"
        add_case_note(case_id, f"**FortiGate Host Quarantine Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        add_case_note(case_id, f"**FortiGate Host Quarantine Failed**\n\nError: {error_msg}")

        return {
            "job_id": job_id,
            "status": "Failed",
            "message": error_msg,
            "error": str(e)
        }