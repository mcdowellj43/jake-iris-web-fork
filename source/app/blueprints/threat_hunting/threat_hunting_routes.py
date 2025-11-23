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

import uuid
import json
import logging
from datetime import datetime
from flask import Blueprint
from flask import render_template
from flask import request
from flask import jsonify
from flask_login import current_user, login_required

from app import db
from app.datamgmt.case.case_db import get_case
from app.models import Cases
from app.models.authorization import CaseAccessLevel, Permissions
from app.models.threat_hunting import (
    ThreatHuntingQuery,
    ThreatHuntingResult,
    ThreatHuntingArtifact
)
from app.util import (
    response_success,
    response_error,
    ac_api_case_requires,
    ac_requires_case_identifier,
    ac_requires
)
from app.blueprints.manage.manage_integrations.manage_integrations_routes import get_integrations_config
from app.blueprints.threat_hunting_queries import (
    THREAT_HUNTING_QUERIES,
    QUERY_CATEGORIES,
    get_query,
    get_queries_by_category,
    get_all_queries,
    get_categories
)
from app.blueprints.threat_hunting.opensearch_handler import get_opensearch_handler

log = logging.getLogger(__name__)

threat_hunting_blueprint = Blueprint('threat_hunting',
                                    __name__,
                                    template_folder='templates')


@threat_hunting_blueprint.route('/threat-hunting', methods=['GET'])
@login_required
@ac_requires(Permissions.search_across_cases, no_cid_required=True)
def threat_hunting_index():
    """
    Main threat hunting dashboard page
    """
    log.debug("Threat hunting dashboard accessed")
    try:
        # Get OpenSearch integration config
        integrations_config = get_integrations_config()
        opensearch_config = integrations_config.get('opensearch', {})
        opensearch_enabled = opensearch_config.get('enabled', False)

        # Get query categories and counts
        categories = get_categories()
        query_counts = {cat: len(get_queries_by_category(cat)) for cat in categories}

        return render_template(
            'threat_hunting.html',
            opensearch_enabled=opensearch_enabled,
            categories=categories,
            query_counts=query_counts,
            total_queries=len(THREAT_HUNTING_QUERIES)
        )

    except Exception as e:
        log.error(f"Error rendering threat hunting dashboard: {str(e)}")
        return render_template('error.html', error=str(e))


@threat_hunting_blueprint.route('/threat-hunting/api/test-connection', methods=['POST'])
@login_required
@ac_requires(Permissions.alerts_read, no_cid_required=True)
def test_opensearch_connection():
    """
    Test OpenSearch connection
    """
    try:
        # Get OpenSearch config
        integrations_config = get_integrations_config()
        opensearch_config = integrations_config.get('opensearch', {})

        if not opensearch_config.get('enabled', False):
            return response_error("OpenSearch integration is not enabled")

        # Create handler and test connection
        handler = get_opensearch_handler(opensearch_config)
        result = handler.test_connection()

        if result['success']:
            return response_success("Connection test successful", data=result)
        else:
            return response_error(result.get('message', 'Connection test failed'), data=result)

    except Exception as e:
        log.error(f"Error testing OpenSearch connection: {str(e)}")
        return response_error(f"Connection test failed: {str(e)}")


@threat_hunting_blueprint.route('/threat-hunting/api/queries/categories', methods=['GET'])
@login_required
@ac_requires(Permissions.search_across_cases, no_cid_required=True)
def get_query_categories():
    """
    Get all query categories
    """
    try:
        categories = get_categories()
        result = {}

        for category in categories:
            queries = get_queries_by_category(category)
            result[category] = {
                'count': len(queries),
                'queries': [
                    {
                        'query_id': qid,
                        'query_name': q['query_name'],
                        'description': q['description'],
                        'severity': q.get('severity', 'medium'),
                        'mitre_attack': q.get('mitre_attack', [])
                    }
                    for qid, q in zip(QUERY_CATEGORIES[category], queries)
                ]
            }

        return response_success("Categories retrieved", data=result)

    except Exception as e:
        log.error(f"Error retrieving query categories: {str(e)}")
        return response_error(f"Failed to retrieve categories: {str(e)}")


@threat_hunting_blueprint.route('/threat-hunting/api/queries/<query_id>', methods=['GET'])
@login_required
@ac_requires(Permissions.search_across_cases, no_cid_required=True)
def get_query_details(query_id):
    """
    Get details for a specific query
    """
    try:
        query_config = get_query(query_id)

        if not query_config:
            return response_error(f"Query '{query_id}' not found")

        return response_success("Query retrieved", data={
            'query_id': query_id,
            **query_config
        })

    except Exception as e:
        log.error(f"Error retrieving query {query_id}: {str(e)}")
        return response_error(f"Failed to retrieve query: {str(e)}")


@threat_hunting_blueprint.route('/threat-hunting/api/execute', methods=['POST'])
@login_required
@ac_requires(Permissions.search_across_cases, no_cid_required=True)
def execute_hunt_query():
    """
    Execute a threat hunting query
    """
    try:
        data = request.get_json()
        query_id = data.get('query_id')
        time_range = data.get('time_range', '24h')
        case_id = data.get('case_id')
        index_pattern = data.get('index_pattern')

        if not query_id:
            return response_error("query_id is required")

        # Get query configuration
        query_config = get_query(query_id)
        if not query_config:
            return response_error(f"Query '{query_id}' not found")

        # Get OpenSearch config
        integrations_config = get_integrations_config()
        opensearch_config = integrations_config.get('opensearch', {})

        if not opensearch_config.get('enabled', False):
            return response_error("OpenSearch integration is not enabled")

        # Create handler and execute query
        handler = get_opensearch_handler(opensearch_config)

        log.info(f"Executing threat hunt query '{query_id}' by user {current_user.id}")

        result = handler.execute_query(
            query_dsl=query_config['query'],
            time_range=time_range,
            index=index_pattern,
            size=1000,
            aggregations=query_config.get('aggregation')
        )

        if result['success']:
            # Store result in database
            result_id = str(uuid.uuid4())

            # Calculate time range
            from app.blueprints.threat_hunting.opensearch_handler import OpenSearchHandler
            temp_handler = OpenSearchHandler({})
            time_filter = temp_handler._build_time_filter(time_range)
            time_range_obj = time_filter['range']['@timestamp']

            hunt_result = ThreatHuntingResult(
                result_id=result_id,
                query_id=query_id,
                case_id=case_id,
                executed_by=current_user.id,
                query_snapshot=query_config,
                time_range_start=datetime.fromisoformat(time_range_obj['gte'].replace('Z', '+00:00')),
                time_range_end=datetime.fromisoformat(time_range_obj['lte'].replace('Z', '+00:00')),
                result_data=result['results'],
                aggregation_results=result.get('aggregations', {}),
                hit_count=result['hit_count'],
                execution_time_ms=result['execution_time_ms'],
                status='completed'
            )

            db.session.add(hunt_result)
            db.session.commit()

            log.info(f"Threat hunt query '{query_id}' completed with {result['hit_count']} hits")

            return response_success("Query executed successfully", data={
                'result_id': result_id,
                'hit_count': result['hit_count'],
                'execution_time_ms': result['execution_time_ms'],
                'results': result['results'][:100],  # Limit frontend results
                'aggregations': result.get('aggregations', {}),
                'query_name': query_config['query_name']
            })
        else:
            # Store failed result
            result_id = str(uuid.uuid4())
            hunt_result = ThreatHuntingResult(
                result_id=result_id,
                query_id=query_id,
                case_id=case_id,
                executed_by=current_user.id,
                query_snapshot=query_config,
                time_range_start=datetime.utcnow(),
                time_range_end=datetime.utcnow(),
                result_data={},
                hit_count=0,
                status='failed',
                error_message=result.get('error', 'Unknown error')
            )

            db.session.add(hunt_result)
            db.session.commit()

            return response_error(result.get('message', 'Query execution failed'), data=result)

    except Exception as e:
        log.error(f"Error executing threat hunt query: {str(e)}")
        return response_error(f"Query execution failed: {str(e)}")


@threat_hunting_blueprint.route('/threat-hunting/api/results/<result_id>', methods=['GET'])
@login_required
@ac_requires(Permissions.search_across_cases, no_cid_required=True)
def get_hunt_result(result_id):
    """
    Get a specific threat hunting result
    """
    try:
        result = ThreatHuntingResult.query.filter_by(result_id=result_id).first()

        if not result:
            return response_error(f"Result '{result_id}' not found")

        return response_success("Result retrieved", data={
            'result_id': result.result_id,
            'query_id': result.query_id,
            'query_name': result.query_snapshot.get('query_name', 'Unknown'),
            'case_id': result.case_id,
            'executed_by': result.executed_by,
            'hit_count': result.hit_count,
            'execution_time_ms': result.execution_time_ms,
            'status': result.status,
            'error_message': result.error_message,
            'created_at': result.created_at.isoformat(),
            'time_range_start': result.time_range_start.isoformat(),
            'time_range_end': result.time_range_end.isoformat(),
            'results': result.result_data,
            'aggregations': result.aggregation_results
        })

    except Exception as e:
        log.error(f"Error retrieving result {result_id}: {str(e)}")
        return response_error(f"Failed to retrieve result: {str(e)}")


@threat_hunting_blueprint.route('/threat-hunting/api/results/history', methods=['GET'])
@login_required
@ac_requires(Permissions.search_across_cases, no_cid_required=True)
def get_hunt_history():
    """
    Get threat hunting execution history
    """
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)

        results = ThreatHuntingResult.query\
            .order_by(ThreatHuntingResult.created_at.desc())\
            .limit(limit)\
            .offset(offset)\
            .all()

        history = []
        for result in results:
            history.append({
                'result_id': result.result_id,
                'query_id': result.query_id,
                'query_name': result.query_snapshot.get('query_name', 'Unknown'),
                'hit_count': result.hit_count,
                'execution_time_ms': result.execution_time_ms,
                'status': result.status,
                'created_at': result.created_at.isoformat(),
                'executed_by': result.executed_by
            })

        return response_success("History retrieved", data=history)

    except Exception as e:
        log.error(f"Error retrieving hunt history: {str(e)}")
        return response_error(f"Failed to retrieve history: {str(e)}")


@threat_hunting_blueprint.route('/threat-hunting/api/results/<result_id>/add-to-case', methods=['POST'])
@login_required
@ac_api_case_requires(CaseAccessLevel.full_access)
def add_result_to_case(result_id):
    """
    Add threat hunting results to a case as a note
    """
    try:
        data = request.get_json()
        case_id = data.get('case_id')

        if not case_id:
            return response_error("case_id is required")

        # Get the result
        result = ThreatHuntingResult.query.filter_by(result_id=result_id).first()
        if not result:
            return response_error(f"Result '{result_id}' not found")

        # Get case
        case = get_case(case_id)
        if not case:
            return response_error(f"Case '{case_id}' not found")

        # Format results as markdown for note
        query_name = result.query_snapshot.get('query_name', 'Unknown Query')
        description = result.query_snapshot.get('description', '')
        severity = result.query_snapshot.get('severity', 'medium')
        mitre_ids = result.query_snapshot.get('mitre_attack', [])

        note_content = f"""# Threat Hunting Results: {query_name}

**Description:** {description}
**Severity:** {severity.upper()}
**MITRE ATT&CK:** {', '.join(mitre_ids) if mitre_ids else 'N/A'}

**Execution Details:**
- Time Range: {result.time_range_start.isoformat()} to {result.time_range_end.isoformat()}
- Hits Found: {result.hit_count}
- Execution Time: {result.execution_time_ms}ms

## Findings

Total events matched: **{result.hit_count}**

"""

        # Add aggregation summary if available
        if result.aggregation_results:
            note_content += "\n## Aggregated Results\n\n"
            note_content += f"```json\n{json.dumps(result.aggregation_results, indent=2)}\n```\n\n"

        # Add sample results (limit to 10)
        if result.result_data and len(result.result_data) > 0:
            note_content += "## Sample Events (First 10)\n\n"
            for idx, event in enumerate(result.result_data[:10], 1):
                source = event.get('_source', {})
                note_content += f"### Event {idx}\n"
                note_content += f"```json\n{json.dumps(source, indent=2)}\n```\n\n"

        # Create case note using IRIS notes business logic
        from app.business import notes as notes_business

        note = notes_business.create(
            request_json={
                'note_title': f"[Threat Hunt] {query_name}",
                'note_content': note_content
            },
            case_identifier=case_id
        )

        if note:
            # Update result with note_id
            result.note_id = note.note_id
            result.case_id = case_id
            db.session.commit()

            log.info(f"Added threat hunt result {result_id} to case {case_id} as note {note.note_id}")

            return response_success("Results added to case", data={
                'note_id': note.note_id,
                'case_id': case_id
            })
        else:
            return response_error("Failed to create case note")

    except Exception as e:
        log.error(f"Error adding result to case: {str(e)}")
        return response_error(f"Failed to add results to case: {str(e)}")


@threat_hunting_blueprint.route('/threat-hunting/api/indices', methods=['GET'])
@login_required
@ac_requires(Permissions.search_across_cases, no_cid_required=True)
def get_opensearch_indices():
    """
    Get available OpenSearch indices
    """
    try:
        # Get OpenSearch config
        integrations_config = get_integrations_config()
        opensearch_config = integrations_config.get('opensearch', {})

        if not opensearch_config.get('enabled', False):
            return response_error("OpenSearch integration is not enabled")

        # Create handler and get indices
        handler = get_opensearch_handler(opensearch_config)
        result = handler.get_indices()

        if result['success']:
            return response_success("Indices retrieved", data=result['indices'])
        else:
            return response_error(result.get('message', 'Failed to retrieve indices'))

    except Exception as e:
        log.error(f"Error retrieving indices: {str(e)}")
        return response_error(f"Failed to retrieve indices: {str(e)}")


@threat_hunting_blueprint.route('/threat-hunting/api/stats', methods=['GET'])
@login_required
@ac_requires(Permissions.search_across_cases, no_cid_required=True)
def get_threat_hunting_stats():
    """
    Get threat hunting statistics
    """
    try:
        # Total executions
        total_executions = ThreatHuntingResult.query.count()

        # Executions in last 24h
        from datetime import timedelta
        last_24h = datetime.utcnow() - timedelta(hours=24)
        executions_24h = ThreatHuntingResult.query\
            .filter(ThreatHuntingResult.created_at >= last_24h)\
            .count()

        # Total hits across all executions
        from sqlalchemy import func
        total_hits = db.session.query(func.sum(ThreatHuntingResult.hit_count))\
            .scalar() or 0

        # Most executed queries
        from sqlalchemy import func
        top_queries = db.session.query(
            ThreatHuntingResult.query_id,
            func.count(ThreatHuntingResult.result_id).label('count')
        ).group_by(ThreatHuntingResult.query_id)\
         .order_by(func.count(ThreatHuntingResult.result_id).desc())\
         .limit(5)\
         .all()

        top_query_data = []
        for query_id, count in top_queries:
            query_config = get_query(query_id)
            if query_config:
                top_query_data.append({
                    'query_id': query_id,
                    'query_name': query_config['query_name'],
                    'execution_count': count
                })

        stats = {
            'total_executions': total_executions,
            'executions_24h': executions_24h,
            'total_hits': total_hits,
            'available_queries': len(THREAT_HUNTING_QUERIES),
            'categories': len(get_categories()),
            'top_queries': top_query_data
        }

        return response_success("Statistics retrieved", data=stats)

    except Exception as e:
        log.error(f"Error retrieving statistics: {str(e)}")
        return response_error(f"Failed to retrieve statistics: {str(e)}")
