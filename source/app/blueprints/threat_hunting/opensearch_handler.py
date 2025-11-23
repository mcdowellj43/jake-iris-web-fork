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

import requests
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

log = logging.getLogger(__name__)


class OpenSearchHandler:
    """
    Handler for OpenSearch API interactions for threat hunting
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize OpenSearch handler with configuration

        Args:
            config (dict): Configuration dictionary containing:
                - base_url: OpenSearch base URL
                - api_key: API key for authentication (optional)
                - username: Username for basic auth (optional)
                - password: Password for basic auth (optional)
                - verify_ssl: Whether to verify SSL certificates
                - timeout: Request timeout in seconds
        """
        self.base_url = config.get('base_url', '').rstrip('/')
        self.api_key = config.get('api_key')
        self.username = config.get('username')
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl', True)
        self.timeout = config.get('timeout', 60)
        self.default_index = config.get('default_index', '*')

    def _get_headers(self) -> Dict[str, str]:
        """
        Build request headers with authentication

        Returns:
            dict: Headers dictionary
        """
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if self.api_key:
            # API Key authentication
            headers['Authorization'] = f'ApiKey {self.api_key}'

        return headers

    def _get_auth(self) -> Optional[tuple]:
        """
        Get basic auth credentials if configured

        Returns:
            tuple: (username, password) or None
        """
        if self.username and self.password:
            return (self.username, self.password)
        return None

    def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to OpenSearch cluster

        Returns:
            dict: Connection test results with status, message, and metadata
        """
        try:
            start_time = time.time()
            endpoint = f'{self.base_url}/'

            response = requests.get(
                endpoint,
                headers=self._get_headers(),
                auth=self._get_auth(),
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            response_time = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                cluster_info = response.json()
                return {
                    'success': True,
                    'message': 'Connection successful',
                    'response_time_ms': response_time,
                    'cluster_name': cluster_info.get('cluster_name', 'Unknown'),
                    'version': cluster_info.get('version', {}).get('number', 'Unknown')
                }
            else:
                return {
                    'success': False,
                    'message': f'Connection failed with status {response.status_code}',
                    'error': response.text
                }

        except requests.exceptions.SSLError as e:
            log.error(f"SSL error connecting to OpenSearch: {str(e)}")
            return {
                'success': False,
                'message': 'SSL certificate verification failed',
                'error': str(e)
            }
        except requests.exceptions.Timeout as e:
            log.error(f"Timeout connecting to OpenSearch: {str(e)}")
            return {
                'success': False,
                'message': 'Connection timeout',
                'error': str(e)
            }
        except requests.exceptions.ConnectionError as e:
            log.error(f"Connection error to OpenSearch: {str(e)}")
            return {
                'success': False,
                'message': 'Could not connect to OpenSearch',
                'error': str(e)
            }
        except Exception as e:
            log.error(f"Error testing OpenSearch connection: {str(e)}")
            return {
                'success': False,
                'message': 'Unexpected error occurred',
                'error': str(e)
            }

    def execute_query(
        self,
        query_dsl: Dict[str, Any],
        time_range: str = '24h',
        index: Optional[str] = None,
        size: int = 1000,
        aggregations: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute a threat hunting query against OpenSearch

        Args:
            query_dsl (dict): OpenSearch Query DSL
            time_range (str): Time range (e.g., '24h', '7d', '30d')
            index (str): Index pattern to search (default: all indices)
            size (int): Maximum number of results to return
            aggregations (dict): Aggregation configuration

        Returns:
            dict: Query execution results
        """
        try:
            start_time = time.time()

            if index is None:
                index = self.default_index

            endpoint = f'{self.base_url}/{index}/_search'

            # Build time range filter
            time_filter = self._build_time_filter(time_range)

            # Construct full query with time range
            full_query = {
                'query': {
                    'bool': {
                        'must': [
                            query_dsl,
                            time_filter
                        ]
                    }
                },
                'size': size,
                'sort': [
                    {'@timestamp': {'order': 'desc'}}
                ]
            }

            # Add aggregations if provided
            if aggregations:
                full_query['aggs'] = aggregations

            log.debug(f"Executing OpenSearch query: {full_query}")

            response = requests.post(
                endpoint,
                headers=self._get_headers(),
                auth=self._get_auth(),
                json=full_query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            execution_time = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                result_data = response.json()

                # Extract hit count
                hit_count = result_data.get('hits', {}).get('total', {})
                if isinstance(hit_count, dict):
                    hit_count = hit_count.get('value', 0)

                return {
                    'success': True,
                    'hit_count': hit_count,
                    'execution_time_ms': execution_time,
                    'results': result_data.get('hits', {}).get('hits', []),
                    'aggregations': result_data.get('aggregations', {}),
                    'raw_response': result_data
                }
            else:
                log.error(f"OpenSearch query failed: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'message': f'Query failed with status {response.status_code}',
                    'error': response.text
                }

        except requests.exceptions.Timeout as e:
            log.error(f"Query timeout: {str(e)}")
            return {
                'success': False,
                'message': 'Query execution timeout',
                'error': str(e)
            }
        except Exception as e:
            log.error(f"Error executing OpenSearch query: {str(e)}")
            return {
                'success': False,
                'message': 'Query execution failed',
                'error': str(e)
            }

    def _build_time_filter(self, time_range: str) -> Dict[str, Any]:
        """
        Build time range filter for queries

        Args:
            time_range (str): Time range string (e.g., '1h', '24h', '7d', '30d')

        Returns:
            dict: OpenSearch time range filter
        """
        # Parse time range
        time_value = int(time_range[:-1])
        time_unit = time_range[-1]

        # Calculate time delta
        if time_unit == 'h':
            delta = timedelta(hours=time_value)
        elif time_unit == 'd':
            delta = timedelta(days=time_value)
        elif time_unit == 'm':
            delta = timedelta(minutes=time_value)
        else:
            # Default to 24 hours
            delta = timedelta(hours=24)

        end_time = datetime.utcnow()
        start_time = end_time - delta

        return {
            'range': {
                '@timestamp': {
                    'gte': start_time.isoformat() + 'Z',
                    'lte': end_time.isoformat() + 'Z',
                    'format': 'strict_date_optional_time'
                }
            }
        }

    def get_indices(self) -> Dict[str, Any]:
        """
        List all available indices in OpenSearch

        Returns:
            dict: List of indices and metadata
        """
        try:
            endpoint = f'{self.base_url}/_cat/indices?format=json&h=index,docs.count,store.size'

            response = requests.get(
                endpoint,
                headers=self._get_headers(),
                auth=self._get_auth(),
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                indices = response.json()
                return {
                    'success': True,
                    'indices': indices
                }
            else:
                return {
                    'success': False,
                    'message': f'Failed to retrieve indices: {response.status_code}',
                    'error': response.text
                }

        except Exception as e:
            log.error(f"Error retrieving indices: {str(e)}")
            return {
                'success': False,
                'message': 'Failed to retrieve indices',
                'error': str(e)
            }

    def get_field_mappings(self, index: Optional[str] = None) -> Dict[str, Any]:
        """
        Get field mappings for an index

        Args:
            index (str): Index name (default: all indices)

        Returns:
            dict: Field mappings
        """
        try:
            if index is None:
                index = self.default_index

            endpoint = f'{self.base_url}/{index}/_mapping'

            response = requests.get(
                endpoint,
                headers=self._get_headers(),
                auth=self._get_auth(),
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                mappings = response.json()
                return {
                    'success': True,
                    'mappings': mappings
                }
            else:
                return {
                    'success': False,
                    'message': f'Failed to retrieve mappings: {response.status_code}',
                    'error': response.text
                }

        except Exception as e:
            log.error(f"Error retrieving field mappings: {str(e)}")
            return {
                'success': False,
                'message': 'Failed to retrieve field mappings',
                'error': str(e)
            }

    def count_documents(
        self,
        query_dsl: Dict[str, Any],
        time_range: str = '24h',
        index: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Count documents matching a query

        Args:
            query_dsl (dict): OpenSearch Query DSL
            time_range (str): Time range
            index (str): Index pattern

        Returns:
            dict: Document count
        """
        try:
            if index is None:
                index = self.default_index

            endpoint = f'{self.base_url}/{index}/_count'

            # Build time range filter
            time_filter = self._build_time_filter(time_range)

            # Construct query
            full_query = {
                'query': {
                    'bool': {
                        'must': [
                            query_dsl,
                            time_filter
                        ]
                    }
                }
            }

            response = requests.post(
                endpoint,
                headers=self._get_headers(),
                auth=self._get_auth(),
                json=full_query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                result = response.json()
                return {
                    'success': True,
                    'count': result.get('count', 0)
                }
            else:
                return {
                    'success': False,
                    'message': f'Count query failed: {response.status_code}',
                    'error': response.text
                }

        except Exception as e:
            log.error(f"Error counting documents: {str(e)}")
            return {
                'success': False,
                'message': 'Count query failed',
                'error': str(e)
            }


def get_opensearch_handler(config: Dict[str, Any]) -> OpenSearchHandler:
    """
    Factory function to create OpenSearch handler instance

    Args:
        config (dict): OpenSearch configuration

    Returns:
        OpenSearchHandler: Handler instance
    """
    return OpenSearchHandler(config)
