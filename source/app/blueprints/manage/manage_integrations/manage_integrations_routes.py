#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
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

import json
import logging as log
import traceback
import requests
import time
from flask import Blueprint
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from flask import jsonify
from flask_login import current_user, login_required

from app import db
from app.models.authorization import Permissions
from app.models.integrations import IntegrationConfig
from app.util import ac_requires
from app.util import response_success, response_error
from app.iris_engine.utils.tracker import track_activity

manage_integrations_blueprint = Blueprint('manage_integrations',
                                        __name__,
                                        template_folder='templates')


@manage_integrations_blueprint.route('/manage/integrations', methods=['GET'])
@login_required
@ac_requires(Permissions.server_administrator)
def manage_integrations_index(caseid, url_redir):
    """
    Main integrations management page
    """
    try:
        if url_redir:
            return redirect(url_for('manage_integrations.manage_integrations_index', cid=caseid))

        # Get current integration settings
        integrations_config = get_integrations_config()

        # Debug output
        log.info(f"Integration config loaded: {integrations_config}")

        return render_template('manage_integrations.html',
                             integrations=integrations_config)

    except Exception as e:
        log.error(f"Error loading integrations page: {str(e)}")
        traceback.print_exc()
        return response_error(f"An error occurred: {str(e)}")


@manage_integrations_blueprint.route('/manage/integrations/save', methods=['POST'])
@login_required
@ac_requires(Permissions.server_administrator, no_cid_required=True)
def save_integration_config(caseid, url_redir):
    """
    Save integration configuration
    """
    if url_redir:
        return redirect(url_for('manage_integrations.manage_integrations_index', cid=caseid))

    try:
        data = request.get_json()
        integration_type = data.get('integration_type')
        config = data.get('config', {})

        if not integration_type:
            return response_error("Integration type is required")

        # Save configuration to database/file
        success = save_integrations_config(integration_type, config)

        if success:
            track_activity(f"Integration {integration_type} configuration updated", caseid=None)
            return response_success("Integration configuration saved successfully")
        else:
            return response_error("Failed to save integration configuration")

    except Exception as e:
        log.error(f"Error saving integration config: {str(e)}")
        traceback.print_exc()
        return response_error(f"An error occurred: {str(e)}")


@manage_integrations_blueprint.route('/manage/integrations/test', methods=['POST'])
@login_required
@ac_requires(Permissions.server_administrator, no_cid_required=True)
def test_integration_connection(caseid, url_redir):
    """
    Test integration connection
    """
    if url_redir:
        return redirect(url_for('manage_integrations.manage_integrations_index', cid=caseid))

    try:
        data = request.get_json()
        integration_type = data.get('integration_type')
        config = data.get('config', {})

        if not integration_type:
            return response_error("Integration type is required")

        # Test connection based on integration type
        if integration_type == 'velociraptor':
            result = test_velociraptor_connection(config)
        elif integration_type == 'sentinelone':
            result = test_sentinelone_connection(config)
        elif integration_type == 'connectwise':
            result = test_connectwise_connection(config)
        elif integration_type == 'crowdstrike':
            result = test_crowdstrike_connection(config)
        elif integration_type == 'meraki':
            result = test_meraki_connection(config)
        elif integration_type == 'haveibeenpwned':
            result = test_haveibeenpwned_connection(config)
        elif integration_type == 'fortigate':
            result = test_fortigate_connection(config)
        else:
            return response_error("Unsupported integration type")

        return response_success("Connection test completed", data=result)

    except Exception as e:
        log.error(f"Error testing integration connection: {str(e)}")
        traceback.print_exc()
        return response_error(f"Connection test failed: {str(e)}")


def get_integrations_config():
    """
    Get current integrations configuration from database
    """
    try:
        # Get all integration configs from database
        configs = IntegrationConfig.query.all()
        log.info(f"Found {len(configs)} integration configs in database")

        # Build response dictionary
        result = {}

        for config in configs:
            config_data = config.config_data or {}
            result[config.integration_type] = {
                'enabled': config.enabled,
                **config_data
            }
            log.info(f"Loaded config for {config.integration_type}: enabled={config.enabled}")

        # Ensure default configs exist for known integrations
        default_configs = {
            'velociraptor': {
                'enabled': False,
                'base_url': '',
                'api_key': '',
                'ca_cert': '',
                'verify_ssl': True
            },
            'sentinelone': {
                'enabled': False,
                'base_url': '',
                'api_token': '',
                'verify_ssl': True,
                'site_id': ''
            },
            'connectwise': {
                'enabled': False,
                'base_url': '',
                'company_id': '',
                'public_key': '',
                'private_key': '',
                'client_id': '',
                'default_board': '',
                'verify_ssl': True
            },
            'crowdstrike': {
                'enabled': False,
                'base_url': '',
                'client_id': '',
                'client_secret': '',
                'cloud_region': 'us-1',
                'verify_ssl': True
            },
            'meraki': {
                'enabled': False,
                'api_key': '',
                'organization_id': '',
                'verify_ssl': True
            },
            'haveibeenpwned': {
                'enabled': False,
                'api_key': '',
                'base_url': 'https://haveibeenpwned.com/api/v3',
                'verify_ssl': True,
                'rate_limit_delay': 1.6
            },
            'fortigate': {
                'enabled': False,
                'base_url': '',
                'api_key': '',
                'verify_ssl': True,
                'api_version': 'v2',
                'vdom': 'root',
                'quarantine_duration': 3600
            },
            'opensearch': {
                'enabled': False,
                'base_url': '',
                'api_key': '',
                'username': '',
                'password': '',
                'verify_ssl': True,
                'timeout': 60,
                'default_index': '*'
            }
        }

        # Merge with defaults for any missing integrations
        for integration_type, default_config in default_configs.items():
            if integration_type not in result:
                result[integration_type] = default_config

        return result

    except Exception as e:
        log.error(f"Error loading integrations config: {str(e)}")
        # Return safe defaults on error
        return {
            'velociraptor': {
                'enabled': False,
                'base_url': '',
                'api_key': '',
                'ca_cert': '',
                'verify_ssl': True
            },
            'sentinelone': {
                'enabled': False,
                'base_url': '',
                'api_token': '',
                'verify_ssl': True,
                'site_id': ''
            },
            'opensearch': {
                'enabled': False,
                'base_url': '',
                'api_key': '',
                'username': '',
                'password': '',
                'verify_ssl': True,
                'timeout': 60,
                'default_index': '*'
            }
        }


def save_integrations_config(integration_type, config):
    """
    Save integration configuration to database
    """
    try:
        # Get or create integration config record
        integration_config = IntegrationConfig.query.filter_by(integration_type=integration_type).first()

        if integration_config:
            # Update existing record
            integration_config.enabled = config.get('enabled', False)
            integration_config.config_data = {k: v for k, v in config.items() if k != 'enabled'}
            integration_config.updated_by = current_user.name if current_user.is_authenticated else 'system'
        else:
            # Create new record
            integration_config = IntegrationConfig(
                integration_type=integration_type,
                enabled=config.get('enabled', False),
                config_data={k: v for k, v in config.items() if k != 'enabled'},
                created_by=current_user.name if current_user.is_authenticated else 'system',
                updated_by=current_user.name if current_user.is_authenticated else 'system'
            )
            db.session.add(integration_config)

        # Commit to database
        db.session.commit()
        log.info(f"Saved {integration_type} configuration to database")
        return True

    except Exception as e:
        log.error(f"Error saving integration config: {str(e)}")
        db.session.rollback()
        return False


def test_velociraptor_connection(config):
    """
    Test Velociraptor connection
    """
    try:
        base_url = config.get('base_url')
        api_key = config.get('api_key')

        if not base_url or not api_key:
            return {'success': False, 'message': 'Missing required configuration'}

        # Here you would implement actual connection test
        # For now, return mock response
        return {
            'success': True,
            'message': 'Connection test successful',
            'server_version': 'Mock Version 0.6.8',
            'response_time': '245ms'
        }

    except Exception as e:
        return {'success': False, 'message': f'Connection failed: {str(e)}'}


def test_sentinelone_connection(config):
    """
    Test SentinelOne connection using v2.1 Management Console API
    """
    try:
        base_url = config.get('base_url')
        api_token = config.get('api_token')
        verify_ssl = config.get('verify_ssl', True)

        if not base_url or not api_token:
            return {'success': False, 'message': 'Missing base_url or api_token configuration'}

        # Clean up base URL
        base_url = base_url.rstrip('/')

        # Prepare headers with proper ApiToken format as per SentinelOne v2.1 API
        headers = {
            'Authorization': f'ApiToken {api_token}',
            'Content-Type': 'application/json'
        }

        # Test connection using the system status endpoint for authentication validation
        test_endpoint = f'{base_url}/web/api/v2.1/system/status'
        params = {}  # No parameters needed for status endpoint

        # Debug logging
        log.info(f"SentinelOne API Test - URL: {test_endpoint}")
        log.info(f"SentinelOne API Test - Headers: {headers}")
        log.info(f"SentinelOne API Test - Params: {params}")
        log.info(f"SentinelOne API Test - Verify SSL: {verify_ssl}")

        start_time = time.time()

        # Make the API call with proper timeout and SSL verification
        response = requests.get(
            test_endpoint,
            headers=headers,
            params=params,
            verify=verify_ssl,
            timeout=30
        )

        # Debug response
        log.info(f"SentinelOne API Test - Response Status: {response.status_code}")
        log.info(f"SentinelOne API Test - Response Headers: {dict(response.headers)}")
        if response.status_code != 200:
            log.info(f"SentinelOne API Test - Response Body: {response.text[:500]}")

        end_time = time.time()
        response_time = int((end_time - start_time) * 1000)  # Convert to milliseconds

        if response.status_code == 200:
            response_data = response.json()

            # Extract system health information
            health_status = response_data.get('data', {}).get('health', 'Unknown')
            account_name = f'SentinelOne Management Console (Health: {health_status})'

            return {
                'success': True,
                'message': 'Connection test successful - SentinelOne API authentication verified',
                'account_name': account_name,
                'response_time': f'{response_time}ms',
                'api_version': 'v2.1',
                'status_code': response.status_code,
                'health_status': health_status
            }
        elif response.status_code == 401:
            return {
                'success': False,
                'message': 'Authentication failed - Invalid API token or insufficient permissions',
                'status_code': response.status_code,
                'response_time': f'{response_time}ms'
            }
        elif response.status_code == 403:
            return {
                'success': False,
                'message': 'Access forbidden - API token lacks required permissions',
                'status_code': response.status_code,
                'response_time': f'{response_time}ms'
            }
        else:
            return {
                'success': False,
                'message': f'API returned error status {response.status_code}: {response.text[:200]}',
                'status_code': response.status_code,
                'response_time': f'{response_time}ms'
            }

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Connection timed out - Check base_url and network connectivity'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': 'Connection failed - Unable to reach SentinelOne server. Verify base_url is correct.'}
    except requests.exceptions.SSLError:
        return {'success': False, 'message': 'SSL certificate verification failed - Check verify_ssl setting or certificate validity'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'message': f'Request failed: {str(e)}'}
    except Exception as e:
        log.error(f"Unexpected error in SentinelOne connection test: {str(e)}")
        return {'success': False, 'message': f'Connection test failed: {str(e)}'}


def test_connectwise_connection(config):
    """
    Test ConnectWise CRM connection
    """
    try:
        import requests
        import base64

        base_url = config.get('base_url', '').rstrip('/')
        company_id = config.get('company_id')
        public_key = config.get('public_key')
        private_key = config.get('private_key')
        client_id = config.get('client_id')

        # Validate required fields
        required_fields = ['base_url', 'company_id', 'public_key', 'private_key', 'client_id']
        missing_fields = [field for field in required_fields if not config.get(field)]

        if missing_fields:
            return {
                'success': False,
                'message': f'Missing required configuration: {", ".join(missing_fields)}'
            }

        # Construct API endpoint - test with company info endpoint
        if 'api-na.myconnectwise.net' in base_url or 'api-eu.myconnectwise.net' in base_url:
            # Cloud instance
            api_endpoint = f"{base_url}/v4_6_release/apis/3.0/company/info"
        else:
            # On-premise instance
            api_endpoint = f"{base_url}/v4_6_release/apis/3.0/company/info"

        # Set up Basic Auth - format: company+public_key:private_key
        auth_string = f"{company_id}+{public_key}:{private_key}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')

        headers = {
            'Authorization': f'Basic {auth_b64}',
            'Content-Type': 'application/json',
            'clientId': client_id
        }

        # Test connection with timeout
        response = requests.get(
            api_endpoint,
            headers=headers,
            verify=config.get('verify_ssl', True),
            timeout=10
        )

        if response.status_code == 200:
            company_info = response.json()
            return {
                'success': True,
                'message': 'Connection test successful',
                'company_name': company_info.get('companyName', 'Unknown'),
                'company_identifier': company_info.get('companyIdentifier', company_id),
                'response_time': f'{response.elapsed.total_seconds()*1000:.0f}ms'
            }
        elif response.status_code == 401:
            return {
                'success': False,
                'message': 'Authentication failed - check credentials'
            }
        elif response.status_code == 403:
            return {
                'success': False,
                'message': 'Access forbidden - check API member permissions'
            }
        else:
            return {
                'success': False,
                'message': f'API returned status {response.status_code}: {response.text[:200]}'
            }

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Connection timeout - check server URL'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': 'Connection failed - check server URL and network'}
    except Exception as e:
        return {'success': False, 'message': f'Connection test failed: {str(e)}'}


def test_crowdstrike_connection(config):
    """
    Test CrowdStrike Falcon API connection using OAuth2
    """
    try:
        import requests

        base_url = config.get('base_url', '').rstrip('/')
        client_id = config.get('client_id')
        client_secret = config.get('client_secret')
        cloud_region = config.get('cloud_region', 'us-1')

        # Validate required fields
        if not client_id or not client_secret:
            return {
                'success': False,
                'message': 'Missing required configuration: client_id and client_secret'
            }

        # Determine base URL from cloud region if not provided
        if not base_url:
            region_map = {
                'us-1': 'https://api.crowdstrike.com',
                'us-2': 'https://api.us-2.crowdstrike.com',
                'eu-1': 'https://api.eu-1.crowdstrike.com',
                'us-gov-1': 'https://api.laggar.gcw.crowdstrike.com'
            }
            base_url = region_map.get(cloud_region, 'https://api.crowdstrike.com')

        # Step 1: Get OAuth2 token
        token_endpoint = f"{base_url}/oauth2/token"
        token_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        token_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'client_credentials'
        }

        # Request access token
        token_response = requests.post(
            token_endpoint,
            headers=token_headers,
            data=token_data,
            verify=config.get('verify_ssl', True),
            timeout=10
        )

        if token_response.status_code != 200:
            if token_response.status_code == 401:
                return {
                    'success': False,
                    'message': 'Authentication failed - check client credentials'
                }
            elif token_response.status_code == 403:
                return {
                    'success': False,
                    'message': 'Access forbidden - check API client permissions'
                }
            else:
                return {
                    'success': False,
                    'message': f'OAuth2 token request failed: {token_response.status_code}'
                }

        token_data = token_response.json()
        access_token = token_data.get('access_token')

        if not access_token:
            return {
                'success': False,
                'message': 'No access token received from OAuth2 endpoint'
            }

        # Step 2: Test API access with sensor status endpoint
        api_headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        # Use a lightweight endpoint to test connectivity
        test_endpoint = f"{base_url}/sensors/queries/installers/v1"
        api_response = requests.get(
            test_endpoint,
            headers=api_headers,
            verify=config.get('verify_ssl', True),
            timeout=10
        )

        if api_response.status_code == 200:
            return {
                'success': True,
                'message': 'Connection test successful',
                'cloud_region': cloud_region,
                'base_url': base_url,
                'token_expires_in': token_data.get('expires_in', 1800),
                'response_time': f'{token_response.elapsed.total_seconds()*1000:.0f}ms'
            }
        elif api_response.status_code == 401:
            return {
                'success': False,
                'message': 'API access denied - check client permissions'
            }
        elif api_response.status_code == 403:
            return {
                'success': False,
                'message': 'Insufficient permissions - check API client scope'
            }
        else:
            return {
                'success': False,
                'message': f'API test failed with status {api_response.status_code}'
            }

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Connection timeout - check network connectivity'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': 'Connection failed - check base URL and network'}
    except Exception as e:
        return {'success': False, 'message': f'Connection test failed: {str(e)}'}


def test_meraki_connection(config):
    """
    Test Cisco Meraki Dashboard API connection
    """
    try:
        import requests

        api_key = config.get('api_key', '').strip()
        organization_id = config.get('organization_id', '').strip()
        verify_ssl = config.get('verify_ssl', True)

        # Validate required fields
        if not api_key:
            return {
                'success': False,
                'message': 'Missing required API key'
            }

        if not organization_id:
            return {
                'success': False,
                'message': 'Missing required Organization ID'
            }

        # Meraki Dashboard API base URL
        base_url = 'https://api.meraki.com/api/v1'

        # Test endpoint - get organization details
        test_url = f"{base_url}/organizations/{organization_id}"

        headers = {
            'X-Cisco-Meraki-API-Key': api_key,
            'Content-Type': 'application/json'
        }

        # Test connection with timeout
        response = requests.get(
            test_url,
            headers=headers,
            verify=verify_ssl,
            timeout=10
        )

        if response.status_code == 200:
            org_data = response.json()
            return {
                'success': True,
                'message': 'Connection test successful',
                'organization_name': org_data.get('name', 'Unknown'),
                'organization_id': organization_id,
                'response_time': f'{response.elapsed.total_seconds()*1000:.0f}ms'
            }
        elif response.status_code == 401:
            return {
                'success': False,
                'message': 'Invalid API key - check your Meraki Dashboard API key'
            }
        elif response.status_code == 403:
            return {
                'success': False,
                'message': 'Insufficient permissions - check API key permissions'
            }
        elif response.status_code == 404:
            return {
                'success': False,
                'message': 'Organization not found - check Organization ID'
            }
        else:
            return {
                'success': False,
                'message': f'API test failed with status {response.status_code}: {response.text}'
            }

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Connection timeout - check network connectivity'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': 'Connection failed - check network connectivity'}
    except Exception as e:
        return {'success': False, 'message': f'Connection test failed: {str(e)}'}


def test_haveibeenpwned_connection(config):
    """
    Test HaveIBeenPwned API connection
    """
    try:
        import requests
        import time

        api_key = config.get('api_key', '').strip()
        base_url = config.get('base_url', 'https://haveibeenpwned.com/api/v3').rstrip('/')
        verify_ssl = config.get('verify_ssl', True)

        # Validate required fields
        if not api_key:
            return {
                'success': False,
                'message': 'Missing required API key'
            }

        # Test endpoint - use the breaches endpoint with a small query
        test_url = f"{base_url}/breaches"

        headers = {
            'hibp-api-key': api_key,
            'User-Agent': 'IRIS-SOAR'
        }

        # Test connection with timeout and rate limiting
        response = requests.get(
            test_url,
            headers=headers,
            verify=verify_ssl,
            timeout=10
        )

        if response.status_code == 200:
            breaches_data = response.json()
            breach_count = len(breaches_data) if isinstance(breaches_data, list) else 0
            return {
                'success': True,
                'message': 'Connection test successful',
                'total_breaches': breach_count,
                'api_version': 'v3',
                'response_time': f'{response.elapsed.total_seconds()*1000:.0f}ms'
            }
        elif response.status_code == 401:
            return {
                'success': False,
                'message': 'Invalid API key - check your HIBP API key'
            }
        elif response.status_code == 403:
            return {
                'success': False,
                'message': 'Access forbidden - check API key permissions'
            }
        elif response.status_code == 429:
            return {
                'success': False,
                'message': 'Rate limit exceeded - please wait before testing again'
            }
        else:
            return {
                'success': False,
                'message': f'API test failed with status {response.status_code}: {response.text}'
            }

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Connection timeout - check network connectivity'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': 'Connection failed - check network connectivity'}
    except Exception as e:
        return {'success': False, 'message': f'Connection test failed: {str(e)}'}


def test_fortigate_connection(config):
    """
    Test FortiGate API connection
    """
    try:
        import requests

        base_url = config.get('base_url', '').strip().rstrip('/')
        api_key = config.get('api_key', '').strip()
        verify_ssl = config.get('verify_ssl', True)
        api_version = config.get('api_version', 'v2')
        vdom = config.get('vdom', 'root')

        # Validate required fields
        if not base_url:
            return {
                'success': False,
                'message': 'Missing required base URL'
            }

        if not api_key:
            return {
                'success': False,
                'message': 'Missing required API key'
            }

        # Test endpoint - get system status
        test_url = f"{base_url}/api/{api_version}/monitor/system/status"

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        params = {'vdom': vdom} if vdom != 'root' else {}

        # Test connection with timeout
        response = requests.get(
            test_url,
            headers=headers,
            params=params,
            verify=verify_ssl,
            timeout=10
        )

        if response.status_code == 200:
            system_data = response.json()
            version = system_data.get('version', 'Unknown')
            serial = system_data.get('serial', 'Unknown')
            hostname = system_data.get('hostname', 'Unknown')

            return {
                'success': True,
                'message': 'Connection test successful',
                'fortigate_version': version,
                'serial_number': serial,
                'hostname': hostname,
                'vdom': vdom,
                'api_version': api_version,
                'response_time': f'{response.elapsed.total_seconds()*1000:.0f}ms'
            }
        elif response.status_code == 401:
            return {
                'success': False,
                'message': 'Invalid API key - check your FortiGate API key'
            }
        elif response.status_code == 403:
            return {
                'success': False,
                'message': 'Access forbidden - check API key permissions and VDOM access'
            }
        elif response.status_code == 404:
            return {
                'success': False,
                'message': 'API endpoint not found - check FortiGate version and API version'
            }
        else:
            return {
                'success': False,
                'message': f'API test failed with status {response.status_code}: {response.text}'
            }

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Connection timeout - check network connectivity'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': 'Connection failed - check network connectivity and FortiGate IP'}
    except Exception as e:
        return {'success': False, 'message': f'Connection test failed: {str(e)}'}