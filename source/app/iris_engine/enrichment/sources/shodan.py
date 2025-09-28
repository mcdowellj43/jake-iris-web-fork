"""
Shodan Enrichment Source
Provides Internet-connected device information from Shodan
"""

import requests
import logging
from typing import Dict, Any
from .base import EnrichmentSourceBase

log = logging.getLogger(__name__)


class Shodan(EnrichmentSourceBase):
    """Shodan Internet scanning source"""

    name = "shodan"
    ioc_support = {"ip"}
    base_url = "https://api.shodan.io"

    def __init__(self):
        super().__init__()
        # Shodan API key should be configured via environment
        self.api_key = self._get_api_key("SHODAN_API_KEY")

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 10) -> Dict[str, Any]:
        """
        Fetch Shodan data for an IP address

        Args:
            ioc_type: Type of IOC (should be 'ip')
            ioc_value: IP address to lookup
            timeout_s: Request timeout in seconds

        Returns:
            Dict containing Shodan data or error information
        """
        if ioc_type != "ip":
            return {"_error": f"Shodan source only supports IP addresses, not {ioc_type}"}

        if not self.api_key:
            return {"_error": "Shodan API key not configured"}

        try:
            endpoint = f"{self.base_url}/shodan/host/{ioc_value}"
            params = {'key': self.api_key}

            response = requests.get(
                endpoint,
                params=params,
                timeout=timeout_s
            )

            if response.status_code == 200:
                data = response.json()

                # Process service data
                services = []
                for service in data.get('data', [])[:10]:  # Limit to 10 services
                    service_info = {
                        'port': service.get('port'),
                        'protocol': service.get('transport'),
                        'service': service.get('product'),
                        'version': service.get('version'),
                        'banner': service.get('data', '')[:200],  # Truncate banner
                        'timestamp': service.get('timestamp'),
                        'ssl': service.get('ssl', {}) if service.get('ssl') else None
                    }
                    services.append(service_info)

                normalized_data = {
                    'ip': ioc_value,
                    'hostnames': data.get('hostnames', []),
                    'domains': data.get('domains', []),
                    'country_name': data.get('country_name'),
                    'country_code': data.get('country_code'),
                    'city': data.get('city'),
                    'region_code': data.get('region_code'),
                    'postal_code': data.get('postal_code'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'area_code': data.get('area_code'),
                    'dma_code': data.get('dma_code'),
                    'asn': data.get('asn'),
                    'isp': data.get('isp'),
                    'organization': data.get('org'),
                    'os': data.get('os'),
                    'ports': data.get('ports', []),
                    'services': services,
                    'last_update': data.get('last_update'),
                    'tags': data.get('tags', []),
                    'vulns': list(data.get('vulns', [])) if data.get('vulns') else [],
                    '_source': self.name,
                    '_timestamp': self._get_timestamp(),
                    '_raw_response': {k: v for k, v in data.items() if k != 'data'}  # Exclude full service data
                }

                log.info(f"Successfully fetched Shodan data for {ioc_value}")
                return normalized_data

            elif response.status_code == 404:
                return {
                    'ip': ioc_value,
                    'found': False,
                    '_source': self.name,
                    '_timestamp': self._get_timestamp(),
                    '_raw_response': {"error": "No information available"}
                }
            elif response.status_code == 401:
                return {"_error": "Shodan API authentication failed - check API key"}
            elif response.status_code == 429:
                return {"_error": "Shodan API rate limit exceeded"}
            else:
                return self._handle_request_error(response, "Shodan")

        except requests.exceptions.Timeout:
            return {"_error": f"Shodan request timeout after {timeout_s} seconds"}
        except requests.exceptions.RequestException as e:
            return {"_error": f"Shodan request failed: {str(e)}"}
        except Exception as e:
            log.error(f"Unexpected error in Shodan lookup for {ioc_value}: {str(e)}")
            return {"_error": f"Unexpected error: {str(e)}"}

    def get_reputation_score(self, data: Dict[str, Any]) -> int:
        """
        Calculate reputation score based on Shodan data

        Args:
            data: Normalized Shodan data

        Returns:
            Risk score (0-100, higher = more suspicious)
        """
        if "_error" in data:
            return 0

        if not data.get('found', True):  # Default to found=True for backward compatibility
            return 0

        risk_score = 0

        # Check for known vulnerabilities
        vulns = data.get('vulns', [])
        if vulns:
            risk_score += min(len(vulns) * 15, 60)  # Up to 60 points for vulnerabilities

        # Check for suspicious services
        services = data.get('services', [])
        suspicious_ports = [22, 23, 3389, 1433, 3306, 5432, 27017, 6379]  # SSH, Telnet, RDP, DB ports
        exposed_db_services = ['mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch']

        for service in services:
            port = service.get('port')
            service_name = service.get('service', '').lower()

            # Suspicious open ports
            if port in suspicious_ports:
                risk_score += 10

            # Exposed database services
            if any(db in service_name for db in exposed_db_services):
                risk_score += 15

            # Web servers with suspicious banners
            if port in [80, 443, 8080, 8443]:
                banner = service.get('banner', '').lower()
                if 'error' in banner or 'default' in banner:
                    risk_score += 5

        # Check organization type
        org = data.get('organization', '').lower()
        hosting_providers = ['amazon', 'google', 'microsoft', 'digitalocean', 'vultr', 'linode', 'ovh']
        if any(provider in org for provider in hosting_providers):
            risk_score += 10  # Hosting providers can be suspicious

        # Check for unusual number of open ports
        port_count = len(data.get('ports', []))
        if port_count > 20:
            risk_score += 20
        elif port_count > 10:
            risk_score += 10

        # Check tags for malicious indicators
        tags = data.get('tags', [])
        malicious_tags = ['malware', 'botnet', 'honeypot', 'scanner', 'compromised']
        for tag in tags:
            if any(mal_tag in tag.lower() for mal_tag in malicious_tags):
                risk_score += 25

        return min(risk_score, 100)

    def _get_api_key(self, env_var: str) -> str:
        """Get API key from environment or return empty string"""
        import os
        return os.getenv(env_var, "")