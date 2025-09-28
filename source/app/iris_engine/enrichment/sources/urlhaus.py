"""
URLhaus Enrichment Source
Provides malware URL and payload information from abuse.ch URLhaus
"""

import requests
import logging
from typing import Dict, Any
from .base import EnrichmentSourceBase

log = logging.getLogger(__name__)


class URLhaus(EnrichmentSourceBase):
    """URLhaus malware URL database source"""

    name = "urlhaus"
    ioc_support = {"url", "domain", "hash"}
    base_url = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self):
        super().__init__()
        self.headers = {
            'User-Agent': 'IRIS-IOC-Enrichment/1.0'
        }

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 8) -> Dict[str, Any]:
        """
        Fetch URLhaus data for URL, domain, or hash

        Args:
            ioc_type: Type of IOC (url, domain, or hash)
            ioc_value: IOC value to lookup
            timeout_s: Request timeout in seconds

        Returns:
            Dict containing URLhaus data or error information
        """
        if ioc_type not in self.ioc_support:
            return {"_error": f"URLhaus source does not support IOC type: {ioc_type}"}

        try:
            if ioc_type == "url":
                return self._fetch_url_info(ioc_value, timeout_s)
            elif ioc_type == "domain":
                return self._fetch_host_info(ioc_value, timeout_s)
            elif ioc_type == "hash":
                return self._fetch_payload_info(ioc_value, timeout_s)

        except requests.exceptions.Timeout:
            return {"_error": f"URLhaus request timeout after {timeout_s} seconds"}
        except requests.exceptions.RequestException as e:
            return {"_error": f"URLhaus request failed: {str(e)}"}
        except Exception as e:
            log.error(f"Unexpected error in URLhaus lookup for {ioc_value}: {str(e)}")
            return {"_error": f"Unexpected error: {str(e)}"}

    def _fetch_url_info(self, url: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch information about a specific URL"""
        endpoint = f"{self.base_url}/url/"
        data = {'url': url}

        response = requests.post(
            endpoint,
            data=data,
            headers=self.headers,
            timeout=timeout_s
        )

        if response.status_code == 200:
            result = response.json()

            if result.get('query_status') == 'ok':
                url_data = result

                normalized_data = {
                    'url': url,
                    'url_status': url_data.get('url_status'),
                    'threat': url_data.get('threat'),
                    'blacklists': url_data.get('blacklists', {}),
                    'tags': url_data.get('tags', []),
                    'payloads': url_data.get('payloads', []),
                    'host': url_data.get('host'),
                    'date_added': url_data.get('date_added'),
                    'last_online': url_data.get('last_online'),
                    'larted': url_data.get('larted'),
                    'takedown_time_seconds': url_data.get('takedown_time_seconds'),
                    '_source': self.name,
                    '_timestamp': self._get_timestamp(),
                    '_raw_response': result
                }

                log.info(f"Successfully fetched URLhaus URL data for {url}")
                return normalized_data

            else:
                return {"_error": "URL not found in URLhaus database"}

        else:
            return self._handle_request_error(response, "URLhaus")

    def _fetch_host_info(self, host: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch information about a host/domain"""
        endpoint = f"{self.base_url}/host/"
        data = {'host': host}

        response = requests.post(
            endpoint,
            data=data,
            headers=self.headers,
            timeout=timeout_s
        )

        if response.status_code == 200:
            result = response.json()

            if result.get('query_status') == 'ok':
                urls = result.get('urls', [])

                normalized_data = {
                    'host': host,
                    'url_count': len(urls),
                    'urls': urls[:10],  # Limit to first 10 URLs
                    'first_seen': result.get('firstseen'),
                    'blacklisted': len(urls) > 0,
                    'threat_types': list(set([url.get('threat', '') for url in urls if url.get('threat')])),
                    'tags': list(set([tag for url in urls for tag in url.get('tags', [])])),
                    '_source': self.name,
                    '_timestamp': self._get_timestamp(),
                    '_raw_response': result
                }

                log.info(f"Successfully fetched URLhaus host data for {host}")
                return normalized_data

            else:
                return {"_error": "Host not found in URLhaus database"}

        else:
            return self._handle_request_error(response, "URLhaus")

    def _fetch_payload_info(self, payload_hash: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch information about a payload hash"""
        endpoint = f"{self.base_url}/payload/"
        data = {'sha256_hash': payload_hash}

        response = requests.post(
            endpoint,
            data=data,
            headers=self.headers,
            timeout=timeout_s
        )

        if response.status_code == 200:
            result = response.json()

            if result.get('query_status') == 'ok':
                payload_data = result

                normalized_data = {
                    'hash': payload_hash,
                    'file_type': payload_data.get('file_type'),
                    'file_size': payload_data.get('file_size'),
                    'signature': payload_data.get('signature'),
                    'imphash': payload_data.get('imphash'),
                    'tlsh': payload_data.get('tlsh'),
                    'ssdeep': payload_data.get('ssdeep'),
                    'virustotal': payload_data.get('virustotal'),
                    'urls': payload_data.get('urls', [])[:5],  # Limit to 5 URLs
                    'firstseen': payload_data.get('firstseen'),
                    'lastseen': payload_data.get('lastseen'),
                    '_source': self.name,
                    '_timestamp': self._get_timestamp(),
                    '_raw_response': result
                }

                log.info(f"Successfully fetched URLhaus payload data for {payload_hash}")
                return normalized_data

            else:
                return {"_error": "Payload hash not found in URLhaus database"}

        else:
            return self._handle_request_error(response, "URLhaus")

    def get_reputation_score(self, data: Dict[str, Any]) -> int:
        """
        Calculate reputation score based on URLhaus data

        Args:
            data: Normalized URLhaus data

        Returns:
            Risk score (0-100, higher = more suspicious)
        """
        if "_error" in data:
            return 0

        # URLhaus primarily contains malicious content
        # So any hit is highly suspicious

        if 'url' in data:
            # URL lookup
            if data.get('url_status') == 'online':
                return 90  # Live malicious URL
            elif data.get('url_status') == 'offline':
                return 75  # Known malicious URL, now offline
            else:
                return 60  # Known to URLhaus

        elif 'host' in data:
            # Host lookup
            url_count = data.get('url_count', 0)
            if url_count > 10:
                return 85  # Many malicious URLs hosted
            elif url_count > 5:
                return 75
            elif url_count > 0:
                return 65

        elif 'hash' in data:
            # Payload lookup
            return 85  # Known malicious payload

        return 0