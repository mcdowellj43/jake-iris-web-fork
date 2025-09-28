"""
AlienVault OTX (Open Threat Exchange) Enrichment Source
Provides threat intelligence data from OTX platform
"""

import requests
import logging
from typing import Dict, Any
from .base import EnrichmentSourceBase

log = logging.getLogger(__name__)


class AlienVaultOTX(EnrichmentSourceBase):
    """AlienVault OTX threat intelligence source"""

    name = "otx"
    ioc_support = {"ip", "domain", "hash", "url"}
    base_url = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self):
        super().__init__()
        # OTX API key should be configured via environment or config file
        self.api_key = self._get_api_key("OTX_API_KEY")
        self.headers = {
            'X-OTX-API-KEY': self.api_key if self.api_key else '',
            'User-Agent': 'IRIS-IOC-Enrichment/1.0'
        }

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 8) -> Dict[str, Any]:
        """
        Fetch threat intelligence data from OTX

        Args:
            ioc_type: Type of IOC (ip, domain, hash, url)
            ioc_value: IOC value to lookup
            timeout_s: Request timeout in seconds

        Returns:
            Dict containing OTX threat data or error information
        """
        if ioc_type not in self.ioc_support:
            return {"_error": f"OTX source does not support IOC type: {ioc_type}"}

        if not self.api_key:
            return {"_error": "OTX API key not configured"}

        try:
            # Map IOC types to OTX endpoint types
            otx_type_mapping = {
                "ip": "IPv4",
                "domain": "domain",
                "hash": "file",
                "url": "url"
            }

            otx_type = otx_type_mapping.get(ioc_type)
            if not otx_type:
                return {"_error": f"Unsupported IOC type for OTX: {ioc_type}"}

            # Build URL for general indicator info
            url = f"{self.base_url}/{otx_type}/{ioc_value}/general"

            response = requests.get(
                url,
                headers=self.headers,
                timeout=timeout_s
            )

            if response.status_code == 200:
                data = response.json()

                # Also get pulse information
                pulse_url = f"{self.base_url}/{otx_type}/{ioc_value}/malware"
                pulse_response = requests.get(
                    pulse_url,
                    headers=self.headers,
                    timeout=timeout_s
                )

                pulse_data = []
                if pulse_response.status_code == 200:
                    pulse_data = pulse_response.json().get('data', [])

                # Normalize the response
                normalized_data = {
                    'ioc_value': ioc_value,
                    'ioc_type': ioc_type,
                    'reputation': self._calculate_reputation(data),
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'pulses': data.get('pulse_info', {}).get('pulses', [])[:5],  # Top 5 pulses
                    'malware_families': [item.get('detections', {}).get('avast', '') for item in pulse_data[:3]],
                    'whois_data': data.get('whois') if ioc_type in ['ip', 'domain'] else None,
                    'country': data.get('country_name'),
                    'city': data.get('city'),
                    'asn': data.get('asn'),
                    '_source': self.name,
                    '_timestamp': self._get_timestamp(),
                    '_raw_response': data
                }

                log.info(f"Successfully fetched OTX data for {ioc_value}")
                return normalized_data

            elif response.status_code == 404:
                return {"_error": "IOC not found in OTX database"}
            elif response.status_code == 403:
                return {"_error": "OTX API access forbidden - check API key"}
            else:
                return self._handle_request_error(response, "OTX")

        except requests.exceptions.Timeout:
            return {"_error": f"OTX request timeout after {timeout_s} seconds"}
        except requests.exceptions.RequestException as e:
            return {"_error": f"OTX request failed: {str(e)}"}
        except Exception as e:
            log.error(f"Unexpected error in OTX lookup for {ioc_value}: {str(e)}")
            return {"_error": f"Unexpected error: {str(e)}"}

    def _calculate_reputation(self, data: Dict[str, Any]) -> str:
        """Calculate reputation based on OTX data"""
        pulse_count = data.get('pulse_info', {}).get('count', 0)

        if pulse_count == 0:
            return "clean"
        elif pulse_count < 5:
            return "suspicious"
        else:
            return "malicious"

    def get_reputation_score(self, data: Dict[str, Any]) -> int:
        """
        Calculate reputation score based on OTX data

        Args:
            data: Normalized OTX data

        Returns:
            Risk score (0-100, higher = more suspicious)
        """
        if "_error" in data:
            return 0

        pulse_count = data.get('pulse_count', 0)

        # Base score on pulse count
        if pulse_count == 0:
            return 0
        elif pulse_count < 3:
            return 25
        elif pulse_count < 10:
            return 50
        elif pulse_count < 20:
            return 75
        else:
            return 95

    def _get_api_key(self, env_var: str) -> str:
        """Get API key from environment or return empty string"""
        import os
        return os.getenv(env_var, "")