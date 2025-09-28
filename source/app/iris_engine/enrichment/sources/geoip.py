"""
GeoIP Lite Enrichment Source
Provides IP geolocation information using free GeoIP services
"""

import requests
import logging
from typing import Dict, Any
from .base import EnrichmentSourceBase

log = logging.getLogger(__name__)


class GeoIPLite(EnrichmentSourceBase):
    """GeoIP geolocation source using free public APIs"""

    name = "geoip"
    ioc_support = {"ip"}
    base_url = "http://ip-api.com/json/"

    def __init__(self):
        super().__init__()
        self.headers = {
            'User-Agent': 'IRIS-IOC-Enrichment/1.0'
        }

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 6) -> Dict[str, Any]:
        """
        Fetch geolocation data for an IP address

        Args:
            ioc_type: Type of IOC (should be 'ip')
            ioc_value: IP address to lookup
            timeout_s: Request timeout in seconds

        Returns:
            Dict containing geolocation data or error information
        """
        if ioc_type != "ip":
            return {"_error": f"GeoIP source does not support IOC type: {ioc_type}"}

        try:
            # Use ip-api.com free service (15/min rate limit)
            url = f"{self.base_url}{ioc_value}"
            params = {
                'fields': 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query'
            }

            response = requests.get(
                url,
                params=params,
                headers=self.headers,
                timeout=timeout_s
            )

            if response.status_code == 200:
                data = response.json()

                if data.get('status') == 'success':
                    # Normalize the response
                    normalized_data = {
                        'ip': ioc_value,
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'zip_code': data.get('zip'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'organization': data.get('org'),
                        'as_number': data.get('as'),
                        'is_mobile': data.get('mobile', False),
                        'is_proxy': data.get('proxy', False),
                        'is_hosting': data.get('hosting', False),
                        '_source': self.name,
                        '_timestamp': self._get_timestamp(),
                        '_raw_response': data
                    }

                    log.info(f"Successfully fetched GeoIP data for {ioc_value}")
                    return normalized_data

                else:
                    error_msg = data.get('message', 'Unknown error from GeoIP service')
                    return {"_error": f"GeoIP lookup failed: {error_msg}"}

            else:
                return self._handle_request_error(response, "GeoIP")

        except requests.exceptions.Timeout:
            return {"_error": f"GeoIP request timeout after {timeout_s} seconds"}
        except requests.exceptions.RequestException as e:
            return {"_error": f"GeoIP request failed: {str(e)}"}
        except Exception as e:
            log.error(f"Unexpected error in GeoIP lookup for {ioc_value}: {str(e)}")
            return {"_error": f"Unexpected error: {str(e)}"}

    def get_reputation_score(self, data: Dict[str, Any]) -> int:
        """
        Calculate reputation score based on geolocation data

        Args:
            data: Normalized GeoIP data

        Returns:
            Risk score (0-100, higher = more suspicious)
        """
        if "_error" in data:
            return 0

        risk_score = 0

        # Check for suspicious hosting/proxy indicators
        if data.get('is_proxy'):
            risk_score += 30
        if data.get('is_hosting'):
            risk_score += 20
        if data.get('is_mobile'):
            risk_score += 10

        # High-risk countries (basic list - should be configurable)
        high_risk_countries = ['CN', 'RU', 'KP', 'IR']
        if data.get('country_code') in high_risk_countries:
            risk_score += 25

        # VPS/Cloud provider detection (basic)
        org = data.get('organization', '').lower()
        cloud_providers = ['amazon', 'google', 'microsoft', 'digitalocean', 'vultr', 'linode']
        if any(provider in org for provider in cloud_providers):
            risk_score += 15

        return min(risk_score, 100)