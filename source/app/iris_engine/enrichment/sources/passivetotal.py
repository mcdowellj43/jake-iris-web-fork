"""
PassiveTotal (RiskIQ) Enrichment Source
Provides passive DNS and threat intelligence data
"""

import requests
import logging
import base64
from typing import Dict, Any
from .base import EnrichmentSourceBase

log = logging.getLogger(__name__)


class PassiveTotal(EnrichmentSourceBase):
    """PassiveTotal/RiskIQ threat intelligence source"""

    name = "passivetotal"
    ioc_support = {"domain", "ip"}
    base_url = "https://api.passivetotal.org/v2"

    def __init__(self):
        super().__init__()
        # PassiveTotal credentials should be configured via environment
        self.username = self._get_api_key("PASSIVETOTAL_USERNAME")
        self.api_key = self._get_api_key("PASSIVETOTAL_API_KEY")

        if self.username and self.api_key:
            # Create basic auth header
            credentials = f"{self.username}:{self.api_key}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            self.headers = {
                'Authorization': f'Basic {encoded_credentials}',
                'User-Agent': 'IRIS-IOC-Enrichment/1.0'
            }
        else:
            self.headers = {'User-Agent': 'IRIS-IOC-Enrichment/1.0'}

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 10) -> Dict[str, Any]:
        """
        Fetch PassiveTotal data for domain or IP

        Args:
            ioc_type: Type of IOC (domain or ip)
            ioc_value: Domain or IP to lookup
            timeout_s: Request timeout in seconds

        Returns:
            Dict containing PassiveTotal data or error information
        """
        if ioc_type not in self.ioc_support:
            return {"_error": f"PassiveTotal source does not support IOC type: {ioc_type}"}

        if not self.username or not self.api_key:
            return {"_error": "PassiveTotal credentials not configured"}

        try:
            # Get passive DNS data
            passive_dns = self._get_passive_dns(ioc_value, timeout_s)

            # Get classification data
            classification = self._get_classification(ioc_value, timeout_s)

            # Get WHOIS data if domain
            whois_data = None
            if ioc_type == "domain":
                whois_data = self._get_whois(ioc_value, timeout_s)

            # Get malware data
            malware_data = self._get_malware(ioc_value, timeout_s)

            normalized_data = {
                'ioc_value': ioc_value,
                'ioc_type': ioc_type,
                'passive_dns': passive_dns,
                'classification': classification,
                'whois': whois_data,
                'malware': malware_data,
                'reputation': self._calculate_reputation(classification, malware_data),
                '_source': self.name,
                '_timestamp': self._get_timestamp()
            }

            log.info(f"Successfully fetched PassiveTotal data for {ioc_value}")
            return normalized_data

        except requests.exceptions.Timeout:
            return {"_error": f"PassiveTotal request timeout after {timeout_s} seconds"}
        except requests.exceptions.RequestException as e:
            return {"_error": f"PassiveTotal request failed: {str(e)}"}
        except Exception as e:
            log.error(f"Unexpected error in PassiveTotal lookup for {ioc_value}: {str(e)}")
            return {"_error": f"Unexpected error: {str(e)}"}

    def _get_passive_dns(self, query: str, timeout_s: int) -> Dict[str, Any]:
        """Get passive DNS data"""
        try:
            endpoint = f"{self.base_url}/dns/passive"
            params = {'query': query}

            response = requests.get(
                endpoint,
                params=params,
                headers=self.headers,
                timeout=timeout_s
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'total_records': data.get('totalRecords', 0),
                    'first_seen': data.get('firstSeen'),
                    'last_seen': data.get('lastSeen'),
                    'results': data.get('results', [])[:10]  # Limit to 10 results
                }
            else:
                return {"error": f"PassiveTotal DNS API error: {response.status_code}"}

        except Exception as e:
            return {"error": f"PassiveTotal DNS lookup failed: {str(e)}"}

    def _get_classification(self, query: str, timeout_s: int) -> Dict[str, Any]:
        """Get classification data"""
        try:
            endpoint = f"{self.base_url}/actions/classification"
            params = {'query': query}

            response = requests.get(
                endpoint,
                params=params,
                headers=self.headers,
                timeout=timeout_s
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'classification': data.get('classification'),
                    'tags': data.get('tags', []),
                    'ever_compromised': data.get('everCompromised', False),
                    'sinkhole': data.get('sinkhole', False)
                }
            else:
                return {"error": f"PassiveTotal classification API error: {response.status_code}"}

        except Exception as e:
            return {"error": f"PassiveTotal classification lookup failed: {str(e)}"}

    def _get_whois(self, domain: str, timeout_s: int) -> Dict[str, Any]:
        """Get WHOIS data for domain"""
        try:
            endpoint = f"{self.base_url}/whois"
            params = {'query': domain}

            response = requests.get(
                endpoint,
                params=params,
                headers=self.headers,
                timeout=timeout_s
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'registrar': data.get('registrar'),
                    'registered': data.get('registered'),
                    'expires': data.get('expiresAt'),
                    'contact_email': data.get('contactEmail'),
                    'name_servers': data.get('nameServers', []),
                    'domain_status': data.get('domain')
                }
            else:
                return {"error": f"PassiveTotal WHOIS API error: {response.status_code}"}

        except Exception as e:
            return {"error": f"PassiveTotal WHOIS lookup failed: {str(e)}"}

    def _get_malware(self, query: str, timeout_s: int) -> Dict[str, Any]:
        """Get malware data"""
        try:
            endpoint = f"{self.base_url}/enrichment/malware"
            params = {'query': query}

            response = requests.get(
                endpoint,
                params=params,
                headers=self.headers,
                timeout=timeout_s
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'results': data.get('results', [])[:5]  # Limit to 5 malware results
                }
            else:
                return {"error": f"PassiveTotal malware API error: {response.status_code}"}

        except Exception as e:
            return {"error": f"PassiveTotal malware lookup failed: {str(e)}"}

    def _calculate_reputation(self, classification: Dict[str, Any], malware: Dict[str, Any]) -> str:
        """Calculate reputation based on PassiveTotal data"""
        # Check classification
        if classification.get('ever_compromised'):
            return "malicious"

        if classification.get('sinkhole'):
            return "malicious"

        class_value = classification.get('classification', '').lower()
        if class_value in ['malicious', 'suspicious']:
            return class_value

        # Check malware data
        malware_results = malware.get('results', [])
        if malware_results:
            return "malicious"

        return "unknown"

    def get_reputation_score(self, data: Dict[str, Any]) -> int:
        """
        Calculate reputation score based on PassiveTotal data

        Args:
            data: Normalized PassiveTotal data

        Returns:
            Risk score (0-100, higher = more suspicious)
        """
        if "_error" in data:
            return 0

        risk_score = 0

        # Check classification data
        classification = data.get('classification', {})
        if classification.get('ever_compromised'):
            risk_score += 40

        if classification.get('sinkhole'):
            risk_score += 50

        class_value = classification.get('classification', '').lower()
        if class_value == 'malicious':
            risk_score += 60
        elif class_value == 'suspicious':
            risk_score += 40

        # Check malware associations
        malware = data.get('malware', {})
        malware_count = len(malware.get('results', []))
        if malware_count > 0:
            risk_score += min(malware_count * 20, 50)

        # Check passive DNS patterns
        passive_dns = data.get('passive_dns', {})
        total_records = passive_dns.get('total_records', 0)

        # Very high DNS activity can be suspicious
        if total_records > 1000:
            risk_score += 15
        elif total_records > 500:
            risk_score += 10

        return min(risk_score, 100)

    def _get_api_key(self, env_var: str) -> str:
        """Get API key from environment or return empty string"""
        import os
        return os.getenv(env_var, "")