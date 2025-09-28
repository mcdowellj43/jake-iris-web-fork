"""
WHOIS Enrichment Source
Provides WHOIS domain registration information
"""

import requests
import logging
from typing import Dict, Any
from datetime import datetime
from .base import EnrichmentSourceBase

log = logging.getLogger(__name__)


class Whois(EnrichmentSourceBase):
    """WHOIS domain information source"""

    name = "whois"
    ioc_support = {"domain", "ip"}
    base_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"

    def __init__(self):
        super().__init__()
        # WHOIS API key should be configured via environment
        self.api_key = self._get_api_key("WHOIS_API_KEY")

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 8) -> Dict[str, Any]:
        """
        Fetch WHOIS data for domain or IP

        Args:
            ioc_type: Type of IOC (domain or ip)
            ioc_value: Domain or IP to lookup
            timeout_s: Request timeout in seconds

        Returns:
            Dict containing WHOIS data or error information
        """
        if ioc_type not in self.ioc_support:
            return {"_error": f"WHOIS source does not support IOC type: {ioc_type}"}

        try:
            # Use free WHOIS API or fallback to whois command
            if self.api_key:
                return self._fetch_via_api(ioc_value, timeout_s)
            else:
                return self._fetch_via_whois_command(ioc_value, timeout_s)

        except Exception as e:
            log.error(f"Unexpected error in WHOIS lookup for {ioc_value}: {str(e)}")
            return {"_error": f"Unexpected error: {str(e)}"}

    def _fetch_via_api(self, ioc_value: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch WHOIS data via WhoisXML API"""
        try:
            params = {
                'apiKey': self.api_key,
                'domainName': ioc_value,
                'outputFormat': 'JSON'
            }

            response = requests.get(
                self.base_url,
                params=params,
                timeout=timeout_s
            )

            if response.status_code == 200:
                data = response.json()
                whois_record = data.get('WhoisRecord', {})

                normalized_data = {
                    'domain': ioc_value,
                    'registrar': whois_record.get('registrarName'),
                    'creation_date': whois_record.get('createdDate'),
                    'expiration_date': whois_record.get('expiresDate'),
                    'updated_date': whois_record.get('updatedDate'),
                    'name_servers': whois_record.get('nameServers', {}).get('hostNames', []),
                    'registrant_country': whois_record.get('registrant', {}).get('country'),
                    'registrant_organization': whois_record.get('registrant', {}).get('organization'),
                    'admin_email': whois_record.get('administrativeContact', {}).get('email'),
                    'status': whois_record.get('status'),
                    'dnssec': whois_record.get('dnssec'),
                    '_source': self.name,
                    '_timestamp': self._get_timestamp(),
                    '_raw_response': data
                }

                log.info(f"Successfully fetched WHOIS data for {ioc_value}")
                return normalized_data

            else:
                return self._handle_request_error(response, "WHOIS API")

        except requests.exceptions.Timeout:
            return {"_error": f"WHOIS API request timeout after {timeout_s} seconds"}
        except requests.exceptions.RequestException as e:
            return {"_error": f"WHOIS API request failed: {str(e)}"}

    def _fetch_via_whois_command(self, ioc_value: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch WHOIS data via system whois command as fallback"""
        try:
            import subprocess
            import re

            # Use system whois command
            result = subprocess.run(
                ['whois', ioc_value],
                capture_output=True,
                text=True,
                timeout=timeout_s
            )

            if result.returncode == 0:
                whois_text = result.stdout

                # Parse basic information from whois text
                normalized_data = {
                    'domain': ioc_value,
                    'registrar': self._extract_field(whois_text, r'Registrar:\s*(.+)'),
                    'creation_date': self._extract_field(whois_text, r'Creation Date:\s*(.+)'),
                    'expiration_date': self._extract_field(whois_text, r'Registry Expiry Date:\s*(.+)'),
                    'updated_date': self._extract_field(whois_text, r'Updated Date:\s*(.+)'),
                    'name_servers': self._extract_nameservers(whois_text),
                    'status': self._extract_field(whois_text, r'Domain Status:\s*(.+)'),
                    '_source': self.name,
                    '_timestamp': self._get_timestamp(),
                    '_raw_response': whois_text
                }

                log.info(f"Successfully fetched WHOIS data for {ioc_value} via command")
                return normalized_data

            else:
                return {"_error": f"WHOIS command failed: {result.stderr}"}

        except subprocess.TimeoutExpired:
            return {"_error": f"WHOIS command timeout after {timeout_s} seconds"}
        except FileNotFoundError:
            return {"_error": "WHOIS command not available and no API key configured"}
        except Exception as e:
            return {"_error": f"WHOIS command failed: {str(e)}"}

    def _extract_field(self, text: str, pattern: str) -> str:
        """Extract field from WHOIS text using regex"""
        import re
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else None

    def _extract_nameservers(self, text: str) -> list:
        """Extract name servers from WHOIS text"""
        import re
        nameservers = []
        for match in re.finditer(r'Name Server:\s*(.+)', text, re.IGNORECASE):
            nameservers.append(match.group(1).strip().lower())
        return nameservers[:10]  # Limit to 10 nameservers

    def get_reputation_score(self, data: Dict[str, Any]) -> int:
        """
        Calculate reputation score based on WHOIS data

        Args:
            data: Normalized WHOIS data

        Returns:
            Risk score (0-100, higher = more suspicious)
        """
        if "_error" in data:
            return 0

        risk_score = 0

        # Check domain age
        creation_date = data.get('creation_date')
        if creation_date:
            try:
                from dateutil import parser
                created = parser.parse(creation_date)
                age_days = (datetime.now() - created).days

                # Very new domains are suspicious
                if age_days < 30:
                    risk_score += 40
                elif age_days < 90:
                    risk_score += 25
                elif age_days < 365:
                    risk_score += 10

            except Exception:
                pass

        # Check for privacy protection (higher risk)
        registrant_org = data.get('registrant_organization', '').lower()
        privacy_indicators = ['privacy', 'protection', 'proxy', 'whoisguard']
        if any(indicator in registrant_org for indicator in privacy_indicators):
            risk_score += 15

        # Check registrar reputation (basic check)
        registrar = data.get('registrar', '').lower()
        suspicious_registrars = ['namecheap', 'godaddy']  # Example list
        if any(sus_reg in registrar for sus_reg in suspicious_registrars):
            risk_score += 5

        return min(risk_score, 100)

    def _get_api_key(self, env_var: str) -> str:
        """Get API key from environment or return empty string"""
        import os
        return os.getenv(env_var, "")