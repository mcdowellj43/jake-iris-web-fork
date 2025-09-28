"""
Certificate Transparency (crt.sh) Enrichment Source
Provides SSL certificate information from crt.sh database
"""

import requests
import logging
from typing import Dict, Any, List
from .base import EnrichmentSourceBase

log = logging.getLogger(__name__)


class CertificateTransparency(EnrichmentSourceBase):
    """Certificate Transparency source using crt.sh database"""

    name = "crtsh"
    ioc_support = {"domain"}
    base_url = "https://crt.sh"

    def __init__(self):
        super().__init__()
        self.headers = {
            'User-Agent': 'IRIS-IOC-Enrichment/1.0'
        }

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 8) -> Dict[str, Any]:
        """
        Fetch certificate transparency data for domain

        Args:
            ioc_type: Type of IOC (should be 'domain')
            ioc_value: Domain to lookup
            timeout_s: Request timeout in seconds

        Returns:
            Dict containing certificate data or error information
        """
        if ioc_type != "domain":
            return {"_error": f"Certificate Transparency source only supports domains, not {ioc_type}"}

        try:
            # Query crt.sh for certificates
            params = {
                'q': ioc_value,
                'output': 'json'
            }

            response = requests.get(
                self.base_url,
                params=params,
                headers=self.headers,
                timeout=timeout_s
            )

            if response.status_code == 200:
                data = response.json() if response.text.strip() else []

                if not data:
                    return {
                        'domain': ioc_value,
                        'certificate_count': 0,
                        'certificates': [],
                        'certificate_authorities': [],
                        'earliest_certificate': None,
                        'latest_certificate': None,
                        'subdomains': [],
                        '_source': self.name,
                        '_timestamp': self._get_timestamp(),
                        '_raw_response': data
                    }

                # Process and normalize certificate data
                certificates = self._process_certificates(data[:50])  # Limit to 50 most recent
                subdomains = self._extract_subdomains(data, ioc_value)
                cert_authorities = self._extract_certificate_authorities(data)

                normalized_data = {
                    'domain': ioc_value,
                    'certificate_count': len(data),
                    'certificates': certificates,
                    'certificate_authorities': cert_authorities,
                    'earliest_certificate': min([cert['not_before'] for cert in certificates if cert.get('not_before')], default=None),
                    'latest_certificate': max([cert['not_after'] for cert in certificates if cert.get('not_after')], default=None),
                    'subdomains': subdomains[:20],  # Limit to 20 subdomains
                    'wildcard_certificates': len([cert for cert in certificates if cert.get('is_wildcard', False)]),
                    '_source': self.name,
                    '_timestamp': self._get_timestamp(),
                    '_raw_response': data[:10]  # Store only first 10 for space
                }

                log.info(f"Successfully fetched certificate data for {ioc_value}")
                return normalized_data

            else:
                return self._handle_request_error(response, "crt.sh")

        except requests.exceptions.Timeout:
            return {"_error": f"crt.sh request timeout after {timeout_s} seconds"}
        except requests.exceptions.RequestException as e:
            return {"_error": f"crt.sh request failed: {str(e)}"}
        except Exception as e:
            log.error(f"Unexpected error in crt.sh lookup for {ioc_value}: {str(e)}")
            return {"_error": f"Unexpected error: {str(e)}"}

    def _process_certificates(self, cert_data: List[Dict]) -> List[Dict]:
        """Process raw certificate data into normalized format"""
        certificates = []

        for cert in cert_data[:10]:  # Limit to 10 certificates
            try:
                cert_info = {
                    'id': cert.get('id'),
                    'name_value': cert.get('name_value'),
                    'issuer_name': cert.get('issuer_name'),
                    'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after'),
                    'is_wildcard': '*' in cert.get('name_value', ''),
                    'common_name': cert.get('common_name')
                }
                certificates.append(cert_info)
            except Exception as e:
                log.warning(f"Error processing certificate: {str(e)}")
                continue

        return certificates

    def _extract_subdomains(self, cert_data: List[Dict], base_domain: str) -> List[str]:
        """Extract unique subdomains from certificate data"""
        subdomains = set()

        for cert in cert_data:
            name_value = cert.get('name_value', '')
            if name_value:
                # Split by newlines for SAN certificates
                names = name_value.split('\n')
                for name in names:
                    name = name.strip().lower()
                    # Only include subdomains of the target domain
                    if name.endswith(base_domain) and name != base_domain:
                        # Remove wildcards for cleaner subdomain list
                        clean_name = name.replace('*.', '')
                        if clean_name != base_domain:
                            subdomains.add(clean_name)

        return sorted(list(subdomains))

    def _extract_certificate_authorities(self, cert_data: List[Dict]) -> List[Dict]:
        """Extract and count certificate authorities"""
        ca_counts = {}

        for cert in cert_data:
            issuer = cert.get('issuer_name', '')
            if issuer:
                ca_counts[issuer] = ca_counts.get(issuer, 0) + 1

        # Return top 10 CAs sorted by count
        sorted_cas = sorted(ca_counts.items(), key=lambda x: x[1], reverse=True)
        return [{'name': ca, 'count': count} for ca, count in sorted_cas[:10]]

    def get_reputation_score(self, data: Dict[str, Any]) -> int:
        """
        Calculate reputation score based on certificate data

        Args:
            data: Normalized certificate data

        Returns:
            Risk score (0-100, higher = more suspicious)
        """
        if "_error" in data:
            return 0

        risk_score = 0

        # No certificates might indicate a new/suspicious domain
        cert_count = data.get('certificate_count', 0)
        if cert_count == 0:
            risk_score += 20
        elif cert_count < 3:
            risk_score += 10

        # Many certificates might indicate suspicious activity
        if cert_count > 100:
            risk_score += 15

        # Check for suspicious certificate patterns
        wildcard_count = data.get('wildcard_certificates', 0)
        if wildcard_count > 5:
            risk_score += 10

        # Check for unusual number of subdomains
        subdomain_count = len(data.get('subdomains', []))
        if subdomain_count > 50:
            risk_score += 15
        elif subdomain_count > 20:
            risk_score += 10

        # Check certificate authorities
        cas = data.get('certificate_authorities', [])
        suspicious_cas = ['Let\'s Encrypt']  # Free CAs often used by malicious actors
        for ca in cas:
            if any(sus_ca.lower() in ca.get('name', '').lower() for sus_ca in suspicious_cas):
                # Only if it's the ONLY CA used
                if len(cas) == 1:
                    risk_score += 5

        return min(risk_score, 100)