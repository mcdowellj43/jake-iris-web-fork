"""
VirusTotal enrichment source
https://www.virustotal.com/vtapi/v2/
"""

import hashlib
import re
from typing import Dict, Any
from .base import EnrichmentSourceBase


class VirusTotal(EnrichmentSourceBase):
    """VirusTotal malware analysis and threat intelligence"""

    name = "virustotal"
    description = "Malware analysis and threat intelligence from VirusTotal"
    ioc_support = {"hash", "ip", "domain", "url"}

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.api_key = self.get_api_key("virustotal_api_key")
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.is_premium = config.get("virustotal_premium", False) if config else False

    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key)

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 6) -> Dict[str, Any]:
        """Fetch threat intelligence from VirusTotal"""
        if not self.supports_ioc_type(ioc_type):
            return {"_error": f"IOC type '{ioc_type}' not supported by {self.name}"}

        if not self.is_configured():
            return {"_error": "VirusTotal API key not configured"}

        # Route to appropriate handler based on IOC type
        if ioc_type == "hash":
            return self._fetch_file_report(ioc_value, timeout_s)
        elif ioc_type == "ip":
            return self._fetch_ip_report(ioc_value, timeout_s)
        elif ioc_type == "domain":
            return self._fetch_domain_report(ioc_value, timeout_s)
        elif ioc_type == "url":
            return self._fetch_url_report(ioc_value, timeout_s)
        else:
            return {"_error": f"Unsupported IOC type: {ioc_type}"}

    def _fetch_file_report(self, file_hash: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch file/hash report"""
        # Validate hash format
        if not self._is_valid_hash(file_hash):
            return {"_error": f"Invalid hash format: {file_hash}"}

        url = f"{self.base_url}/file/report"
        params = {
            "apikey": self.api_key,
            "resource": file_hash
        }

        response_data = self._make_request(url, params=params, timeout=timeout_s)

        if "_error" in response_data:
            return response_data

        try:
            return {
                "hash": file_hash,
                "sha256": response_data.get("sha256", ""),
                "md5": response_data.get("md5", ""),
                "sha1": response_data.get("sha1", ""),
                "scan_date": response_data.get("scan_date", ""),
                "positives": response_data.get("positives", 0),
                "total": response_data.get("total", 0),
                "detection_ratio": f"{response_data.get('positives', 0)}/{response_data.get('total', 0)}",
                "permalink": response_data.get("permalink", ""),
                "scans": response_data.get("scans", {}),
                "response_code": response_data.get("response_code", 0),
                "_raw": response_data
            }

        except Exception as e:
            return {"_error": f"Error parsing VirusTotal file response: {str(e)}"}

    def _fetch_ip_report(self, ip_address: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch IP address report"""
        url = f"{self.base_url}/ip-address/report"
        params = {
            "apikey": self.api_key,
            "ip": ip_address
        }

        response_data = self._make_request(url, params=params, timeout=timeout_s)

        if "_error" in response_data:
            return response_data

        try:
            return {
                "ip": ip_address,
                "asn": response_data.get("asn", ""),
                "country": response_data.get("country", ""),
                "as_owner": response_data.get("as_owner", ""),
                "detected_urls": response_data.get("detected_urls", []),
                "detected_downloaded_samples": response_data.get("detected_downloaded_samples", []),
                "detected_communicating_samples": response_data.get("detected_communicating_samples", []),
                "resolutions": response_data.get("resolutions", []),
                "response_code": response_data.get("response_code", 0),
                "_raw": response_data
            }

        except Exception as e:
            return {"_error": f"Error parsing VirusTotal IP response: {str(e)}"}

    def _fetch_domain_report(self, domain: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch domain report"""
        url = f"{self.base_url}/domain/report"
        params = {
            "apikey": self.api_key,
            "domain": domain
        }

        response_data = self._make_request(url, params=params, timeout=timeout_s)

        if "_error" in response_data:
            return response_data

        try:
            return {
                "domain": domain,
                "whois": response_data.get("whois", ""),
                "detected_urls": response_data.get("detected_urls", []),
                "detected_downloaded_samples": response_data.get("detected_downloaded_samples", []),
                "detected_communicating_samples": response_data.get("detected_communicating_samples", []),
                "resolutions": response_data.get("resolutions", []),
                "subdomains": response_data.get("subdomains", []),
                "categories": response_data.get("categories", []),
                "response_code": response_data.get("response_code", 0),
                "_raw": response_data
            }

        except Exception as e:
            return {"_error": f"Error parsing VirusTotal domain response: {str(e)}"}

    def _fetch_url_report(self, url: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch URL report"""
        vt_url = f"{self.base_url}/url/report"
        params = {
            "apikey": self.api_key,
            "resource": url
        }

        response_data = self._make_request(vt_url, params=params, timeout=timeout_s)

        if "_error" in response_data:
            return response_data

        try:
            return {
                "url": url,
                "scan_date": response_data.get("scan_date", ""),
                "positives": response_data.get("positives", 0),
                "total": response_data.get("total", 0),
                "detection_ratio": f"{response_data.get('positives', 0)}/{response_data.get('total', 0)}",
                "permalink": response_data.get("permalink", ""),
                "scans": response_data.get("scans", {}),
                "response_code": response_data.get("response_code", 0),
                "_raw": response_data
            }

        except Exception as e:
            return {"_error": f"Error parsing VirusTotal URL response: {str(e)}"}

    def _is_valid_hash(self, hash_value: str) -> bool:
        """Validate hash format (MD5, SHA1, SHA256)"""
        hash_value = hash_value.lower().strip()

        # MD5: 32 hex chars
        if len(hash_value) == 32 and re.match(r'^[a-f0-9]{32}$', hash_value):
            return True

        # SHA1: 40 hex chars
        if len(hash_value) == 40 and re.match(r'^[a-f0-9]{40}$', hash_value):
            return True

        # SHA256: 64 hex chars
        if len(hash_value) == 64 and re.match(r'^[a-f0-9]{64}$', hash_value):
            return True

        return False