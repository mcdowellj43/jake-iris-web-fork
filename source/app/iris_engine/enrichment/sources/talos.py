"""
Cisco Talos enrichment source
https://talosintelligence.com/
"""

import ipaddress
from typing import Dict, Any
from .base import EnrichmentSourceBase


class CiscoTalos(EnrichmentSourceBase):
    """Cisco Talos threat intelligence"""

    name = "talos"
    description = "Threat intelligence from Cisco Talos"
    ioc_support = {"ip", "domain"}

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        # Talos has a public reputation API
        self.base_url = "https://talosintelligence.com/sb_api/query_lookup"

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 6) -> Dict[str, Any]:
        """Fetch reputation data from Cisco Talos"""
        if not self.supports_ioc_type(ioc_type):
            return {"_error": f"IOC type '{ioc_type}' not supported by {self.name}"}

        params = {
            "query": f"/api/v2/details/ip/",
            "query_entry": ioc_value
        }

        if ioc_type == "domain":
            params["query"] = "/api/v2/details/domain/"

        response_data = self._make_request(self.base_url, params=params, timeout=timeout_s)

        if "_error" in response_data:
            return response_data

        try:
            # Parse Talos response format
            web_reputation = response_data.get("web_reputation", "Unknown")
            email_reputation = response_data.get("email_reputation", "Unknown")

            return {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "web_reputation": web_reputation,
                "email_reputation": email_reputation,
                "category": response_data.get("category", ""),
                "web_score_name": response_data.get("web_score_name", ""),
                "email_score_name": response_data.get("email_score_name", ""),
                "threat_types": response_data.get("threat_types", []),
                "_raw": response_data
            }

        except Exception as e:
            return {"_error": f"Error parsing Talos response: {str(e)}"}


class TalosFallback(EnrichmentSourceBase):
    """Fallback Talos implementation using web scraping approach"""

    name = "talos_fallback"
    description = "Cisco Talos (fallback method)"
    ioc_support = {"ip", "domain"}

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 6) -> Dict[str, Any]:
        """Simple fallback that returns basic structure"""
        return {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "web_reputation": "Unknown",
            "email_reputation": "Unknown",
            "category": "Unknown",
            "_note": "Fallback implementation - limited data available",
            "_error": None
        }