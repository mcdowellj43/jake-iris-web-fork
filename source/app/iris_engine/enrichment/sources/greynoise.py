"""
GreyNoise enrichment source
https://greynoise.io/
"""

import ipaddress
from typing import Dict, Any
from .base import EnrichmentSourceBase


class GreyNoise(EnrichmentSourceBase):
    """GreyNoise scanner and targeting intelligence"""

    name = "greynoise"
    description = "Scanner vs targeted traffic intelligence from GreyNoise"
    ioc_support = {"ip"}

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.api_key = self.get_api_key("greynoise_api_key")
        self.use_community = config.get("greynoise_use_community", True) if config else True

        if self.use_community:
            self.base_url = "https://api.greynoise.io/v3/community"
        else:
            self.base_url = "https://api.greynoise.io/v2"

    def is_configured(self) -> bool:
        """Community API doesn't require key, paid API does"""
        if self.use_community:
            return True
        return bool(self.api_key)

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 6) -> Dict[str, Any]:
        """Fetch IP intelligence from GreyNoise"""
        if not self.supports_ioc_type(ioc_type):
            return {"_error": f"IOC type '{ioc_type}' not supported by {self.name}"}

        # Validate IP address
        try:
            ipaddress.ip_address(ioc_value)
        except ValueError:
            return {"_error": f"Invalid IP address: {ioc_value}"}

        if self.use_community:
            return self._fetch_community(ioc_value, timeout_s)
        else:
            return self._fetch_enterprise(ioc_value, timeout_s)

    def _fetch_community(self, ip: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch from community API (free, limited)"""
        url = f"{self.base_url}/{ip}"

        response_data = self._make_request(url, timeout=timeout_s)

        if "_error" in response_data:
            return response_data

        try:
            return {
                "ip": ip,
                "noise": response_data.get("noise", False),
                "riot": response_data.get("riot", False),
                "classification": response_data.get("classification", ""),
                "name": response_data.get("name", ""),
                "link": response_data.get("link", ""),
                "last_seen": response_data.get("last_seen", ""),
                "message": response_data.get("message", ""),
                "_tier": "community",
                "_raw": response_data
            }

        except Exception as e:
            return {"_error": f"Error parsing GreyNoise community response: {str(e)}"}

    def _fetch_enterprise(self, ip: str, timeout_s: int) -> Dict[str, Any]:
        """Fetch from enterprise API (requires API key)"""
        if not self.api_key:
            return {"_error": "GreyNoise API key required for enterprise features"}

        url = f"{self.base_url}/noise/context/{ip}"
        headers = {"key": self.api_key}

        response_data = self._make_request(url, headers=headers, timeout=timeout_s)

        if "_error" in response_data:
            return response_data

        try:
            return {
                "ip": ip,
                "seen": response_data.get("seen", False),
                "classification": response_data.get("classification", ""),
                "first_seen": response_data.get("first_seen", ""),
                "last_seen": response_data.get("last_seen", ""),
                "actor": response_data.get("actor", ""),
                "tags": response_data.get("tags", []),
                "metadata": response_data.get("metadata", {}),
                "raw_data": response_data.get("raw_data", {}),
                "_tier": "enterprise",
                "_raw": response_data
            }

        except Exception as e:
            return {"_error": f"Error parsing GreyNoise enterprise response: {str(e)}"}