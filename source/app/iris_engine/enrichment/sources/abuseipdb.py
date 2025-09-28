"""
AbuseIPDB enrichment source
https://www.abuseipdb.com/api
"""

import ipaddress
from typing import Dict, Any
from .base import EnrichmentSourceBase


class AbuseIPDB(EnrichmentSourceBase):
    """AbuseIPDB IP reputation and abuse reporting service"""

    name = "abuseipdb"
    description = "IP reputation and abuse categories from AbuseIPDB"
    ioc_support = {"ip"}

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.api_key = self.get_api_key("abuseipdb_api_key")
        self.base_url = "https://api.abuseipdb.com/api/v2"

    def is_configured(self) -> bool:
        """Check if API key is configured"""
        return bool(self.api_key)

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 6) -> Dict[str, Any]:
        """Fetch IP reputation data from AbuseIPDB"""
        if not self.supports_ioc_type(ioc_type):
            return {"_error": f"IOC type '{ioc_type}' not supported by {self.name}"}

        if not self.is_configured():
            return {"_error": f"AbuseIPDB API key not configured"}

        # Validate IP address
        try:
            ipaddress.ip_address(ioc_value)
        except ValueError:
            return {"_error": f"Invalid IP address: {ioc_value}"}

        url = f"{self.base_url}/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ioc_value,
            "maxAgeInDays": "90",
            "verbose": ""
        }

        response_data = self._make_request(url, params=params, headers=headers, timeout=timeout_s)

        if "_error" in response_data:
            return response_data

        # Extract relevant data
        try:
            data = response_data.get("data", {})
            return {
                "ip": ioc_value,
                "abuse_confidence": data.get("abuseConfidencePercentage", 0),
                "usage_type": data.get("usageType", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "country_code": data.get("countryCode", ""),
                "is_public": data.get("isPublic", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt", ""),
                "_raw": response_data
            }

        except Exception as e:
            return {"_error": f"Error parsing AbuseIPDB response: {str(e)}"}


class AbuseIPDBFree(AbuseIPDB):
    """Free tier version of AbuseIPDB with limited features"""

    name = "abuseipdb_free"
    description = "AbuseIPDB free tier (limited features)"

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 6) -> Dict[str, Any]:
        """Fetch with free tier limitations"""
        result = super().fetch(ioc_type, ioc_value, timeout_s)

        # Free tier doesn't get detailed usage info
        if "_error" not in result:
            result["_note"] = "Limited data (free tier)"

        return result