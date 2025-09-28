"""
Base class for enrichment sources
All enrichment sources must inherit from this class
"""

import abc
import logging
import requests
from typing import Dict, Any, Set, Optional
from datetime import datetime

log = logging.getLogger(__name__)


class EnrichmentSourceBase(abc.ABC):
    """Abstract base class for all enrichment sources"""

    # Source metadata - must be defined by subclasses
    name: str = None
    description: str = None
    ioc_support: Set[str] = set()  # Supported IOC types: 'ip', 'domain', 'hash', 'url', etc.

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the enrichment source

        Args:
            config: Optional configuration dictionary with API keys, settings, etc.
        """
        if not self.name:
            raise ValueError(f"Source {self.__class__.__name__} must define a 'name' attribute")

        if not self.ioc_support:
            raise ValueError(f"Source {self.name} must define supported IOC types in 'ioc_support'")

        self.config = config or {}
        self._session = None

    @property
    def session(self) -> requests.Session:
        """Get or create HTTP session for this source"""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({
                'User-Agent': 'IRIS-IOC-Enrichment/1.0'
            })
        return self._session

    def supports_ioc_type(self, ioc_type: str) -> bool:
        """Check if this source supports the given IOC type"""
        return ioc_type.lower() in self.ioc_support

    @abc.abstractmethod
    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 6) -> Dict[str, Any]:
        """
        Fetch enrichment data for an IOC

        Args:
            ioc_type: Type of IOC ('ip', 'domain', 'hash', etc.)
            ioc_value: The IOC value to enrich
            timeout_s: Timeout in seconds for the request

        Returns:
            Dictionary with enrichment data. On error, should return {"_error": "error message"}
        """
        pass

    def _handle_request_error(self, e: Exception, ioc_value: str) -> Dict[str, Any]:
        """Handle request errors consistently"""
        error_msg = f"Error fetching data for {ioc_value} from {self.name}: {str(e)}"
        log.warning(error_msg)
        return {"_error": error_msg}

    def _make_request(self, url: str, params: Optional[Dict] = None,
                     headers: Optional[Dict] = None, timeout: int = 6) -> Dict[str, Any]:
        """
        Make HTTP request with consistent error handling

        Returns:
            Response JSON data or error dict
        """
        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers or {},
                timeout=timeout
            )
            response.raise_for_status()

            # Try to parse JSON
            try:
                return response.json()
            except ValueError:
                return {
                    "_error": f"Invalid JSON response from {self.name}",
                    "_raw_response": response.text[:500]  # First 500 chars
                }

        except requests.exceptions.RequestException as e:
            return self._handle_request_error(e, url)
        except Exception as e:
            return self._handle_request_error(e, url)

    def get_api_key(self, key_name: str) -> Optional[str]:
        """Get API key from configuration"""
        return self.config.get(key_name)

    def is_configured(self) -> bool:
        """Check if the source is properly configured (override in subclasses)"""
        return True

    def _get_timestamp(self) -> float:
        """Get current timestamp for data collection"""
        import time
        return time.time()

    def __repr__(self):
        return f"{self.__class__.__name__}(name='{self.name}', supports={list(self.ioc_support)})"