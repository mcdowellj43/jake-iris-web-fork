"""
Enrichment Configuration and Caching System
Handles configuration management and caching for enrichment operations
"""

import logging
import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class EnrichmentConfig:
    """Configuration for enrichment operations"""

    # Cache settings
    cache_enabled: bool = True
    cache_default_ttl: int = 86400  # 24 hours
    cache_max_entries: int = 10000
    cache_cleanup_interval: int = 3600  # 1 hour

    # API rate limiting
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 60
    rate_limit_burst_size: int = 10

    # Timeout settings
    default_timeout: int = 6
    max_timeout: int = 30

    # Retry settings
    retry_enabled: bool = True
    max_retries: int = 3
    retry_backoff_factor: float = 2.0
    retry_max_delay: int = 60

    # Job settings
    job_cleanup_hours: int = 24
    max_concurrent_jobs: int = 50
    job_progress_update_interval: int = 5

    # Source-specific configurations
    source_configs: Dict[str, Dict[str, Any]] = None

    def __post_init__(self):
        if self.source_configs is None:
            self.source_configs = self._get_default_source_configs()

    def _get_default_source_configs(self) -> Dict[str, Dict[str, Any]]:
        """Get default source configurations"""
        return {
            "abuseipdb": {
                "api_key": None,
                "rate_limit": 1000,  # per day for free tier
                "timeout": 10,
                "retries": 2
            },
            "greynoise": {
                "api_key": None,
                "use_community": True,
                "timeout": 8,
                "retries": 3
            },
            "virustotal": {
                "api_key": None,
                "is_premium": False,
                "rate_limit": 500,  # per day for free tier
                "timeout": 15,
                "retries": 2
            },
            "talos": {
                "timeout": 6,
                "retries": 3
            }
        }

    def get_source_config(self, source_name: str) -> Dict[str, Any]:
        """Get configuration for a specific source"""
        return self.source_configs.get(source_name, {})

    def update_source_config(self, source_name: str, config: Dict[str, Any]) -> None:
        """Update configuration for a specific source"""
        if source_name in self.source_configs:
            self.source_configs[source_name].update(config)
        else:
            self.source_configs[source_name] = config


class EnrichmentCache:
    """Simple in-memory cache for enrichment results with TTL support"""

    def __init__(self, config: EnrichmentConfig):
        self.config = config
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_cleanup = time.time()

    def _generate_cache_key(self, source: str, ioc_type: str, ioc_value: str) -> str:
        """Generate a cache key for the given parameters"""
        key_data = f"{source}:{ioc_type}:{ioc_value.lower()}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(self, source: str, ioc_type: str, ioc_value: str) -> Optional[Dict[str, Any]]:
        """Get cached result if available and not expired"""
        if not self.config.cache_enabled:
            return None

        cache_key = self._generate_cache_key(source, ioc_type, ioc_value)

        if cache_key in self._cache:
            entry = self._cache[cache_key]

            # Check if entry is expired
            if time.time() - entry["timestamp"] > entry["ttl"]:
                del self._cache[cache_key]
                return None

            log.debug(f"Cache hit for {source}:{ioc_type}:{ioc_value}")
            return entry["data"]

        return None

    def set(self, source: str, ioc_type: str, ioc_value: str, data: Dict[str, Any],
            ttl: int = None) -> None:
        """Store result in cache with TTL"""
        if not self.config.cache_enabled:
            return

        if "_error" in data:
            # Don't cache error results
            return

        cache_key = self._generate_cache_key(source, ioc_type, ioc_value)
        cache_ttl = ttl or self.config.cache_default_ttl

        self._cache[cache_key] = {
            "data": data,
            "timestamp": time.time(),
            "ttl": cache_ttl,
            "source": source,
            "ioc_type": ioc_type,
            "ioc_value": ioc_value
        }

        log.debug(f"Cached result for {source}:{ioc_type}:{ioc_value}")

        # Cleanup if needed
        self._maybe_cleanup()

    def _maybe_cleanup(self) -> None:
        """Cleanup expired entries if needed"""
        current_time = time.time()

        # Only cleanup periodically
        if current_time - self._last_cleanup < self.config.cache_cleanup_interval:
            return

        self._last_cleanup = current_time

        # Remove expired entries
        expired_keys = []
        for key, entry in self._cache.items():
            if current_time - entry["timestamp"] > entry["ttl"]:
                expired_keys.append(key)

        for key in expired_keys:
            del self._cache[key]

        # Remove oldest entries if cache is too large
        if len(self._cache) > self.config.cache_max_entries:
            # Sort by timestamp and remove oldest
            sorted_entries = sorted(
                self._cache.items(),
                key=lambda x: x[1]["timestamp"]
            )

            entries_to_remove = len(self._cache) - self.config.cache_max_entries
            for i in range(entries_to_remove):
                key = sorted_entries[i][0]
                del self._cache[key]

        if expired_keys or len(self._cache) > self.config.cache_max_entries:
            log.info(f"Cache cleanup: removed {len(expired_keys)} expired entries")

    def invalidate(self, source: str = None, ioc_type: str = None, ioc_value: str = None) -> int:
        """Invalidate cache entries matching the criteria"""
        if not any([source, ioc_type, ioc_value]):
            # Clear all cache
            count = len(self._cache)
            self._cache.clear()
            return count

        keys_to_remove = []

        for key, entry in self._cache.items():
            should_remove = True

            if source and entry["source"] != source:
                should_remove = False
            if ioc_type and entry["ioc_type"] != ioc_type:
                should_remove = False
            if ioc_value and entry["ioc_value"].lower() != ioc_value.lower():
                should_remove = False

            if should_remove:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self._cache[key]

        return len(keys_to_remove)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        current_time = time.time()
        expired_count = 0

        for entry in self._cache.values():
            if current_time - entry["timestamp"] > entry["ttl"]:
                expired_count += 1

        return {
            "total_entries": len(self._cache),
            "expired_entries": expired_count,
            "max_entries": self.config.cache_max_entries,
            "cache_enabled": self.config.cache_enabled,
            "default_ttl": self.config.cache_default_ttl
        }


class RateLimiter:
    """Simple rate limiter for API calls"""

    def __init__(self, config: EnrichmentConfig):
        self.config = config
        self._requests: Dict[str, List[float]] = {}

    def is_allowed(self, source: str) -> bool:
        """Check if request is allowed under rate limits"""
        if not self.config.rate_limit_enabled:
            return True

        current_time = time.time()
        source_config = self.config.get_source_config(source)
        rate_limit = source_config.get("rate_limit", self.config.rate_limit_per_minute)

        if source not in self._requests:
            self._requests[source] = []

        # Remove old requests (older than 1 minute)
        minute_ago = current_time - 60
        self._requests[source] = [
            req_time for req_time in self._requests[source]
            if req_time > minute_ago
        ]

        # Check if under limit
        if len(self._requests[source]) < rate_limit:
            self._requests[source].append(current_time)
            return True

        return False

    def get_retry_after(self, source: str) -> float:
        """Get seconds to wait before next request"""
        if not self._requests.get(source):
            return 0

        oldest_request = min(self._requests[source])
        return max(0, 60 - (time.time() - oldest_request))


class RetryHandler:
    """Handles retry logic for failed enrichment requests"""

    def __init__(self, config: EnrichmentConfig):
        self.config = config

    def should_retry(self, attempt: int, error: Exception) -> bool:
        """Determine if a request should be retried"""
        if not self.config.retry_enabled:
            return False

        if attempt >= self.config.max_retries:
            return False

        # Check error type for retry eligibility
        error_str = str(error).lower()

        # Retry on network/timeout errors
        if any(keyword in error_str for keyword in [
            "timeout", "connection", "network", "unreachable",
            "502", "503", "504", "429"  # HTTP status codes
        ]):
            return True

        # Don't retry on authentication/authorization errors
        if any(keyword in error_str for keyword in [
            "401", "403", "unauthorized", "forbidden", "api key"
        ]):
            return False

        # Retry on 5xx server errors
        if any(status in error_str for status in ["500", "502", "503", "504"]):
            return True

        return False

    def get_retry_delay(self, attempt: int) -> float:
        """Calculate delay before retry"""
        base_delay = 1.0
        delay = base_delay * (self.config.retry_backoff_factor ** attempt)
        return min(delay, self.config.retry_max_delay)


# Global configuration instance
_config = None
_cache = None
_rate_limiter = None
_retry_handler = None


def get_enrichment_config() -> EnrichmentConfig:
    """Get the global enrichment configuration"""
    global _config
    if _config is None:
        _config = EnrichmentConfig()
    return _config


def get_enrichment_cache() -> EnrichmentCache:
    """Get the global enrichment cache"""
    global _cache
    if _cache is None:
        config = get_enrichment_config()
        _cache = EnrichmentCache(config)
    return _cache


def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter"""
    global _rate_limiter
    if _rate_limiter is None:
        config = get_enrichment_config()
        _rate_limiter = RateLimiter(config)
    return _rate_limiter


def get_retry_handler() -> RetryHandler:
    """Get the global retry handler"""
    global _retry_handler
    if _retry_handler is None:
        config = get_enrichment_config()
        _retry_handler = RetryHandler(config)
    return _retry_handler


def update_config_from_dict(config_dict: Dict[str, Any]) -> None:
    """Update global configuration from dictionary"""
    global _config
    config = get_enrichment_config()

    for key, value in config_dict.items():
        if hasattr(config, key):
            setattr(config, key, value)

    log.info("Updated enrichment configuration")


def load_config_from_file(config_path: Union[str, Path]) -> None:
    """Load configuration from JSON file"""
    try:
        with open(config_path, 'r') as f:
            config_dict = json.load(f)

        update_config_from_dict(config_dict)
        log.info(f"Loaded enrichment configuration from {config_path}")

    except Exception as e:
        log.error(f"Failed to load enrichment configuration from {config_path}: {str(e)}")
        raise


def save_config_to_file(config_path: Union[str, Path]) -> None:
    """Save current configuration to JSON file"""
    try:
        config = get_enrichment_config()
        config_dict = asdict(config)

        with open(config_path, 'w') as f:
            json.dump(config_dict, f, indent=2)

        log.info(f"Saved enrichment configuration to {config_path}")

    except Exception as e:
        log.error(f"Failed to save enrichment configuration to {config_path}: {str(e)}")
        raise