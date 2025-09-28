"""
Profile System for IOC Enrichment
Manages YAML-based enrichment profiles and their configurations
"""

import os
import yaml
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

log = logging.getLogger(__name__)


class EnrichmentProfile:
    """Represents a single enrichment profile"""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.ioc_type = config.get('ioc_type')
        self.description = config.get('description', '')
        self.sources = config.get('sources', [])
        self.cache_ttl = config.get('cache_ttl', 86400)
        self.timeout_s = config.get('timeout_s', 6)
        self.config = config

    def supports_ioc_type(self, ioc_type: str) -> bool:
        """Check if this profile supports the given IOC type"""
        return self.ioc_type == ioc_type or self.ioc_type == 'any'

    def __repr__(self):
        return f"EnrichmentProfile(name='{self.name}', ioc_type='{self.ioc_type}', sources={self.sources})"


class ProfileManager:
    """Manages enrichment profiles and their loading/caching"""

    def __init__(self, profiles_dir: Optional[str] = None):
        if profiles_dir is None:
            profiles_dir = os.path.join(os.path.dirname(__file__), 'profiles')

        self.profiles_dir = Path(profiles_dir)
        self._profiles: Dict[str, EnrichmentProfile] = {}
        self._loaded = False

    def load_profiles(self) -> None:
        """Load all profiles from YAML files in the profiles directory"""
        if not self.profiles_dir.exists():
            log.warning(f"Profiles directory does not exist: {self.profiles_dir}")
            return

        self._profiles.clear()

        # Load default profiles first
        default_profiles = self._get_default_profiles()
        for name, config in default_profiles.items():
            self._profiles[name] = EnrichmentProfile(name, config)

        # Load profiles from YAML files
        for yaml_file in self.profiles_dir.glob('*.yaml'):
            try:
                with open(yaml_file, 'r') as f:
                    profiles_data = yaml.safe_load(f)

                if 'profiles' in profiles_data:
                    for name, config in profiles_data['profiles'].items():
                        self._profiles[name] = EnrichmentProfile(name, config)
                        log.info(f"Loaded profile: {name} from {yaml_file}")

            except Exception as e:
                log.error(f"Error loading profile from {yaml_file}: {e}")

        self._loaded = True
        log.info(f"Loaded {len(self._profiles)} enrichment profiles")

    def get_profile(self, name: str) -> Optional[EnrichmentProfile]:
        """Get a specific profile by name"""
        if not self._loaded:
            self.load_profiles()

        return self._profiles.get(name)

    def get_profiles_for_ioc_type(self, ioc_type: str) -> List[EnrichmentProfile]:
        """Get all profiles that support the given IOC type"""
        if not self._loaded:
            self.load_profiles()

        return [profile for profile in self._profiles.values()
                if profile.supports_ioc_type(ioc_type)]

    def list_profiles(self) -> Dict[str, EnrichmentProfile]:
        """Get all available profiles"""
        if not self._loaded:
            self.load_profiles()

        return self._profiles.copy()

    def _get_default_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Return default built-in profiles"""
        return {
            'IP-basic': {
                'ioc_type': 'ip',
                'description': 'Quick IP risk context',
                'sources': ['abuseipdb', 'greynoise', 'talos', 'rdap', 'geoip'],
                'cache_ttl': 86400,
                'timeout_s': 6
            },
            'Domain-basic': {
                'ioc_type': 'domain',
                'description': 'Phishing/infrastructure context',
                'sources': ['otx', 'talos', 'whois', 'crtsh', 'urlhaus'],
                'cache_ttl': 86400,
                'timeout_s': 8
            },
            'Hash-basic': {
                'ioc_type': 'hash',
                'description': 'Malware reputation',
                'sources': ['virustotal', 'hybridanalysis', 'malwarebazaar'],
                'cache_ttl': 86400,
                'timeout_s': 8
            }
        }


# Global profile manager instance
_profile_manager = None


def get_profile_manager() -> ProfileManager:
    """Get the global profile manager instance"""
    global _profile_manager
    if _profile_manager is None:
        _profile_manager = ProfileManager()
    return _profile_manager


def load_profiles() -> None:
    """Load/reload all profiles"""
    get_profile_manager().load_profiles()


def get_profile(name: str) -> Optional[EnrichmentProfile]:
    """Get a specific profile by name"""
    return get_profile_manager().get_profile(name)


def get_profiles_for_ioc_type(ioc_type: str) -> List[EnrichmentProfile]:
    """Get all profiles that support the given IOC type"""
    return get_profile_manager().get_profiles_for_ioc_type(ioc_type)


def list_profiles() -> Dict[str, EnrichmentProfile]:
    """Get all available profiles"""
    return get_profile_manager().list_profiles()