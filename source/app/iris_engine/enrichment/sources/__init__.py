# Enrichment Sources
# Individual source implementations for IOC enrichment

from .base import EnrichmentSourceBase
from .abuseipdb import AbuseIPDB
from .greynoise import GreyNoise
from .talos import CiscoTalos
from .rdap import RDAP
from .geoip import GeoIPLite
from .otx import AlienVaultOTX
from .whois import Whois
from .crtsh import CertificateTransparency
from .urlhaus import URLhaus
from .virustotal import VirusTotal
from .hybridanalysis import HybridAnalysis
from .malwarebazaar import MalwareBazaar
from .shodan import Shodan
from .passivetotal import PassiveTotal

# Source registry - all implemented sources
SOURCES = {
    'abuseipdb': AbuseIPDB,
    'greynoise': GreyNoise,
    'talos': CiscoTalos,
    'rdap': RDAP,
    'geoip': GeoIPLite,
    'otx': AlienVaultOTX,
    'whois': Whois,
    'crtsh': CertificateTransparency,
    'urlhaus': URLhaus,
    'virustotal': VirusTotal,
    'hybridanalysis': HybridAnalysis,
    'malwarebazaar': MalwareBazaar,
    'shodan': Shodan,
    'passivetotal': PassiveTotal,
}

__all__ = ['EnrichmentSourceBase', 'SOURCES'] + list(SOURCES.keys())