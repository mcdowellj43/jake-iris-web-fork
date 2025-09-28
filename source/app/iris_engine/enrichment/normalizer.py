"""
Enrichment Data Normalizer and Risk Scoring
Normalizes raw enrichment results into consistent structure with risk scores
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

log = logging.getLogger(__name__)


class EnrichmentNormalizer:
    """Normalizes and scores enrichment data from multiple sources"""

    def __init__(self):
        self.scoring_rules = self._get_scoring_rules()

    def normalize(self, ioc_type: str, ioc_value: str, raw_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Normalize raw enrichment results into consistent structure

        Args:
            ioc_type: Type of IOC (ip, domain, hash)
            ioc_value: The IOC value
            raw_results: Dict of {source_name: raw_result_data}

        Returns:
            Normalized enrichment data with risk score
        """
        # Initialize normalized structure
        normalized = {
            "ioc": {
                "type": ioc_type,
                "value": ioc_value
            },
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "risk_score": 0,
                "risk_level": "unknown",
                "classifications": [],
                "confidence": "low"
            },
            "sources": {},
            "errors": {},
            "metadata": {
                "sources_queried": list(raw_results.keys()),
                "sources_succeeded": [],
                "sources_failed": []
            }
        }

        # Process each source result
        for source_name, raw_data in raw_results.items():
            if "_error" in raw_data:
                normalized["errors"][source_name] = raw_data["_error"]
                normalized["metadata"]["sources_failed"].append(source_name)
            else:
                normalized["sources"][source_name] = self._normalize_source_data(source_name, raw_data)
                normalized["metadata"]["sources_succeeded"].append(source_name)

        # Calculate risk score and classifications
        self._calculate_risk_score(normalized, ioc_type)
        self._extract_classifications(normalized, ioc_type)

        # Add IOC-type specific summary data
        if ioc_type == "ip":
            self._add_ip_summary(normalized)
        elif ioc_type == "domain":
            self._add_domain_summary(normalized)
        elif ioc_type == "hash":
            self._add_hash_summary(normalized)

        return normalized

    def _normalize_source_data(self, source_name: str, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize data from a specific source"""
        # Remove internal/raw fields for cleaner output
        normalized = {}
        for key, value in raw_data.items():
            if not key.startswith('_'):
                normalized[key] = value

        # Add metadata
        normalized["_source"] = source_name
        normalized["_processed_at"] = datetime.utcnow().isoformat()

        return normalized

    def _calculate_risk_score(self, normalized: Dict[str, Any], ioc_type: str) -> None:
        """Calculate overall risk score based on source data"""
        risk_score = 0
        confidence_factors = []

        sources = normalized["sources"]

        # Apply IOC-type specific scoring rules
        if ioc_type == "ip":
            risk_score += self._score_ip_sources(sources, confidence_factors)
        elif ioc_type == "domain":
            risk_score += self._score_domain_sources(sources, confidence_factors)
        elif ioc_type == "hash":
            risk_score += self._score_hash_sources(sources, confidence_factors)

        # Clamp score to 0-100
        risk_score = max(0, min(100, risk_score))

        # Determine risk level
        risk_level = self._get_risk_level(risk_score)

        # Determine confidence based on number of sources and agreement
        confidence = self._calculate_confidence(confidence_factors, len(sources))

        normalized["summary"]["risk_score"] = risk_score
        normalized["summary"]["risk_level"] = risk_level
        normalized["summary"]["confidence"] = confidence

    def _score_ip_sources(self, sources: Dict[str, Any], confidence_factors: List[str]) -> int:
        """Score IP-specific sources"""
        score = 0

        # AbuseIPDB scoring
        if "abuseipdb" in sources:
            abuse_conf = sources["abuseipdb"].get("abuse_confidence", 0)
            if abuse_conf > 75:
                score += 30
                confidence_factors.append("abuseipdb_high")
            elif abuse_conf > 25:
                score += 15
                confidence_factors.append("abuseipdb_medium")

        # GreyNoise scoring
        if "greynoise" in sources:
            classification = sources["greynoise"].get("classification", "").lower()
            if classification == "malicious":
                score += 25
                confidence_factors.append("greynoise_malicious")
            elif classification == "benign":
                score -= 25  # Actually reduces risk
                confidence_factors.append("greynoise_benign")

        # Talos scoring
        if "talos" in sources:
            web_rep = sources["talos"].get("web_reputation", "").lower()
            if "poor" in web_rep or "malicious" in web_rep:
                score += 20
                confidence_factors.append("talos_poor")

        # VirusTotal IP scoring
        if "virustotal" in sources:
            detected_urls = len(sources["virustotal"].get("detected_urls", []))
            if detected_urls > 10:
                score += 15
                confidence_factors.append("vt_many_detections")
            elif detected_urls > 0:
                score += 5

        return score

    def _score_domain_sources(self, sources: Dict[str, Any], confidence_factors: List[str]) -> int:
        """Score domain-specific sources"""
        score = 0

        # OTX scoring
        if "otx" in sources:
            pulse_count = sources["otx"].get("pulse_count", 0)
            if pulse_count > 5:
                score += 20
                confidence_factors.append("otx_many_pulses")
            elif pulse_count > 0:
                score += 10

        # URLhaus scoring
        if "urlhaus" in sources:
            threat = sources["urlhaus"].get("threat", "").lower()
            if "malware" in threat:
                score += 25
                confidence_factors.append("urlhaus_malware")

        # VirusTotal domain scoring
        if "virustotal" in sources:
            detected_urls = len(sources["virustotal"].get("detected_urls", []))
            if detected_urls > 0:
                score += 15
                confidence_factors.append("vt_detected_urls")

        # Whois age scoring (newer domains are riskier)
        if "whois" in sources:
            creation_date = sources["whois"].get("creation_date", "")
            # Simplified: if we can parse the date and it's recent, add score
            # This would need proper date parsing in production

        return score

    def _score_hash_sources(self, sources: Dict[str, Any], confidence_factors: List[str]) -> int:
        """Score hash-specific sources"""
        score = 0

        # VirusTotal hash scoring
        if "virustotal" in sources:
            positives = sources["virustotal"].get("positives", 0)
            total = sources["virustotal"].get("total", 1)
            detection_rate = positives / total if total > 0 else 0

            if detection_rate > 0.5:
                score += 40
                confidence_factors.append("vt_high_detection")
            elif detection_rate > 0.1:
                score += 20
                confidence_factors.append("vt_medium_detection")
            elif positives > 0:
                score += 10

        # Hybrid Analysis scoring
        if "hybridanalysis" in sources:
            verdict = sources["hybridanalysis"].get("verdict", "").lower()
            if "malicious" in verdict:
                score += 30
                confidence_factors.append("hybrid_malicious")

        # MalwareBazaar scoring
        if "malwarebazaar" in sources:
            family = sources["malwarebazaar"].get("malware_family", "")
            if family and family != "Unknown":
                score += 25
                confidence_factors.append("malwarebazaar_known")

        return score

    def _extract_classifications(self, normalized: Dict[str, Any], ioc_type: str) -> None:
        """Extract classification tags from source data"""
        classifications = set()
        sources = normalized["sources"]

        if ioc_type == "ip":
            # AbuseIPDB categories
            if "abuseipdb" in sources:
                usage_type = sources["abuseipdb"].get("usage_type", "")
                if usage_type:
                    classifications.add(usage_type)

            # GreyNoise classifications
            if "greynoise" in sources:
                classification = sources["greynoise"].get("classification", "")
                if classification:
                    classifications.add(classification)

        elif ioc_type == "hash":
            # Malware families
            if "malwarebazaar" in sources:
                family = sources["malwarebazaar"].get("malware_family", "")
                if family and family != "Unknown":
                    classifications.add(f"Malware: {family}")

        normalized["summary"]["classifications"] = sorted(list(classifications))

    def _add_ip_summary(self, normalized: Dict[str, Any]) -> None:
        """Add IP-specific summary information"""
        sources = normalized["sources"]

        # Geolocation
        if "geoip" in sources:
            normalized["summary"]["geo"] = sources["geoip"].get("country", "Unknown")
            normalized["summary"]["asn"] = sources["geoip"].get("asn", "Unknown")

        # ISP information
        if "abuseipdb" in sources:
            normalized["summary"]["isp"] = sources["abuseipdb"].get("isp", "Unknown")

    def _add_domain_summary(self, normalized: Dict[str, Any]) -> None:
        """Add domain-specific summary information"""
        sources = normalized["sources"]

        # Registrar information
        if "whois" in sources:
            normalized["summary"]["registrar"] = sources["whois"].get("registrar", "Unknown")
            normalized["summary"]["creation_date"] = sources["whois"].get("creation_date", "Unknown")

    def _add_hash_summary(self, normalized: Dict[str, Any]) -> None:
        """Add hash-specific summary information"""
        sources = normalized["sources"]

        # Detection ratio from VirusTotal
        if "virustotal" in sources:
            normalized["summary"]["detection_ratio"] = sources["virustotal"].get("detection_ratio", "0/0")

    def _get_risk_level(self, risk_score: int) -> str:
        """Convert numeric risk score to categorical risk level"""
        if risk_score >= 80:
            return "critical"
        elif risk_score >= 60:
            return "high"
        elif risk_score >= 40:
            return "medium"
        elif risk_score >= 20:
            return "low"
        else:
            return "minimal"

    def _calculate_confidence(self, confidence_factors: List[str], source_count: int) -> str:
        """Calculate confidence level based on agreement between sources"""
        if len(confidence_factors) >= 3 and source_count >= 3:
            return "high"
        elif len(confidence_factors) >= 2 and source_count >= 2:
            return "medium"
        elif len(confidence_factors) >= 1:
            return "low"
        else:
            return "minimal"

    def _get_scoring_rules(self) -> Dict[str, Any]:
        """Get scoring rules configuration (placeholder for future config file)"""
        return {
            "ip": {
                "abuseipdb_high_threshold": 75,
                "abuseipdb_medium_threshold": 25
            },
            "domain": {
                "otx_high_pulse_threshold": 5
            },
            "hash": {
                "vt_high_detection_threshold": 0.5,
                "vt_medium_detection_threshold": 0.1
            }
        }