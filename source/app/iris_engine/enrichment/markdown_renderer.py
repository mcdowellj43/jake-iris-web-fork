"""
Markdown Report Generator for IOC Enrichment
Generates formatted markdown reports from normalized enrichment data
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

log = logging.getLogger(__name__)


class MarkdownRenderer:
    """Generates markdown reports from enrichment data"""

    def __init__(self):
        self.risk_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🔵",
            "minimal": "⚪",
            "unknown": "⚫"
        }

        self.confidence_icons = {
            "high": "✅",
            "medium": "⚠️",
            "low": "❓",
            "minimal": "❌"
        }

    def render_enrichment_report(self, normalized_data: Dict[str, Any],
                                profile_name: str, artifact_ids: List[str] = None) -> str:
        """
        Generate a complete markdown report from normalized enrichment data

        Args:
            normalized_data: Output from EnrichmentNormalizer
            profile_name: Name of the enrichment profile used
            artifact_ids: List of artifact IDs for raw data storage

        Returns:
            Formatted markdown report
        """
        report_sections = []

        # Header section
        report_sections.append(self._render_header(normalized_data, profile_name))

        # Executive summary
        report_sections.append(self._render_summary(normalized_data))

        # Key findings
        report_sections.append(self._render_key_findings(normalized_data))

        # Source details (collapsible)
        report_sections.append(self._render_source_details(normalized_data))

        # Artifacts section (if any)
        if artifact_ids:
            report_sections.append(self._render_artifacts_section(artifact_ids))

        # Footer
        report_sections.append(self._render_footer(normalized_data))

        return "\n\n".join(report_sections)

    def _render_header(self, data: Dict[str, Any], profile_name: str) -> str:
        """Render report header with IOC info and metadata"""
        ioc = data["ioc"]
        summary = data["summary"]
        timestamp = data.get("timestamp", datetime.utcnow().isoformat())

        # Parse timestamp for display
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            time_str = dt.strftime("%Y-%m-%d %H:%M UTC")
        except:
            time_str = timestamp

        risk_icon = self.risk_icons.get(summary["risk_level"], "⚫")
        conf_icon = self.confidence_icons.get(summary["confidence"], "❓")

        return f"""# IOC Enrichment Report

**IOC**: `{ioc["value"]}` ({ioc["type"].upper()})
**Profile**: {profile_name}
**Timestamp**: {time_str}
**Risk Level**: {risk_icon} {summary["risk_level"].title()} ({summary["risk_score"]}/100)
**Confidence**: {conf_icon} {summary["confidence"].title()}

---"""

    def _render_summary(self, data: Dict[str, Any]) -> str:
        """Render executive summary section"""
        summary = data["summary"]
        metadata = data["metadata"]

        classifications_text = ""
        if summary.get("classifications"):
            classifications_text = f"**Classifications**: {', '.join(summary['classifications'])}\n"

        sources_text = f"**Sources Queried**: {len(metadata['sources_queried'])} " \
                      f"({len(metadata['sources_succeeded'])} successful, {len(metadata['sources_failed'])} failed)"

        # Add IOC-type specific summary
        ioc_specific = self._render_ioc_specific_summary(data)

        return f"""## 🎯 Executive Summary

{classifications_text}{sources_text}

{ioc_specific}"""

    def _render_ioc_specific_summary(self, data: Dict[str, Any]) -> str:
        """Render IOC type-specific summary information"""
        ioc_type = data["ioc"]["type"]
        summary = data["summary"]

        if ioc_type == "ip":
            geo = summary.get("geo", "Unknown")
            asn = summary.get("asn", "Unknown")
            isp = summary.get("isp", "Unknown")
            return f"**Location**: {geo} | **ASN**: {asn} | **ISP**: {isp}"

        elif ioc_type == "domain":
            registrar = summary.get("registrar", "Unknown")
            creation_date = summary.get("creation_date", "Unknown")
            return f"**Registrar**: {registrar} | **Created**: {creation_date}"

        elif ioc_type == "hash":
            detection_ratio = summary.get("detection_ratio", "0/0")
            return f"**Detection Ratio**: {detection_ratio}"

        return ""

    def _render_key_findings(self, data: Dict[str, Any]) -> str:
        """Render key findings from all sources"""
        findings = []
        sources = data["sources"]
        ioc_type = data["ioc"]["type"]

        # Extract key findings based on IOC type
        if ioc_type == "ip":
            findings.extend(self._extract_ip_findings(sources))
        elif ioc_type == "domain":
            findings.extend(self._extract_domain_findings(sources))
        elif ioc_type == "hash":
            findings.extend(self._extract_hash_findings(sources))

        if not findings:
            findings.append("ℹ️ No significant findings detected")

        findings_text = "\n".join([f"- {finding}" for finding in findings])

        return f"""## 🔍 Key Findings

{findings_text}"""

    def _extract_ip_findings(self, sources: Dict[str, Any]) -> List[str]:
        """Extract key findings for IP addresses"""
        findings = []

        # AbuseIPDB findings
        if "abuseipdb" in sources:
            abuse = sources["abuseipdb"]
            confidence = abuse.get("abuse_confidence", 0)
            if confidence > 75:
                findings.append(f"🚨 **High abuse confidence** ({confidence}%) reported by AbuseIPDB")
            elif confidence > 25:
                findings.append(f"⚠️ **Moderate abuse reports** ({confidence}%) on AbuseIPDB")

            if abuse.get("is_whitelisted"):
                findings.append("✅ **Whitelisted** on AbuseIPDB")

        # GreyNoise findings
        if "greynoise" in sources:
            gn = sources["greynoise"]
            classification = gn.get("classification", "").lower()
            if classification == "malicious":
                findings.append("🔴 **Classified as malicious** by GreyNoise")
            elif classification == "benign":
                findings.append("🟢 **Benign scanner activity** detected by GreyNoise")

        # Talos findings
        if "talos" in sources:
            talos = sources["talos"]
            web_rep = talos.get("web_reputation", "").lower()
            if "poor" in web_rep or "malicious" in web_rep:
                findings.append(f"⚠️ **Poor reputation** ({web_rep}) from Cisco Talos")

        return findings

    def _extract_domain_findings(self, sources: Dict[str, Any]) -> List[str]:
        """Extract key findings for domains"""
        findings = []

        # OTX findings
        if "otx" in sources:
            otx = sources["otx"]
            pulse_count = otx.get("pulse_count", 0)
            if pulse_count > 5:
                findings.append(f"🚨 **Multiple threat pulses** ({pulse_count}) in AlienVault OTX")
            elif pulse_count > 0:
                findings.append(f"⚠️ **Threat intelligence hits** ({pulse_count}) in OTX")

        # URLhaus findings
        if "urlhaus" in sources:
            urlhaus = sources["urlhaus"]
            threat = urlhaus.get("threat", "").lower()
            if "malware" in threat:
                findings.append("🔴 **Associated with malware** in URLhaus database")

        return findings

    def _extract_hash_findings(self, sources: Dict[str, Any]) -> List[str]:
        """Extract key findings for hashes"""
        findings = []

        # VirusTotal findings
        if "virustotal" in sources:
            vt = sources["virustotal"]
            positives = vt.get("positives", 0)
            total = vt.get("total", 1)

            if positives > 0:
                detection_rate = positives / total if total > 0 else 0
                if detection_rate > 0.5:
                    findings.append(f"🔴 **High detection rate** ({positives}/{total}) on VirusTotal")
                elif detection_rate > 0.1:
                    findings.append(f"🟠 **Moderate detection** ({positives}/{total}) on VirusTotal")
                else:
                    findings.append(f"🟡 **Low-level detection** ({positives}/{total}) on VirusTotal")

        # Malware family findings
        if "malwarebazaar" in sources:
            mb = sources["malwarebazaar"]
            family = mb.get("malware_family", "")
            if family and family != "Unknown":
                findings.append(f"🦠 **Known malware family**: {family}")

        return findings

    def _render_source_details(self, data: Dict[str, Any]) -> str:
        """Render detailed source information in collapsible sections"""
        sources = data["sources"]
        errors = data["errors"]

        details_sections = []

        # Successful sources
        for source_name, source_data in sources.items():
            details_sections.append(self._render_source_section(source_name, source_data))

        # Failed sources
        if errors:
            error_items = []
            for source_name, error_msg in errors.items():
                error_items.append(f"- **{source_name}**: {error_msg}")

            error_section = f"""<details>
<summary>❌ Failed Sources ({len(errors)})</summary>

{chr(10).join(error_items)}

</details>"""
            details_sections.append(error_section)

        return f"""## 📊 Source Details

{chr(10).join(details_sections)}"""

    def _render_source_section(self, source_name: str, source_data: Dict[str, Any]) -> str:
        """Render a single source's data in a collapsible section"""
        # Create a summary line for the source
        summary_line = self._create_source_summary(source_name, source_data)

        # Format the detailed data
        details = []
        for key, value in source_data.items():
            if key.startswith('_'):
                continue  # Skip metadata

            if isinstance(value, (list, dict)):
                # Handle complex data types
                if isinstance(value, list) and value:
                    details.append(f"**{key.title()}**: {len(value)} items")
                elif isinstance(value, dict) and value:
                    details.append(f"**{key.title()}**: {len(value)} entries")
            else:
                details.append(f"**{key.title()}**: {value}")

        details_text = "\n".join([f"- {detail}" for detail in details]) if details else "No detailed data available"

        return f"""<details>
<summary>🔍 {source_name.title()} - {summary_line}</summary>

{details_text}

</details>"""

    def _create_source_summary(self, source_name: str, source_data: Dict[str, Any]) -> str:
        """Create a one-line summary for a source"""
        if source_name == "abuseipdb":
            confidence = source_data.get("abuse_confidence", 0)
            return f"{confidence}% abuse confidence"
        elif source_name == "greynoise":
            classification = source_data.get("classification", "Unknown")
            return f"Classification: {classification}"
        elif source_name == "virustotal":
            ratio = source_data.get("detection_ratio", "0/0")
            return f"Detection: {ratio}"
        elif source_name == "talos":
            web_rep = source_data.get("web_reputation", "Unknown")
            return f"Reputation: {web_rep}"
        else:
            return "Data collected"

    def _render_artifacts_section(self, artifact_ids: List[str]) -> str:
        """Render artifacts section with links to raw data"""
        if not artifact_ids:
            return ""

        artifact_links = []
        for artifact_id in artifact_ids:
            artifact_links.append(f"- [Artifact {artifact_id}](#artifact-{artifact_id})")

        return f"""## 📎 Raw Data Artifacts

The following artifacts contain the complete raw response data from each source:

{chr(10).join(artifact_links)}"""

    def _render_footer(self, data: Dict[str, Any]) -> str:
        """Render report footer with metadata"""
        metadata = data["metadata"]

        return f"""---

*Report generated by IRIS IOC Enrichment Engine*
*Sources: {', '.join(metadata['sources_succeeded'])}*
*Timestamp: {data.get('timestamp', 'Unknown')}*"""

    def render_update_block(self, normalized_data: Dict[str, Any], profile_name: str) -> str:
        """
        Render a shorter update block for appending to existing notes

        Args:
            normalized_data: Normalized enrichment data
            profile_name: Profile name used

        Returns:
            Markdown block for updates
        """
        ioc = normalized_data["ioc"]
        summary = normalized_data["summary"]
        timestamp = normalized_data.get("timestamp", datetime.utcnow().isoformat())

        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            time_str = dt.strftime("%Y-%m-%d %H:%M UTC")
        except:
            time_str = timestamp

        risk_icon = self.risk_icons.get(summary["risk_level"], "⚫")

        # Extract key changes/updates
        key_findings = []
        if summary.get("classifications"):
            key_findings.append(f"Classifications: {', '.join(summary['classifications'])}")

        findings_text = " | ".join(key_findings) if key_findings else "No significant changes"

        return f"""## 🔄 Update - {time_str}

**Profile**: {profile_name} | **Risk**: {risk_icon} {summary["risk_level"].title()} ({summary["risk_score"]}/100)

{findings_text}

---"""