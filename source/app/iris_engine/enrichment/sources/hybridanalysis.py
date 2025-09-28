"""
Hybrid Analysis Enrichment Source
Provides malware analysis data from Falcon Sandbox / Hybrid Analysis
"""

import requests
import logging
from typing import Dict, Any
from .base import EnrichmentSourceBase

log = logging.getLogger(__name__)


class HybridAnalysis(EnrichmentSourceBase):
    """Hybrid Analysis malware sandbox source"""

    name = "hybridanalysis"
    ioc_support = {"hash"}
    base_url = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self):
        super().__init__()
        # Hybrid Analysis API key should be configured via environment
        self.api_key = self._get_api_key("HYBRID_ANALYSIS_API_KEY")
        self.headers = {
            'api-key': self.api_key if self.api_key else '',
            'User-Agent': 'IRIS-IOC-Enrichment/1.0',
            'Content-Type': 'application/x-www-form-urlencoded'
        }

    def fetch(self, ioc_type: str, ioc_value: str, timeout_s: int = 8) -> Dict[str, Any]:
        """
        Fetch malware analysis data from Hybrid Analysis

        Args:
            ioc_type: Type of IOC (should be 'hash')
            ioc_value: Hash to lookup (MD5, SHA1, or SHA256)
            timeout_s: Request timeout in seconds

        Returns:
            Dict containing analysis data or error information
        """
        if ioc_type != "hash":
            return {"_error": f"Hybrid Analysis source only supports hashes, not {ioc_type}"}

        if not self.api_key:
            return {"_error": "Hybrid Analysis API key not configured"}

        try:
            # First, search for the hash
            search_endpoint = f"{self.base_url}/search/hash"
            search_data = {'hash': ioc_value}

            response = requests.post(
                search_endpoint,
                data=search_data,
                headers=self.headers,
                timeout=timeout_s
            )

            if response.status_code == 200:
                search_results = response.json()

                if not search_results:
                    return {
                        'hash': ioc_value,
                        'found': False,
                        'submissions': [],
                        '_source': self.name,
                        '_timestamp': self._get_timestamp(),
                        '_raw_response': search_results
                    }

                # Process the first few results
                submissions = search_results[:3]  # Limit to 3 submissions
                processed_submissions = []

                for submission in submissions:
                    job_id = submission.get('job_id')
                    if job_id:
                        # Get detailed report for each submission
                        report_data = self._get_detailed_report(job_id, timeout_s)
                        if report_data:
                            processed_submissions.append({
                                'job_id': job_id,
                                'environment_id': submission.get('environment_id'),
                                'environment_description': submission.get('environment_description'),
                                'submit_name': submission.get('submit_name'),
                                'verdict': submission.get('verdict'),
                                'threat_score': submission.get('threat_score'),
                                'analysis_start_time': submission.get('analysis_start_time'),
                                'size': submission.get('size'),
                                'type': submission.get('type'),
                                'detailed_report': report_data
                            })

                # Calculate overall verdict
                verdicts = [sub.get('verdict') for sub in submissions if sub.get('verdict')]
                threat_scores = [sub.get('threat_score') for sub in submissions if sub.get('threat_score')]

                normalized_data = {
                    'hash': ioc_value,
                    'found': True,
                    'submission_count': len(search_results),
                    'submissions': processed_submissions,
                    'overall_verdict': self._calculate_overall_verdict(verdicts),
                    'max_threat_score': max(threat_scores) if threat_scores else 0,
                    'avg_threat_score': sum(threat_scores) / len(threat_scores) if threat_scores else 0,
                    'file_types': list(set([sub.get('type') for sub in submissions if sub.get('type')])),
                    '_source': self.name,
                    '_timestamp': self._get_timestamp(),
                    '_raw_response': search_results[:5]  # Store first 5 for space
                }

                log.info(f"Successfully fetched Hybrid Analysis data for {ioc_value}")
                return normalized_data

            elif response.status_code == 403:
                return {"_error": "Hybrid Analysis API access forbidden - check API key"}
            elif response.status_code == 429:
                return {"_error": "Hybrid Analysis API rate limit exceeded"}
            else:
                return self._handle_request_error(response, "Hybrid Analysis")

        except requests.exceptions.Timeout:
            return {"_error": f"Hybrid Analysis request timeout after {timeout_s} seconds"}
        except requests.exceptions.RequestException as e:
            return {"_error": f"Hybrid Analysis request failed: {str(e)}"}
        except Exception as e:
            log.error(f"Unexpected error in Hybrid Analysis lookup for {ioc_value}: {str(e)}")
            return {"_error": f"Unexpected error: {str(e)}"}

    def _get_detailed_report(self, job_id: str, timeout_s: int) -> Dict[str, Any]:
        """Get detailed analysis report for a job"""
        try:
            report_endpoint = f"{self.base_url}/report/{job_id}/summary"

            response = requests.get(
                report_endpoint,
                headers=self.headers,
                timeout=timeout_s
            )

            if response.status_code == 200:
                return response.json()
            else:
                log.warning(f"Failed to get detailed report for job {job_id}: {response.status_code}")
                return None

        except Exception as e:
            log.warning(f"Error getting detailed report for job {job_id}: {str(e)}")
            return None

    def _calculate_overall_verdict(self, verdicts: list) -> str:
        """Calculate overall verdict from multiple submissions"""
        if not verdicts:
            return "unknown"

        verdict_priority = {
            'malicious': 4,
            'suspicious': 3,
            'whitelisted': 1,
            'no specific threat': 2
        }

        # Return the highest priority verdict
        max_priority = 0
        overall_verdict = "unknown"

        for verdict in verdicts:
            priority = verdict_priority.get(verdict.lower(), 0)
            if priority > max_priority:
                max_priority = priority
                overall_verdict = verdict

        return overall_verdict

    def get_reputation_score(self, data: Dict[str, Any]) -> int:
        """
        Calculate reputation score based on Hybrid Analysis data

        Args:
            data: Normalized Hybrid Analysis data

        Returns:
            Risk score (0-100, higher = more suspicious)
        """
        if "_error" in data:
            return 0

        if not data.get('found', False):
            return 0

        # Use max threat score as primary indicator
        max_threat_score = data.get('max_threat_score', 0)
        if max_threat_score >= 70:
            return 90
        elif max_threat_score >= 50:
            return 75
        elif max_threat_score >= 30:
            return 60
        elif max_threat_score > 0:
            return 40

        # Also consider verdict
        overall_verdict = data.get('overall_verdict', '').lower()
        if overall_verdict == 'malicious':
            return max(85, max_threat_score)
        elif overall_verdict == 'suspicious':
            return max(60, max_threat_score)
        elif overall_verdict == 'whitelisted':
            return 5

        return max_threat_score

    def _get_api_key(self, env_var: str) -> str:
        """Get API key from environment or return empty string"""
        import os
        return os.getenv(env_var, "")