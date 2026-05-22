"""
Ollama API client for AI-powered log analysis.
Sends structured anomaly summaries and receives threat assessments.
"""

import json
import logging
import urllib.error
import urllib.request
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1:8b"
REQUEST_TIMEOUT = 120  # seconds


class OllamaClient:
    """Thin wrapper around the Ollama REST API."""

    def __init__(self, base_url: str = DEFAULT_BASE_URL, model: str = DEFAULT_MODEL) -> None:
        """
        Initialize client.

        Args:
            base_url: Ollama server URL.
            model: Model name to use for generation.
        """
        self.base_url = base_url.rstrip("/")
        self.model = model

    def _post(self, endpoint: str, payload: dict) -> dict:
        """
        Make a POST request to the Ollama API.

        Raises:
            RuntimeError: On network error or non-200 response.
        """
        url = f"{self.base_url}{endpoint}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body)
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

    def is_available(self) -> bool:
        """Return True if the Ollama server is reachable."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5):
                return True
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return list of available model names on the server."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        """
        Generate a completion from the model.

        Args:
            prompt: User prompt text.
            system: Optional system instruction.

        Returns:
            Model response text.
        """
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system

        response = self._post("/api/generate", payload)
        return response.get("response", "").strip()

    def analyze_anomalies(self, anomaly_summary: str, log_sample: str) -> str:
        """
        Ask the model to analyze detected anomalies and provide a threat assessment.

        Args:
            anomaly_summary: Structured text summary of rule-based anomaly findings.
            log_sample: Representative raw log lines for context.

        Returns:
            AI-generated threat assessment and recommendations.
        """
        system = (
            "You are an expert Linux security analyst specializing in log forensics "
            "and intrusion detection. Analyze the provided auth log anomalies and "
            "produce a concise threat assessment. Be factual and specific. "
            "Format your response with these sections:\n"
            "1. THREAT ASSESSMENT (overall risk: CRITICAL/HIGH/MEDIUM/LOW)\n"
            "2. KEY FINDINGS (bullet points)\n"
            "3. ATTACK PATTERN ANALYSIS\n"
            "4. IMMEDIATE RECOMMENDATIONS\n"
            "5. INDICATORS OF COMPROMISE (IPs, usernames, patterns to block)"
        )

        prompt = (
            f"## Detected Anomalies\n\n{anomaly_summary}\n\n"
            f"## Sample Log Lines\n\n{log_sample}\n\n"
            "Provide your threat assessment."
        )

        return self.generate(prompt, system=system)

    def enrich_finding(self, anomaly_title: str, anomaly_description: str) -> str:
        """
        Get AI enrichment for a single anomaly finding.

        Args:
            anomaly_title: Short title of the anomaly.
            anomaly_description: Description with counts and context.

        Returns:
            AI-generated explanation, risk context, and recommended action.
        """
        system = (
            "You are a Linux security analyst. Given a single security finding from "
            "auth logs, provide: (1) a 1-sentence risk explanation, "
            "(2) most likely attack scenario, (3) one specific mitigation command or config change."
        )

        prompt = (
            f"Finding: {anomaly_title}\n"
            f"Details: {anomaly_description}\n\n"
            "Analyze this finding."
        )

        return self.generate(prompt, system=system)
