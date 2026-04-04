import logging
import os
import json
from typing import Dict, Any
from dotenv import load_dotenv
from core.rate_limiter import RateLimiter

load_dotenv()
_limiter = RateLimiter(calls_per_minute=int(os.getenv("GEMINI_RPM_LIMIT", "15")))

try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

logger = logging.getLogger(__name__)

class LLMManager:
    """
    Manages interactions with LLM APIs (Gemini, OpenAI, Claude).
    Using Gemini-1.5-flash parameter as primary via modern google.genai,
    with a graceful mock fallback.
    """
    def __init__(self, provider="gemini"):
        self.provider = provider
        load_dotenv()
        
        self.api_key = os.getenv("GEMINI_API_KEY")
        
        if self.api_key and self.api_key != "your_gemini_key_here" and GENAI_AVAILABLE:
            self.client = genai.Client(api_key=self.api_key)
            self.model_name = 'gemini-2.5-flash'
            self.live_mode = True
        else:
            self.live_mode = False

    @_limiter
    def analyze_scan(self, scan_json: Dict[str, Any], client_context: str) -> str:
        """
        Takes standardized JSON and RAG Context to produce an intelligent Triage Report.
        """
        logger.info(f"[LLMManager] Analyzing scan... (Live Mode: {self.live_mode})")
        
        if self.live_mode:
            try:
                prompt = f"""
You are a hostile security reviewer, not a compliance checker.
Your job is to assume a threat actor perspective.

Rules:
1. An open port is NOT automatically safe because it's "expected".
   Expected ≠ Hardened.
2. For each service found, you MUST evaluate:
   - Is the version exposed? (Version disclosure risk)
   - Is the protocol unencrypted? (Port 80 = cleartext HTTP = data interception risk)
   - Is the port on its default number? (Port 22 default = higher exposure to automated attacks)
3. Compliance context (NCA, ISO 27001) should be used to GENERATE findings,
   not to DISMISS them.
4. Output format: findings ONLY. No "everything is fine" verdicts.
   If there are no critical findings, explicitly state LOW risk with justification.
5. HTTP Redirect Context: Port 80 open does NOT automatically mean cleartext_http risk
   if the target is behind a CDN (Cloudflare, Akamai, Fastly, CloudFront).
   CDN providers use port 80 exclusively for HTTP→HTTPS redirect (301/302).
   Check: if target resolves to a known CDN IP range, downgrade port 80 from
   Critical to Low with note: 'CDN redirect pattern - verify HTTPS enforcement'.
6. Subdomain Attack Surface: If subdomains were discovered, list the top 5
   most interesting ones (admin., api., dev., staging., vpn.) as Medium findings
   requiring investigation.

Client Context (RAG Data):
{client_context}

Scan Results (JSON Format):
{json.dumps(scan_json, indent=2)}
                """
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                )
                return response.text
            except Exception as e:
                logger.error(f"[LLMManager] Exception calling Gemini API: {e}. Falling back to MOCK.")
        
        # Fallback Mock Logic
        targets = scan_json.get("targets", [])
        ip = targets[0].get("ip", "Unknown") if targets else "Unknown"
        ports = len(targets[0].get("open_ports", [])) if targets else 0
        
        has_nginx = "Nginx" in client_context if client_context else False
        
        report = f"""
💡 [MOCK RAG ANALYSIS REPORT]
Target Investigated: {ip}
Open Ports Detected: {ports}

Context Applied:
- Expected Web Server: {'Nginx (matches finding)' if has_nginx else 'Unknown'}

Triage Verdict:
No critical anomalies detected based on the provided context. (Mock Fallback triggered due to missing API key or error. Open ports align with standard basic operations).
"""
        return report.strip()
