import logging
import os
import json
from typing import Dict, Any

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

logger = logging.getLogger(__name__)

class LLMManager:
    """
    Manages interactions with LLM APIs (Gemini, OpenAI, Claude).
    Using Gemini-1.5-flash/pro as primary via google.generativeai,
    with a graceful mock fallback.
    """
    def __init__(self, provider="gemini"):
        self.provider = provider
        
        # Load environment variables. In a full system we'd use dotenv, 
        # but here we rely on the OS environment if loaded, or read directly.
        from dotenv import load_dotenv
        load_dotenv()
        
        self.api_key = os.getenv("GEMINI_API_KEY")
        
        if self.api_key and self.api_key != "your_gemini_key_here" and GENAI_AVAILABLE:
            genai.configure(api_key=self.api_key)
            # Use gemini-1.5-flash as default for fast, cost-effective triage
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            self.live_mode = True
        else:
            self.live_mode = False

    def analyze_scan(self, scan_json: Dict[str, Any], client_context: str) -> str:
        """
        Takes standardized JSON and RAG Context to produce an intelligent Triage Report.
        """
        logger.info(f"[LLMManager] Analyzing scan... (Live Mode: {self.live_mode})")
        
        if self.live_mode:
            try:
                prompt = f"""
You are an expert Security Operations Center (SOC) AI Analyst. Your job is to triage the following automated network scan results against the specific infrastructure context of the client.
Identify any false positives based on the context. If something is expected, explain why.

Client Context (RAG Data):
{client_context}

Scan Results (JSON Format):
{json.dumps(scan_json, indent=2)}

Please provide a highly professional, concise Triage Verdict.
"""
                response = self.model.generate_content(prompt)
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
