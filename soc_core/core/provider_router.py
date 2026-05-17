"""
ProviderRouter — Unified LLM provider management for SOCRoot.

Merges the responsibilities of the old LLMManager + LLMRouter into one canonical class.
Now integrated with APIKeyPool for automatic Round-Robin key rotation.

Usage:
    router = ProviderRouter()
    response = router.complete(TaskType.THREAT_ANALYSIS, prompt="Analyze this CVE...")
"""

import time
import logging
from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime
from dotenv import load_dotenv
from core.api_key_pool import get_pool, APIKeyPool

load_dotenv()
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Task Types — defines what kind of LLM work is being requested
# ─────────────────────────────────────────────────────────────
class TaskType(Enum):
    THREAT_ANALYSIS = "threat_analysis"
    REPORT_WRITING = "report_writing"
    TRANSLATION_AR = "translation_ar"
    FAST_CLASSIFICATION = "classification"
    GENERAL = "general"


# ─────────────────────────────────────────────────────────────
# Routing Table — canonical mapping of task → provider
# ─────────────────────────────────────────────────────────────
ROUTING_TABLE: Dict[TaskType, Dict[str, Any]] = {
    TaskType.THREAT_ANALYSIS: {
        "provider": "gemini",
        "model": "gemini-2.0-flash",
        "api_key_env": "GEMINI_API_KEY",
        "rpm_limit": 15,
        "reason": "Threat analysis — accurate and fast",
    },
    TaskType.REPORT_WRITING: {
        "provider": "gemini",
        "model": "gemini-2.0-flash",
        "api_key_env": "GEMINI_API_KEY",
        "rpm_limit": 15,
        "reason": "Cost-efficient, good quality for structured text",
    },
    TaskType.TRANSLATION_AR: {
        "provider": "gemini",
        "model": "gemini-2.0-flash",
        "api_key_env": "GEMINI_API_KEY",
        "rpm_limit": 15,
        "reason": "Arabic translation — Gemini performs well",
    },
    TaskType.FAST_CLASSIFICATION: {
        "provider": "gemini",
        "model": "gemini-2.0-flash-lite",
        "api_key_env": "GEMINI_API_KEY",
        "rpm_limit": 30,
        "reason": "Lightweight model for fast classification tasks",
    },
    TaskType.GENERAL: {
        "provider": "gemini",
        "model": "gemini-2.0-flash",
        "api_key_env": "GEMINI_API_KEY",
        "rpm_limit": 15,
        "reason": "Default fallback for unclassified tasks",
    },
}

# Fallback chain — tried in order when primary provider is unavailable
FALLBACK_MODELS = [
    {"model": "gemini-2.0-flash", "api_key_env": "GEMINI_API_KEY"},
    {"model": "gemini-2.0-flash-lite", "api_key_env": "GEMINI_API_KEY_2"},
    {"model": "gemini-1.5-flash", "api_key_env": "GEMINI_API_KEY_3"},
]


class ProviderRouter:
    """
    Single-class replacement for LLMManager + LLMRouter.
    Integrated with APIKeyPool for automatic Round-Robin key rotation.
    Reports rate limits back to the pool automatically.
    """

    def __init__(self, pool: Optional[APIKeyPool] = None):
        self._pool = pool or get_pool()
        self._client_cache: Dict[str, Any] = {}  # api_key → genai.Client
        self._active_key: Optional[str] = None
        self._call_count: int = 0
        self.last_health: Optional[Dict] = None
        self._genai = self._import_genai()

    def _import_genai(self):
        try:
            from google import genai
            return genai
        except ImportError:
            logger.warning("[ProviderRouter] google-genai not installed")
            return None

    def _get_client(self, api_key: str):
        """Get or create a Gemini client for the given key."""
        if not self._genai:
            return None
        if api_key not in self._client_cache:
            self._client_cache[api_key] = self._genai.Client(api_key=api_key)
        return self._client_cache[api_key]



    def get_config_for_task(self, task: TaskType) -> Dict[str, Any]:
        """Return the routing config for a given task type."""
        return ROUTING_TABLE.get(task, ROUTING_TABLE[TaskType.GENERAL])

    def complete(
        self,
        prompt: str,
        task: TaskType = TaskType.GENERAL,
        system_prompt: Optional[str] = None,
        max_retries: int = 3,
    ) -> str:
        """
        Generate a completion for the given prompt.
        Keys are sourced from APIKeyPool with automatic Round-Robin rotation.
        Rate limit errors are reported back to the pool automatically.
        """
        config = self.get_config_for_task(task)
        provider = config.get("provider", "gemini")
        contents = f"{system_prompt}\n\n---\n\n{prompt}" if system_prompt else prompt

        models_to_try = [config["model"]] + [
            f["model"] for f in FALLBACK_MODELS if f["model"] != config["model"]
        ]

        for model in models_to_try:
            for attempt in range(max_retries):
                api_key = self._pool.get_key(provider)
                if not api_key:
                    logger.error(f"[ProviderRouter] No keys available for '{provider}'")
                    return self._offline_response(prompt, task)

                client = self._get_client(api_key)
                if not client:
                    return self._offline_response(prompt, task)

                try:
                    resp = client.models.generate_content(model=model, contents=contents)
                    self._active_key = api_key
                    self._call_count += 1
                    logger.debug(f"[ProviderRouter] {task.value} → {model} ✓ (call #{self._call_count})")
                    return resp.text
                except Exception as e:
                    err_str = str(e).lower()
                    if "429" in err_str or "quota" in err_str or "rate" in err_str:
                        self._pool.report_rate_limit(provider, api_key)
                        logger.warning(f"[ProviderRouter] Rate limit on {model} — key rotated")
                        continue  # Try same model again with new key
                    else:
                        self._pool.report_error(provider, api_key)
                        wait = 2 ** attempt
                        logger.warning(f"[ProviderRouter] {model} attempt {attempt+1} error: {e}. Retry in {wait}s")
                        time.sleep(wait)
                        continue  # Try same model again after waiting

        logger.error("[ProviderRouter] All models and keys exhausted")
        return self._offline_response(prompt, task)

    def _offline_response(self, prompt: str, task: TaskType) -> str:
        return (
            f"[OFFLINE — {task.value}] LLM unavailable. "
            f"Manual analysis required for prompt: {prompt[:120]}..."
        )

    def health_check(self) -> Dict[str, Any]:
        """Non-destructive API health check. Includes pool status."""
        result: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "pool_status": self._pool.status(),
        }
        api_key = self._pool.get_key("gemini")
        if not api_key:
            result["status"] = "offline"
            result["reason"] = "No Gemini keys available"
            self.last_health = result
            return result

        client = self._get_client(api_key)
        if not client:
            result["status"] = "offline"
            result["reason"] = "google-genai not installed"
            self.last_health = result
            return result

        try:
            resp = client.models.generate_content(
                model="gemini-2.0-flash",
                contents="Reply with exactly: OK",
            )
            result["status"] = "healthy" if "OK" in (resp.text or "") else "degraded"
            result["model"] = "gemini-2.0-flash"
        except Exception as e:
            err_str = str(e).lower()
            if "429" in err_str or "quota" in err_str:
                self._pool.report_rate_limit("gemini", api_key)
            result["status"] = "error"
            result["error"] = str(e)

        self.last_health = result
        return result
