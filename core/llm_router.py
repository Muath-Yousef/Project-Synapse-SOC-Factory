from enum import Enum
import os
from typing import Dict, Any, Optional

class TaskType(Enum):
    THREAT_ANALYSIS = "threat_analysis"
    REPORT_WRITING = "report_writing"
    TRANSLATION_AR = "translation_ar"
    FAST_CLASSIFICATION = "classification"

PRODUCTION_ROUTING_TABLE = {
    TaskType.THREAT_ANALYSIS: {
        "provider": "claude",
        "model": "claude-sonnet-4-5",
        "api_key_env": "ANTHROPIC_API_KEY",
        "rpm_limit": 50,
        "reason": "Critical threat analysis — Claude Sonnet for accuracy",
        "trigger": "Phase 7 — Claude API budget allocated",
    },
    TaskType.REPORT_WRITING: {
        "provider": "gemini",
        "model": "gemini-2.0-flash",
        "api_key_env": "GEMINI_API_KEY",
        "rpm_limit": 15,
        "reason": "Keep on Gemini — cost efficient, good quality",
    },
    TaskType.TRANSLATION_AR: {
        "provider": "deepseek",
        "model": "deepseek-chat",
        "api_key_env": "DEEPSEEK_API_KEY",
        "rpm_limit": 60,
        "reason": "Free 1M tokens, best Arabic quality",
    },
}

class LLMRouter:
    @staticmethod
    def get_llm_for_task(task: TaskType) -> Dict[str, Any]:
        """Return the best model configuration for the given task."""
        config = PRODUCTION_ROUTING_TABLE.get(task)
        if not config:
            return {
                "provider": "gemini",
                "model": "gemini-2.0-flash",
                "api_key_env": "GEMINI_API_KEY",
            }
        
        # Check if API key for preferred provider exists, else fallback to Gemini
        api_key = os.getenv(config["api_key_env"])
        if not api_key:
            return {
                "provider": "gemini",
                "model": "gemini-2.0-flash",
                "api_key_env": "GEMINI_API_KEY",
            }
            
        return config
