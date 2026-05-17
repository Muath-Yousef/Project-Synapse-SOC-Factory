"""
APIKeyPool — Centralized API key rotation and quota tracking for SOCRoot Node 1.0.

Solves BUG-03: The system was using a single API key per provider until exhaustion.
This module implements:
  - Round-Robin rotation across all available keys per provider
  - Per-key quota/rate tracking (RPM and daily call counts)
  - Automatic cooldown scheduling when a key is rate-limited
  - Status reporting for the scheduler dashboard

Supported providers: gemini, groq, openrouter, openai
Keys are loaded from environment variables (.shared-secrets.env pattern).

Usage:
    pool = APIKeyPool()
    key = pool.get_key("gemini")       # Gets the best available key
    pool.report_rate_limit("gemini", key)  # Mark key as rate-limited
    print(pool.status())               # Show current key health
"""

import os
import time
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Key Health Tracking
# ─────────────────────────────────────────────────────────────
@dataclass
class KeyState:
    key: str
    env_var: str
    provider: str
    call_count: int = 0
    error_count: int = 0
    rate_limited_until: float = 0.0   # Unix timestamp — 0 means available
    last_used: float = 0.0
    daily_calls: int = 0
    daily_reset_at: str = ""

    @property
    def is_available(self) -> bool:
        """True if this key can be used right now."""
        return time.monotonic() > self.rate_limited_until

    @property
    def cooldown_remaining(self) -> float:
        """Seconds until this key is available again. 0 if already available."""
        remaining = self.rate_limited_until - time.monotonic()
        return max(0.0, remaining)

    def to_dict(self) -> dict:
        return {
            "env_var": self.env_var,
            "provider": self.provider,
            "available": self.is_available,
            "call_count": self.call_count,
            "error_count": self.error_count,
            "daily_calls": self.daily_calls,
            "cooldown_remaining_sec": round(self.cooldown_remaining, 1),
            "last_used": datetime.fromtimestamp(self.last_used, tz=timezone.utc).isoformat()
            if self.last_used > 0 else None,
        }


# ─────────────────────────────────────────────────────────────
# Provider Definitions — env var patterns per provider
# ─────────────────────────────────────────────────────────────
PROVIDER_KEY_PATTERNS: Dict[str, List[str]] = {
    "gemini": [
        "GEMINI_API_KEY",
        *[f"GEMINI_API_KEY_{i}" for i in range(2, 9)],
    ],
    "groq": [
        "GROQ_API_KEY",
        *[f"GROQ_API_KEY_{i}" for i in range(2, 9)],
    ],
    "openrouter": [
        "OPENROUTER_API_KEY",
        *[f"OPENROUTER_API_KEY_{i}" for i in range(2, 4)],
    ],
    "openai": [
        "OPENAI_API_KEY",
    ],
}

# Default cooldown durations per provider (seconds)
PROVIDER_COOLDOWNS: Dict[str, float] = {
    "gemini": 60.0,       # Gemini free tier: 60s cooldown per key
    "groq": 60.0,         # Groq: 60s cooldown on rate limit
    "openrouter": 30.0,   # OpenRouter: shorter cooldown
    "openai": 60.0,
}


class APIKeyPool:
    """
    Central manager for all API keys across all LLM providers.
    Implements Round-Robin with health-aware rotation and automatic cooldown.
    """

    def __init__(self):
        # provider → list of KeyState
        self._pools: Dict[str, List[KeyState]] = {}
        # Round-Robin pointer per provider
        self._rr_index: Dict[str, int] = {}
        self._load_keys()

    def _load_keys(self):
        """Discover and load all available API keys from environment."""
        for provider, env_vars in PROVIDER_KEY_PATTERNS.items():
            keys: List[KeyState] = []
            for env_var in env_vars:
                value = os.getenv(env_var, "").strip()
                if value and value not in ("your_key_here", ""):
                    keys.append(KeyState(
                        key=value,
                        env_var=env_var,
                        provider=provider,
                    ))

            if keys:
                self._pools[provider] = keys
                self._rr_index[provider] = 0
                logger.info(f"[APIKeyPool] Loaded {len(keys)} key(s) for '{provider}'")
            else:
                logger.warning(f"[APIKeyPool] No keys found for provider '{provider}'")

    def get_key(self, provider: str) -> Optional[str]:
        """
        Return the next available API key for the given provider.
        Uses Round-Robin rotation, skipping keys on cooldown.
        Returns None if all keys are rate-limited.
        """
        pool = self._pools.get(provider)
        if not pool:
            logger.error(f"[APIKeyPool] No keys configured for '{provider}'")
            return None

        n = len(pool)
        start = self._rr_index.get(provider, 0)

        for i in range(n):
            idx = (start + i) % n
            key_state = pool[idx]
            if key_state.is_available:
                # Advance the Round-Robin pointer
                self._rr_index[provider] = (idx + 1) % n
                key_state.call_count += 1
                key_state.daily_calls += 1
                key_state.last_used = time.monotonic()
                logger.debug(
                    f"[APIKeyPool] '{provider}' → {key_state.env_var} "
                    f"(call #{key_state.call_count})"
                )
                return key_state.key

        # All keys rate-limited — find the one that recovers soonest
        soonest = min(pool, key=lambda k: k.rate_limited_until)
        wait = soonest.cooldown_remaining
        logger.warning(
            f"[APIKeyPool] All '{provider}' keys rate-limited. "
            f"Soonest recovery: {soonest.env_var} in {wait:.1f}s"
        )
        return None

    def get_key_with_wait(self, provider: str, max_wait: float = 120.0) -> Optional[str]:
        """
        Like get_key() but waits (up to max_wait seconds) for a key to become available.
        Useful for critical tasks that must not fail.
        """
        pool = self._pools.get(provider)
        if not pool:
            return None

        start_wait = time.monotonic()
        while time.monotonic() - start_wait < max_wait:
            key = self.get_key(provider)
            if key:
                return key
            soonest = min(pool, key=lambda k: k.rate_limited_until)
            sleep_time = min(soonest.cooldown_remaining, 5.0)
            logger.info(f"[APIKeyPool] Waiting {sleep_time:.1f}s for '{provider}' key to recover...")
            time.sleep(sleep_time)

        logger.error(f"[APIKeyPool] Max wait ({max_wait}s) exceeded for '{provider}' — giving up")
        return None

    def report_rate_limit(
        self,
        provider: str,
        key: str,
        cooldown_seconds: Optional[float] = None,
    ):
        """
        Mark a key as rate-limited. Call this when you receive a 429 error.
        The key will be skipped for 'cooldown_seconds' before being retried.
        """
        pool = self._pools.get(provider, [])
        cooldown = cooldown_seconds or PROVIDER_COOLDOWNS.get(provider, 60.0)

        for key_state in pool:
            if key_state.key == key:
                key_state.rate_limited_until = time.monotonic() + cooldown
                key_state.error_count += 1
                logger.warning(
                    f"[APIKeyPool] '{provider}' key {key_state.env_var} rate-limited. "
                    f"Cooldown: {cooldown}s (until {datetime.now(timezone.utc).isoformat()}+{cooldown}s)"
                )
                return

        logger.error(f"[APIKeyPool] report_rate_limit: key not found in '{provider}' pool")

    def report_error(self, provider: str, key: str):
        """
        Mark a key as having encountered a non-rate-limit error.
        Increments error count; applies a short back-off.
        """
        pool = self._pools.get(provider, [])
        for key_state in pool:
            if key_state.key == key:
                key_state.error_count += 1
                # Short back-off for transient errors
                backoff = min(key_state.error_count * 5.0, 30.0)
                key_state.rate_limited_until = time.monotonic() + backoff
                logger.warning(
                    f"[APIKeyPool] '{provider}' key {key_state.env_var} errored "
                    f"(count={key_state.error_count}). Back-off: {backoff}s"
                )
                return

    def provider_status(self, provider: str) -> Dict:
        """Return health status of all keys for a given provider."""
        pool = self._pools.get(provider, [])
        available_count = sum(1 for k in pool if k.is_available)
        return {
            "provider": provider,
            "total_keys": len(pool),
            "available_keys": available_count,
            "rate_limited_keys": len(pool) - available_count,
            "keys": [k.to_dict() for k in pool],
        }

    def status(self) -> Dict:
        """Return health status of all providers and keys."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "providers": {
                provider: self.provider_status(provider)
                for provider in self._pools
            },
        }

    def reset_daily_counters(self):
        """Reset daily call counters. Call this at midnight or via a scheduler."""
        for pool in self._pools.values():
            for key_state in pool:
                key_state.daily_calls = 0
                key_state.daily_reset_at = datetime.now(timezone.utc).isoformat()
        logger.info("[APIKeyPool] Daily call counters reset.")

    def available_providers(self) -> List[str]:
        """Return list of providers that have at least one available key."""
        return [
            provider
            for provider, pool in self._pools.items()
            if any(k.is_available for k in pool)
        ]


# ─────────────────────────────────────────────────────────────
# Singleton accessor — one pool instance across the whole process
# ─────────────────────────────────────────────────────────────
_global_pool: Optional[APIKeyPool] = None


def get_pool() -> APIKeyPool:
    """Return the global APIKeyPool singleton, creating it if needed."""
    global _global_pool
    if _global_pool is None:
        _global_pool = APIKeyPool()
    return _global_pool
