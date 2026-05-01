import threading
import time
from functools import wraps
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    Thread-safe implementation of a simple rate limiter using a lock.
    Ensures that calls to the decorated function happen at least 'interval' seconds apart.
    """
    def __init__(self, calls_per_minute: int):
        self.interval = 60.0 / calls_per_minute
        self._lock = threading.Lock()
        self._last_called = 0.0

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with self._lock:
                elapsed = time.time() - self._last_called
                if elapsed < self.interval:
                    wait_time = self.interval - elapsed
                    logger.debug(f"[RateLimiter] Waiting {wait_time:.2f}s for next API call...")
                    time.sleep(wait_time)
                self._last_called = time.time()
            return func(*args, **kwargs)
        return wrapper
