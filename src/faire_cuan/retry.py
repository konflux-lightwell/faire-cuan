from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


def retry(
    fn: Callable[[], T],
    *,
    attempts: int = 3,
    delay: float = 5.0,
    backoff: float = 2.0,
) -> T:
    last_exc: Exception | None = None
    current_delay = delay

    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if attempt < attempts:
                logger.warning("Attempt %d/%d failed, retrying in %.0fs...", attempt, attempts, current_delay)
                time.sleep(current_delay)
                current_delay *= backoff

    raise last_exc  # type: ignore[misc]
