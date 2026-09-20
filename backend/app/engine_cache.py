from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Generic, TypeVar

T = TypeVar("T")

logger = logging.getLogger("netshield.backend")


class ReloadableCache(Generic[T]):
    """A lazily-loaded, process-local object that can be invalidated from *any* worker process.

    The plain module-level cache this replaces was per process, so with `uvicorn --workers N` a
    retrain that finished on worker A reloaded only A's model; B..N kept serving the old weights
    until restarted. Here, "reload needed" is a small shared *generation marker file*: invalidate()
    writes a fresh value into it, and every worker's get() compares that value with the one its
    cached object was loaded under, reloading when they differ. Reading a tiny file per call is
    far cheaper than the request it guards.

    The marker is deliberately NOT derived from the model files' own modification times: the
    retrain job overwrites artifacts/ in place while it trains and only decides afterwards (the
    quality gate) whether the result may go live, so an mtime watcher would hot-swap an
    unvetted, half-written model into every worker. The marker is written only once that
    decision has been made -- and it lives outside artifacts/, which the gate deletes and
    restores wholesale when it rejects a run.
    """

    def __init__(self, loader: Callable[[], T], marker_path: Callable[[], Path]):
        self._loader = loader
        self._marker_path = marker_path
        self._lock = threading.Lock()
        self._value: T | None = None
        self._loaded_generation: str | None = None
        self._loads = 0

    def _read_generation(self) -> str | None:
        try:
            return self._marker_path().read_text(encoding="utf-8").strip() or None
        except FileNotFoundError:
            return None
        except OSError:
            logger.exception("Could not read the model-generation marker; keeping the loaded model.")
            return self._loaded_generation

    def get(self) -> T:
        value = self._value
        if value is not None and self._read_generation() == self._loaded_generation:
            return value

        with self._lock:
            # Read the generation *before* loading: if another worker bumps it while this load is
            # in flight, the next get() sees a mismatch and reloads again (the safe direction).
            generation = self._read_generation()
            if self._value is None or generation != self._loaded_generation:
                reloading = self._loads > 0
                self._value = self._loader()
                self._loads += 1
                self._loaded_generation = generation
                logger.info(
                    "Model %s in process %d (generation %s).",
                    "reloaded after a retrain" if reloading else "loaded", os.getpid(), generation or "initial",
                )
            return self._value

    def invalidate(self) -> None:
        """Signal every worker (this one included) to reload on its next get()."""
        marker = self._marker_path()
        try:
            marker.parent.mkdir(parents=True, exist_ok=True)
            tmp = marker.with_name(marker.name + ".tmp")
            tmp.write_text(str(time.time_ns()), encoding="utf-8")
            os.replace(tmp, marker)  # atomic: a reader sees the old value or the new one, never half
        except OSError:
            # Still drop the local copy below, so a single-worker deployment keeps working exactly
            # as before even when the marker can't be written.
            logger.exception("Could not write the model-generation marker; other workers won't reload.")
        with self._lock:
            self._value = None
