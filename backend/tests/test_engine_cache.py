"""4.4 -- a model reload signalled by one worker process reaches every other worker."""
from __future__ import annotations

import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

from app.engine_cache import ReloadableCache

BACKEND_DIR = str(Path(__file__).resolve().parents[1])


def _cache(marker: Path):
    builds = []

    def loader():
        builds.append(1)
        return object()

    return ReloadableCache(loader, lambda: marker), builds


def test_loads_once_then_serves_the_cached_object(tmp_path):
    cache, builds = _cache(tmp_path / "gen")
    first = cache.get()
    assert cache.get() is first and len(builds) == 1


def test_invalidate_makes_the_next_get_reload(tmp_path):
    cache, builds = _cache(tmp_path / "gen")
    first = cache.get()
    cache.invalidate()
    second = cache.get()
    assert second is not first and len(builds) == 2
    assert cache.get() is second and len(builds) == 2  # and only once per invalidation


def test_a_second_cache_sharing_the_marker_reloads_when_the_first_invalidates(tmp_path):
    """Two ReloadableCache objects stand in for two workers: only the marker file connects them."""
    marker = tmp_path / "gen"
    worker_a, builds_a = _cache(marker)
    worker_b, builds_b = _cache(marker)
    a_old, b_old = worker_a.get(), worker_b.get()

    worker_a.invalidate()  # e.g. the retrain thread running inside worker A finished and was accepted

    assert worker_b.get() is not b_old and len(builds_b) == 2
    assert worker_a.get() is not a_old and len(builds_a) == 2
    worker_b.get(); worker_a.get()
    assert (len(builds_a), len(builds_b)) == (2, 2)  # no reload storm afterwards


def test_no_marker_file_is_fine(tmp_path):
    cache, builds = _cache(tmp_path / "does" / "not" / "exist")
    cache.get(); cache.get()
    assert len(builds) == 1


def test_concurrent_first_requests_build_the_model_once(tmp_path):
    builds = []

    def slow_loader():
        time.sleep(0.2)
        builds.append(1)
        return object()

    cache = ReloadableCache(slow_loader, lambda: tmp_path / "gen")
    results = []
    threads = [threading.Thread(target=lambda: results.append(cache.get())) for _ in range(8)]
    [t.start() for t in threads]; [t.join() for t in threads]
    assert len(builds) == 1 and len({id(r) for r in results}) == 1


def test_unwritable_marker_does_not_raise_and_still_drops_the_local_copy(tmp_path):
    marker = tmp_path / "gen"
    marker.mkdir()  # a directory where the file should go -> writing it fails
    cache, builds = _cache(marker)
    first = cache.get()
    cache.invalidate()  # must not raise
    assert cache.get() is not first and len(builds) == 2


def test_reload_reaches_a_real_second_process(tmp_path):
    """The actual multi-worker scenario: a separate OS process holds a loaded model and must notice."""
    marker = tmp_path / "gen"
    child_code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {BACKEND_DIR!r})
        from pathlib import Path
        from app.engine_cache import ReloadableCache
        builds = []
        cache = ReloadableCache(lambda: builds.append(1) or object(), lambda: Path({str(marker)!r}))
        for line in sys.stdin:
            if line.strip() == "get":
                cache.get()
                print(f"builds={{len(builds)}}", flush=True)
    """)
    child = subprocess.Popen([sys.executable, "-c", child_code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        def ask() -> str:
            child.stdin.write("get\n"); child.stdin.flush()
            return child.stdout.readline().strip()

        assert ask() == "builds=1"
        assert ask() == "builds=1"

        parent, _ = _cache(marker)
        parent.invalidate()  # "worker A" accepts a retrained model

        assert ask() == "builds=2"  # "worker B" (a different process) reloaded
        assert ask() == "builds=2"
    finally:
        child.stdin.close(); child.wait(timeout=10)
