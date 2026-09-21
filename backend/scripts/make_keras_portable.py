"""Make Keras ``.keras`` model files that were saved on Windows loadable on Linux (and so inside Docker).

Why this exists: Keras 2.18's ``.keras`` saver builds the path of each layer's weights inside ``model.weights.h5``
with the operating system's path separator. Saved on Windows, the groups are literally named ``layers\\lstm``,
``layers\\lstm\\cell`` ... (one flat group per layer, backslashes in the *name*). Windows loads them because it builds
the same backslash path. Linux looks for ``layers/lstm``, finds nothing, and fails with
``Layer 'lstm_cell' expected 3 variables, but received 0 variables during loading``.

This rewrites those group names to ``/`` so they become real nested groups. The weight arrays are copied byte for
byte; only the names change. It is idempotent (a file with no backslash names is left untouched) and replaces each
file atomically. Run it on the Linux side only -- on Windows the un-converted files are the ones that load.

    python backend/scripts/make_keras_portable.py [directory-or-file ...]      # default: artifacts/models
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import zipfile
from pathlib import Path

import h5py

WEIGHTS_MEMBER = "model.weights.h5"


def _has_backslash_groups(weights: bytes) -> bool:
    with h5py.File(io.BytesIO(weights), "r") as source:
        return any("\\" in key for key in source.keys())


def convert_weights(weights: bytes) -> bytes:
    """Return the same weights file with every backslash-named top-level group turned into a nested ``/`` path."""
    buffer = io.BytesIO()
    with h5py.File(io.BytesIO(weights), "r") as source, h5py.File(buffer, "w") as target:
        for key in sorted(source.keys()):           # sorted: "layers\lstm" is copied before "layers\lstm\cell"
            new_key = key.replace("\\", "/")
            parent = new_key.rpartition("/")[0]
            if parent:
                target.require_group(parent)
            source.copy(source[key], target, name=new_key)
    return buffer.getvalue()


def convert_file(path: Path) -> bool:
    """Convert one ``.keras`` file in place. Returns True if it changed, False if it was already portable."""
    with zipfile.ZipFile(path) as archive:
        if WEIGHTS_MEMBER not in archive.namelist():
            return False
        weights = archive.read(WEIGHTS_MEMBER)
        if not _has_backslash_groups(weights):
            return False
        converted = convert_weights(weights)
        members = [(info, archive.read(info.filename)) for info in archive.infolist()]

    fd, temp_name = tempfile.mkstemp(suffix=".keras.tmp", dir=path.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(temp_name, "w") as out:
            for info, data in members:
                out.writestr(info, converted if info.filename == WEIGHTS_MEMBER else data, compress_type=info.compress_type)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.remove(temp_name)
    return True


def main(argv: list[str]) -> int:
    targets = [Path(a) for a in argv] or [Path("artifacts") / "models"]
    files: list[Path] = []
    for target in targets:
        files += sorted(target.glob("*.keras")) if target.is_dir() else [target]
    for path in files:
        print(f"{path}: {'converted to portable paths' if convert_file(path) else 'already portable, left as is'}")
    if not files:
        print("no .keras files found", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
