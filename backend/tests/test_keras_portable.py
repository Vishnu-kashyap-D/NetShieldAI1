"""backend/scripts/make_keras_portable.py: Windows-saved .keras weights become loadable on Linux."""
from __future__ import annotations

import importlib.util
import io
import zipfile
from pathlib import Path

import h5py
import numpy as np
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "make_keras_portable.py"
REAL_MODELS = Path(__file__).resolve().parents[2] / "artifacts" / "models"


@pytest.fixture(scope="module")
def portable():
    spec = importlib.util.spec_from_file_location("make_keras_portable", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def windows_style_weights() -> bytes:
    """The layout Keras 2.18 writes on Windows: flat top-level groups with backslashes in their names."""
    buffer = io.BytesIO()
    with h5py.File(buffer, "w") as f:
        f.create_group("layers\\lstm").create_group("vars")
        f["layers\\lstm/vars"].create_dataset("0", data=np.arange(6, dtype="float32").reshape(2, 3))
        f.create_group("layers\\lstm\\cell").create_group("vars")
        f["layers\\lstm\\cell/vars"].create_dataset("0", data=np.full((4,), 7.0, dtype="float32"))
        f.create_group("layers\\dense").create_group("vars")
        f["layers\\dense/vars"].create_dataset("0", data=np.array([1.5, 2.5], dtype="float32"))
        f.create_group("optimizer").create_group("vars")
        f.create_group("vars")
    return buffer.getvalue()


def write_keras(path: Path, weights: bytes) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("metadata.json", '{"keras_version": "2.18.0"}')
        z.writestr("config.json", '{"class_name": "Sequential"}')
        z.writestr("model.weights.h5", weights)


def keys_and_arrays(weights: bytes) -> dict[str, np.ndarray]:
    out: dict[str, np.ndarray] = {}
    with h5py.File(io.BytesIO(weights), "r") as f:
        f.visititems(lambda name, obj: out.__setitem__(name, obj[()]) if isinstance(obj, h5py.Dataset) else None)
    return out


def test_backslash_groups_become_nested_slash_groups(portable, tmp_path):
    model = tmp_path / "m.keras"
    write_keras(model, windows_style_weights())
    assert portable.convert_file(model) is True
    with zipfile.ZipFile(model) as z:
        with h5py.File(io.BytesIO(z.read("model.weights.h5")), "r") as f:
            assert not any("\\" in k for k in f.keys())
            assert set(f["layers"].keys()) == {"lstm", "dense"}
            assert "cell" in f["layers/lstm"] and "vars" in f["layers/lstm/cell"]        # nested, like Linux expects
            assert "vars" in f["optimizer"]


def test_weight_values_are_copied_exactly(portable, tmp_path):
    model = tmp_path / "m.keras"
    original = windows_style_weights()
    write_keras(model, original)
    portable.convert_file(model)
    with zipfile.ZipFile(model) as z:
        after = keys_and_arrays(z.read("model.weights.h5"))
    before = {k.replace("\\", "/"): v for k, v in keys_and_arrays(original).items()}
    assert set(after) == set(before) and after
    for name in before:
        np.testing.assert_array_equal(after[name], before[name])


def test_other_files_in_the_archive_are_untouched(portable, tmp_path):
    model = tmp_path / "m.keras"
    write_keras(model, windows_style_weights())
    portable.convert_file(model)
    with zipfile.ZipFile(model) as z:
        assert z.read("config.json") == b'{"class_name": "Sequential"}'
        assert z.read("metadata.json") == b'{"keras_version": "2.18.0"}'
        assert z.namelist() == ["metadata.json", "config.json", "model.weights.h5"]


def test_running_it_twice_changes_nothing_the_second_time(portable, tmp_path):
    model = tmp_path / "m.keras"
    write_keras(model, windows_style_weights())
    assert portable.convert_file(model) is True
    first = model.read_bytes()
    assert portable.convert_file(model) is False
    assert model.read_bytes() == first


def test_no_temp_files_are_left_behind(portable, tmp_path):
    model = tmp_path / "m.keras"
    write_keras(model, windows_style_weights())
    portable.convert_file(model)
    assert [p.name for p in tmp_path.iterdir()] == ["m.keras"]


def test_a_file_without_weights_is_ignored(portable, tmp_path):
    model = tmp_path / "odd.keras"
    with zipfile.ZipFile(model, "w") as z:
        z.writestr("config.json", "{}")
    assert portable.convert_file(model) is False


@pytest.mark.real_model
def test_the_committed_windows_models_convert_without_losing_a_single_weight(portable, tmp_path):
    for name in ("autoencoder", "bilstm_classifier"):
        copy = tmp_path / f"{name}.keras"
        copy.write_bytes((REAL_MODELS / f"{name}.keras").read_bytes())
        with zipfile.ZipFile(copy) as z:
            original = keys_and_arrays(z.read("model.weights.h5"))
        assert any("\\" in k for k in original), "expected the Windows-saved layout"
        assert portable.convert_file(copy) is True
        with zipfile.ZipFile(copy) as z:
            converted = keys_and_arrays(z.read("model.weights.h5"))
        assert {k.replace("\\", "/") for k in original} == set(converted)
        for key, value in original.items():
            np.testing.assert_array_equal(converted[key.replace("\\", "/")], value)
