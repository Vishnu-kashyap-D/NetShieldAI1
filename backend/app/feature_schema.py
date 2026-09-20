from __future__ import annotations

import hashlib
from collections.abc import Iterable


def feature_schema_version(feature_names: Iterable[str]) -> str:
    """Short fingerprint of a feature *set*, stored on every Alert (Alert.feature_schema_version).

    Alert.features is already keyed by feature name, so old rows stay readable after the trained
    feature set changes -- what was missing is knowing *which* feature set a row was scored under
    (e.g. before deciding whether its vector can still be used as a retraining row). Names are
    sorted before hashing because the JSON column doesn't preserve key order once it round-trips
    through MySQL; two rows have the same version exactly when they carry the same set of names.
    """
    joined = "\n".join(sorted(feature_names))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:12]
