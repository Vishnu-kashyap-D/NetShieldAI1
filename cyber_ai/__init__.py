"""Adaptive cybersecurity analytics framework for CICIDS2017 traffic."""

import os

# Must be set before the first `import tensorflow` anywhere in the process (TF reads it once,
# at import time). TensorFlow >=2.16 defaults to Keras 3, which cannot deserialize the
# `keras.src.engine.functional` class path baked into the .keras files under artifacts/models/
# (saved under Keras 2, TF 2.15) -- loading them raises "parent module ... cannot be imported"
# under Keras 3. This forces `tf.keras` back to the legacy Keras 2 API (via the `tf-keras`
# package) so those existing artifacts keep loading without retraining. Only fixes entry points
# that import cyber_ai before tensorflow; backend/app/config.py sets the same var for the
# FastAPI app, whose detection_service.py imports tensorflow before cyber_ai.
os.environ.setdefault("TF_USE_LEGACY_KERAS", "1")

__version__ = "0.1.0"
