from __future__ import annotations

import math

import numpy as np
import tensorflow as tf

from cyber_ai.data import build_window_starts


class WindowSequence(tf.keras.utils.Sequence):
    """Keras sequence that materializes temporal windows batch by batch."""

    def __init__(
        self,
        X: np.ndarray,
        y: np.ndarray | None = None,
        starts: np.ndarray | None = None,
        window_size: int = 10,
        stride: int = 1,
        batch_size: int = 256,
        target_mode: str | None = "label",
        shuffle: bool = False,
    ) -> None:
        super().__init__()
        self.X = np.asarray(X, dtype=np.float32)
        self.y = None if y is None else np.asarray(y)
        self.window_size = int(window_size)
        self.batch_size = int(batch_size)
        self.target_mode = target_mode
        self.shuffle = shuffle
        self.starts = (
            np.asarray(starts, dtype=np.int64)
            if starts is not None
            else build_window_starts(len(self.X), window_size, stride)
        )
        if self.target_mode == "label" and self.y is None:
            raise ValueError("Labels are required when target_mode='label'.")
        self.order = np.arange(len(self.starts), dtype=np.int64)
        self.on_epoch_end()

    def __len__(self) -> int:
        return int(math.ceil(len(self.starts) / self.batch_size))

    def __getitem__(self, index: int):
        batch_positions = self.order[index * self.batch_size : (index + 1) * self.batch_size]
        batch_starts = self.starts[batch_positions]
        windows = materialize_windows(self.X, batch_starts, self.window_size)

        if self.target_mode is None:
            return windows
        if self.target_mode == "autoencoder":
            return windows, windows

        labels = self.y[batch_starts + self.window_size - 1].astype(np.int64)
        return windows, labels

    def on_epoch_end(self) -> None:
        if self.shuffle:
            np.random.shuffle(self.order)


def materialize_windows(X: np.ndarray, starts: np.ndarray, window_size: int) -> np.ndarray:
    X = np.asarray(X, dtype=np.float32)
    starts = np.asarray(starts, dtype=np.int64)
    windows = np.empty((len(starts), window_size, X.shape[1]), dtype=np.float32)
    for index, start in enumerate(starts):
        windows[index] = X[start : start + window_size]
    return windows
