"""6.6 -- Cross-window correlation: catching sustained activity the per-window gate lets through.

The pipeline is sequential: the Autoencoder decides which windows the classifier ever sees. Measured on
real, time-ordered traffic, that gate misses most windows of some attacks -- ~93% of Port Scanning windows,
because a scan looks *simple* to an autoencoder trained on benign traffic. Yet the classifier, shown those
same windows, recognises them at ~99.8% confidence, again and again, window after window.

This layer exploits exactly that: it looks for **persistence**. A run of many consecutive windows that the
classifier all reads as the SAME category, each at very high confidence, is not noise -- whether or not the
Autoencoder flagged a single one of them. Benign traffic does not do this: its classifier outputs are
scattered across categories and rarely confident (the classifier was never trained on benign traffic, so on
it the confidence is low and the label jumps around).

Why persistence and not a running total of risk (CUSUM): that was tried first and failed the evaluation --
bursty benign traffic accumulates risk just as a slow attack does, giving hundreds of false campaigns on a
pure-benign day. Same-category-at-high-confidence-for-many-windows is far more selective.

The layer only ever ADDS information. It reads scores the pipeline already produced, changes no per-window
alert, label or risk level, and reports campaigns separately. Pure numpy; see `cyber_ai.correlation_eval`
for how the defaults were chosen and what they achieve (and do not achieve) on real traffic.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

# From `python -m cyber_ai.correlation_eval` (docs/PHASE6_FINDINGS.md): a confidence of 0.99 is the knee (at 0.95 the
# benign day already produces false campaigns; at 0.99 it produces none). The run length of 8 is a deliberate margin
# over the sweep's own pick of 5, which recovers only 0.4 points more.
DEFAULT_MIN_CONFIDENCE = 0.99  # a window counts toward a campaign only if the classifier is at least this sure
DEFAULT_MIN_WINDOWS = 8        # ...and the run must span at least this many consecutive windows
DEFAULT_MAX_GAP = 1            # up to this many consecutive off-pattern windows may interrupt a run
MIN_DENSITY = 0.75             # at least this share of a run's windows must themselves be on-pattern
MAX_STRIDES_APART = 2          # windows further apart than this many strides are not "consecutive"


@dataclass(frozen=True)
class Campaign:
    """A run of consecutive windows the classifier kept reading as one category with high confidence."""

    category: int              # class id the run consistently looked like
    first_window: int          # row where the first window of the run starts
    last_window: int           # row where the last window of the run ends
    windows: int               # windows the run spans
    mean_confidence: float     # average classifier confidence over the run's on-pattern windows
    alerted_windows: int       # windows in the run that were individually Medium/High anyway
    first_index: int           # position (in the ordered window list) of the run's first window
    last_index: int            # position of its last window

    @property
    def quiet_windows(self) -> int:
        """Windows in the run that did NOT raise an alert on their own -- what this layer adds."""
        return self.windows - self.alerted_windows


def find_campaigns(
    window_starts: np.ndarray,
    categories: np.ndarray,
    confidences: np.ndarray,
    risk_scores: np.ndarray,
    alert_floor: float,
    window_size: int,
    stride: int,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    min_windows: int = DEFAULT_MIN_WINDOWS,
    max_gap: int = DEFAULT_MAX_GAP,
) -> list[Campaign]:
    """Find campaigns in ONE stream of windows (one capture file), given the classifier's output on every window.

    `categories` / `confidences` are the classifier's arg-max class and probability for each window (computed
    for ALL windows, not just the ones the anomaly gate flagged). `risk_scores` / `alert_floor` are used only
    to report how many of a campaign's windows already alerted on their own.

    Windows further apart than `MAX_STRIDES_APART` strides are not consecutive: a run never bridges a hole in
    the data (a dropped chunk, a different capture).
    """
    starts = np.asarray(window_starts, dtype=np.int64)
    if len(starts) == 0:
        return []
    order = np.argsort(starts, kind="stable")
    starts = starts[order]
    categories = np.asarray(categories)[order]
    confidences = np.nan_to_num(np.asarray(confidences, dtype=np.float64)[order], nan=0.0)
    risk = np.nan_to_num(np.asarray(risk_scores, dtype=np.float64)[order], nan=0.0)

    breaks = np.where(np.diff(starts) > MAX_STRIDES_APART * stride)[0] + 1
    campaigns: list[Campaign] = []
    for segment in np.split(np.arange(len(starts)), breaks):
        campaigns.extend(_runs_in_segment(
            segment, starts, categories, confidences, risk, alert_floor, window_size, min_confidence, min_windows, max_gap
        ))
    return campaigns


def _runs_in_segment(segment, starts, categories, confidences, risk, alert_floor, window_size,
                     min_confidence, min_windows, max_gap) -> list[Campaign]:
    on_pattern = confidences >= min_confidence
    found: list[Campaign] = []
    position, end = int(segment[0]), int(segment[-1])
    while position <= end:
        if not on_pattern[position]:
            position += 1
            continue
        category = categories[position]
        last_on = position          # last on-pattern window of the run so far
        misses = 0
        j = position
        while j < end:
            j += 1
            if on_pattern[j] and categories[j] == category:
                last_on, misses = j, 0
            elif misses < max_gap:
                misses += 1
            else:
                break
        indices = np.arange(position, last_on + 1)
        on = on_pattern[indices] & (categories[indices] == category)
        if len(indices) >= min_windows and on.mean() >= MIN_DENSITY:
            found.append(Campaign(
                category=int(category),
                first_window=int(starts[position]),
                last_window=int(starts[last_on]) + window_size - 1,
                windows=int(len(indices)),
                mean_confidence=float(confidences[indices][on].mean()),
                alerted_windows=int((risk[indices] >= alert_floor).sum()),
                first_index=int(position),
                last_index=int(last_on),
            ))
        position = last_on + 1
    return found
