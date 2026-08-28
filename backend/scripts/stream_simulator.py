"""Simulates a live network traffic feed against the NetShield AI backend.

Reads a CSV (the curated demo CSV by default, or any raw CICIDS2017-format CSV) and
posts it to POST /api/ingest/csv in small row chunks with a delay between each, instead
of scoring the whole file in one instant. That's what makes /api/stats/timeseries show
an actual trend and a dashboard feel like it's watching live traffic, rather than a
static batch report.

Known limitation: each chunk is windowed independently (the backend has no cross-request
state), so a 10-row detection window that straddles the boundary between two chunks is
never scored. Fine for a demo/dashboard feed; a production stream would need a stateful
sliding buffer on the server side instead of this client-side chunking.

Usage:
    python backend/scripts/stream_simulator.py
    python backend/scripts/stream_simulator.py --input-csv MachineLearningCVE/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv --chunk-rows 50 --interval 1 --loop
"""

from __future__ import annotations

import argparse
import io
import sys
import time
from pathlib import Path

import pandas as pd
import requests

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = REPO_ROOT / "demo" / "panel_demo_traffic.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input-csv", default=str(DEFAULT_INPUT), help="Traffic CSV to replay.")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000", help="Base URL of the running backend.")
    parser.add_argument("--chunk-rows", type=int, default=15, help="Rows sent per request (needs >= window_size, default 10).")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds to sleep between chunks.")
    parser.add_argument("--loop", action="store_true", help="Restart from the beginning when the file is exhausted.")
    parser.add_argument(
        "--include-all-windows", dest="include_all_windows", action="store_true", default=True,
        help="Store Low-risk windows too (default: on, so the quiet stretches are visible in the feed).",
    )
    parser.add_argument("--alerts-only", dest="include_all_windows", action="store_false", help="Store only Medium/High windows.")
    parser.add_argument("--shap", action="store_true", help="Attach SHAP explanations (slower per chunk).")
    return parser.parse_args()


def _check_backend_ready(api_url: str) -> None:
    try:
        response = requests.get(f"{api_url}/api/health", timeout=5)
        response.raise_for_status()
        health = response.json()
    except requests.RequestException as exc:
        print(f"Could not reach {api_url}/api/health -- is the backend running? ({exc})", file=sys.stderr)
        raise SystemExit(1) from exc

    if not health.get("model_loaded"):
        print(f"Backend is up but the model isn't loaded ({health.get('status')}). Fix that first.", file=sys.stderr)
        raise SystemExit(1)


def _send_chunk(api_url: str, source_name: str, chunk: pd.DataFrame, include_all_windows: bool, shap: bool) -> dict:
    buffer = io.StringIO()
    chunk.to_csv(buffer, index=False)
    files = {"file": (source_name, buffer.getvalue(), "text/csv")}
    params = {"include_all_windows": str(include_all_windows).lower(), "shap": str(shap).lower()}
    response = requests.post(f"{api_url}/api/ingest/csv", files=files, params=params, timeout=120)
    response.raise_for_status()
    return response.json()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input_csv)
    if not input_path.exists():
        raise SystemExit(f"Input CSV not found: {input_path}")

    _check_backend_ready(args.api_url)

    df = pd.read_csv(input_path, low_memory=False)
    chunk_rows = max(args.chunk_rows, 10)  # below window_size, a chunk could never produce a window
    total_rows = len(df)

    print(f"Streaming {input_path.name} ({total_rows} rows) to {args.api_url} "
          f"in chunks of {chunk_rows} rows every {args.interval}s. Ctrl+C to stop.")

    pass_number = 0
    try:
        while True:
            pass_number += 1
            for start in range(0, total_rows, chunk_rows):
                chunk = df.iloc[start : start + chunk_rows]
                if len(chunk) < 10:
                    break  # trailing remainder too small to form even one window

                summary = _send_chunk(args.api_url, input_path.name, chunk, args.include_all_windows, args.shap)
                risk = summary["risk_level_counts"]
                labels = {k: v for k, v in summary["predicted_label_counts"].items() if k != "Normal"}
                label_note = f" -> {labels}" if labels else ""
                print(
                    f"[pass {pass_number}] rows {start}-{start + len(chunk) - 1}: "
                    f"{summary['windows_scored']} windows, "
                    f"Low={risk.get('Low', 0)} Medium={risk.get('Medium', 0)} High={risk.get('High', 0)}"
                    f"{label_note}"
                )
                time.sleep(args.interval)

            if not args.loop:
                break
            print(f"-- reached end of {input_path.name}, looping --")
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
