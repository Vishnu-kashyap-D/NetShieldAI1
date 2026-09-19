from __future__ import annotations

import hashlib
import io
import uuid

import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import CAN_INGEST_TRAFFIC, require_role
from app.config import settings
from app.database import get_db
from app.detection_service import get_engine, load_csv_as_traffic_frame, new_batch_id
from app.models import Alert
from app.schemas import IngestSummaryOut

# Both routes here run real traffic through the trained models and write alerts -- a Viewer
# or Security Analyst shouldn't be able to trigger that, only Threat Hunter/Administrator.
router = APIRouter(prefix="/ingest", tags=["ingest"], dependencies=[Depends(require_role(*CAN_INGEST_TRAFFIC))])

# Fixed namespace for deriving batch ids from upload content (see _batch_id_for_upload).
_INGEST_BATCH_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://netshield.ai/ingest-batch")


def _batch_id_for_upload(source: str, content: bytes) -> str:
    """Deterministic batch id for "this exact file, uploaded under this exact name".

    Re-uploading identical bytes under the same name yields the *same* batch id, which is what
    makes ingest idempotent (see _score_and_store). Anything else -- different bytes, or the same
    bytes under a different name -- gets a different batch id and is never treated as a duplicate.
    """
    digest = hashlib.sha256(content).hexdigest()
    return str(uuid.uuid5(_INGEST_BATCH_NAMESPACE, f"{source}\n{digest}"))


def _score_and_store(
    df,
    source: str,
    db: Session,
    include_all_windows: bool,
    shap: bool,
    batch_id: str,
) -> IngestSummaryOut:
    engine = get_engine()
    try:
        records, summary = engine.score_dataframe(df, include_all_windows=include_all_windows, shap=shap)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Re-ingesting the same upload (the demo endpoint clicked twice, one file sent twice) used to
    # create a fully duplicate set of alerts each time, silently doubling stats/counts. Skip any
    # window that already exists in this upload's batch.
    #
    # window_start is only unique WITHIN one upload -- it's a position in the frame that was
    # scored, not a global one -- so it must only ever be compared inside a single batch id. An
    # earlier version compared it across everything sharing a source_file name, which silently
    # discarded real data whenever two different uploads shared a filename or a chunked feed
    # (backend/scripts/stream_simulator.py sends one file as many small POSTs, each starting
    # again at window 0) reused it: everything after the first chunk was dropped as a "duplicate".
    existing_starts = set(
        db.execute(
            select(Alert.window_start).where(Alert.batch_id == batch_id)
        ).scalars()
    )
    new_records = [record for record in records if record["window_start"] not in existing_starts]
    duplicates_skipped = len(records) - len(new_records)

    if new_records:
        db.bulk_save_objects([Alert(batch_id=batch_id, **record) for record in new_records])
        db.commit()

    # Counts in the response reflect what actually got written this call, not the full
    # scored batch -- windows_scored/anomalous_windows stay as scoring-layer facts (the
    # model ran on all of them regardless of storage dedup); the rest describe storage.
    new_risk_levels = pd.Series([record["risk_level"] for record in new_records])
    new_predicted_labels = pd.Series([record["predicted_label"] for record in new_records])
    summary = {
        **summary,
        "alerts_written": len(new_records),
        "duplicates_skipped": duplicates_skipped,
        "risk_level_counts": {str(k): int(v) for k, v in new_risk_levels.value_counts().items()},
        "predicted_label_counts": {str(k): int(v) for k, v in new_predicted_labels.value_counts().items()},
    }

    return IngestSummaryOut(batch_id=batch_id, source=source, **summary)


@router.post("/csv", response_model=IngestSummaryOut)
async def ingest_csv(
    file: UploadFile,
    include_all_windows: bool = Query(False, description="Store Low-risk windows too, not just Medium/High."),
    shap: bool = Query(False, description="Attach SHAP explanations (slower)."),
    allow_duplicates: bool = Query(
        False,
        description=(
            "Skip the duplicate check and always store as a new batch. For callers that deliberately replay "
            "the same data as new events (backend/scripts/stream_simulator.py --loop); leave off otherwise."
        ),
    ),
    db: Session = Depends(get_db),
) -> IngestSummaryOut:
    # Declared Content-Length lets an oversized upload be rejected before reading any of the
    # body; a client that omits it (some multipart encoders do) still gets caught by the
    # len(raw) check right after reading, just after the bytes are already in memory once.
    declared_size = file.size
    if declared_size is not None and declared_size > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File is {declared_size} bytes, over the {settings.max_upload_bytes}-byte limit.",
        )

    raw = await file.read()
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File is {len(raw)} bytes, over the {settings.max_upload_bytes}-byte limit.",
        )

    source_name = file.filename or "upload.csv"
    try:
        df = load_csv_as_traffic_frame(io.BytesIO(raw), source_name=source_name)
    except Exception as exc:
        # Anything pandas/clean_raw_dataframe can throw on a garbled, binary, or empty upload
        # (ParserError, UnicodeDecodeError, EmptyDataError, ...) is a bad *input*, not a server
        # bug -- surface it as a clean validation error instead of an unhandled 500.
        raise HTTPException(status_code=422, detail=f"Couldn't parse '{source_name}' as CSV: {exc}") from exc

    batch_id = new_batch_id() if allow_duplicates else _batch_id_for_upload(source_name, raw)
    return _score_and_store(
        df, source=source_name, db=db, include_all_windows=include_all_windows, shap=shap, batch_id=batch_id
    )


@router.post("/demo", response_model=IngestSummaryOut)
def ingest_demo(
    include_all_windows: bool = Query(True, description="Store every window, including Low risk (default for the demo scene)."),
    shap: bool = Query(False, description="Attach SHAP explanations (slower)."),
    db: Session = Depends(get_db),
) -> IngestSummaryOut:
    """Convenience endpoint: score the repo's curated panel demo CSV without a file upload.

    Handy for exercising the dashboard/backend without waiting on a real stream simulator.
    """
    if not settings.demo_csv.exists():
        raise HTTPException(status_code=404, detail=f"Demo CSV not found at {settings.demo_csv}")
    df = load_csv_as_traffic_frame(settings.demo_csv, source_name=settings.demo_csv.name)
    batch_id = _batch_id_for_upload(settings.demo_csv.name, settings.demo_csv.read_bytes())
    return _score_and_store(
        df, source=settings.demo_csv.name, db=db, include_all_windows=include_all_windows, shap=shap, batch_id=batch_id
    )
