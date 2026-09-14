from __future__ import annotations

import io

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


def _score_and_store(
    df,
    source: str,
    db: Session,
    include_all_windows: bool,
    shap: bool,
) -> IngestSummaryOut:
    engine = get_engine()
    try:
        records, summary = engine.score_dataframe(df, include_all_windows=include_all_windows, shap=shap)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # Re-ingesting the same source (the demo endpoint, or a file uploaded twice) previously
    # created a fully duplicate set of alerts every time, silently doubling stats/counts.
    # A window is uniquely identified by (source_file, window_start), so skip any record
    # whose window already exists for that exact source before writing.
    existing_starts = set(
        db.execute(
            select(Alert.window_start).where(Alert.source_file == source)
        ).scalars()
    )
    new_records = [record for record in records if record["window_start"] not in existing_starts]
    duplicates_skipped = len(records) - len(new_records)

    batch_id = new_batch_id()
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

    return _score_and_store(df, source=source_name, db=db, include_all_windows=include_all_windows, shap=shap)


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
    return _score_and_store(df, source=settings.demo_csv.name, db=db, include_all_windows=include_all_windows, shap=shap)
