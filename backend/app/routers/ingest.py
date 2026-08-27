from __future__ import annotations

import io

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.detection_service import get_engine, load_csv_as_traffic_frame, new_batch_id
from app.models import Alert
from app.schemas import IngestSummaryOut

router = APIRouter(prefix="/ingest", tags=["ingest"])


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

    batch_id = new_batch_id()
    db.bulk_save_objects([Alert(batch_id=batch_id, **record) for record in records])
    db.commit()

    return IngestSummaryOut(batch_id=batch_id, source=source, **summary)


@router.post("/csv", response_model=IngestSummaryOut)
async def ingest_csv(
    file: UploadFile,
    include_all_windows: bool = Query(False, description="Store Low-risk windows too, not just Medium/High."),
    shap: bool = Query(False, description="Attach SHAP explanations (slower)."),
    db: Session = Depends(get_db),
) -> IngestSummaryOut:
    raw = await file.read()
    df = load_csv_as_traffic_frame(io.BytesIO(raw), source_name=file.filename or "upload.csv")
    return _score_and_store(df, source=file.filename or "upload.csv", db=db, include_all_windows=include_all_windows, shap=shap)


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
