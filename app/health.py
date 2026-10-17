"""
SentinelPay – health-check router.

Single endpoint that confirms the API is alive AND the database is reachable.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check(db: Session = Depends(get_db)) -> dict:
    """
    Return {"status": "ok", "database": "connected"} when everything is fine.
    If the DB is unreachable, return a 503 so load-balancers / monitoring
    know the instance is unhealthy.
    """
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Database unreachable: {exc}",
        )
    return {"status": "ok", "database": "connected"}
