import os

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

try:
    from .storage import read_latest_analysis, read_recent_events
except ImportError:
    from storage import read_latest_analysis, read_recent_events

API_TOKEN = os.getenv("GHOSTPLC_API_TOKEN")

app = FastAPI(title="GhostPLC Sensor API")


def require_token(authorization: str | None) -> None:
    if not API_TOKEN:
        return

    expected = f"Bearer {API_TOKEN}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/events.json")
def events_json(limit: int = 1000, authorization: str | None = Header(default=None)) -> JSONResponse:
    require_token(authorization)
    return JSONResponse(
        read_recent_events(limit=limit),
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/events")
def events(limit: int = 1000, authorization: str | None = Header(default=None)) -> JSONResponse:
    return events_json(limit, authorization)


@app.get("/analysis")
def analysis(authorization: str | None = Header(default=None)) -> JSONResponse:
    require_token(authorization)
    return JSONResponse(
        read_latest_analysis() or {},
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/analysis.txt")
def analysis_text(authorization: str | None = Header(default=None)) -> PlainTextResponse:
    require_token(authorization)
    latest = read_latest_analysis() or {}
    return PlainTextResponse(
        str(latest.get("summary") or ""),
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
