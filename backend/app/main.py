import json
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from app.schemas.payload import TriageBatchRequest
from app.agents.orchestrator import SentinelOrchestrator

app = FastAPI(
    title="Sentinel SOC - Enterprise Alert Triage Engine",
    description="Autonomous Multi-Agent Alert Summarizer for Problem #25"
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

orchestrator = SentinelOrchestrator()

@app.get("/")
def health_check():
    return {"status": "ONLINE", "system": "Sentinel SOC Core Engine", "version": "1.0.0"}

@app.get("/api/sample-alerts")
def get_sample_alerts():
    """Returns the pre-configured enterprise attack telemetry dataset."""
    sample_file = Path(__file__).resolve().parent.parent / "data" / "alerts.json"
    if sample_file.exists():
        with open(sample_file, "r") as f:
            return json.load(f)
    return []

@app.post("/api/triage/stream")
async def stream_triage(request: TriageBatchRequest):
    """
    Streams multi-agent triage, clustering, MITRE ATT&CK mapping,
    and the executive handover brief via Server-Sent Events (SSE).
    """
    async def event_generator():
        async for chunk in orchestrator.execute_stream(request.alerts, request.analyst_notes):
            yield {"data": chunk}

    return EventSourceResponse(event_generator())