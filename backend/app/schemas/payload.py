from typing import List, Optional
from pydantic import BaseModel

class SecurityAlert(BaseModel):
    alert_id: str
    timestamp: str
    source_ip: str
    dest_ip: str
    target_host: str
    user: str
    event_type: str
    raw_severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    asset_criticality: str  # TIER_1_CROWN_JEWEL, TIER_2_BUSINESS, TIER_3_DEV
    description: str

class TriageBatchRequest(BaseModel):
    analyst_notes: Optional[str] = "Standard shift handover review"
    alerts: List[SecurityAlert]

class AgentStepEvent(BaseModel):
    agent_name: str
    stage: str
    message: str
    is_final: bool = False