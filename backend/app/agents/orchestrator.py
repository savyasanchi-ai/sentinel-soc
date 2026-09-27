import os
import json
import asyncio
from typing import AsyncGenerator
from dotenv import load_dotenv

from openai import AsyncOpenAI
from semantic_kernel import Kernel
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion
from app.plugins.triage_plugin import SecOpsTriagePlugin

load_dotenv()

class SentinelOrchestrator:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is missing from backend/.env")

        # Create standard AsyncOpenAI client pointed to Google's Gemini endpoint
        self.client = AsyncOpenAI(
            api_key=self.api_key,
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
        )

        # Configure Semantic Kernel using the client
        self.kernel = Kernel()
        self.service = OpenAIChatCompletion(
            ai_model_id="gemini-2.5-flash",
            async_client=self.client
        )
        self.kernel.add_service(self.service)

        # Register deterministic SecOps plugin
        self.plugin = SecOpsTriagePlugin()
        self.kernel.add_plugin(self.plugin, plugin_name="SecOpsPlugin")

    async def execute_stream(self, alerts: list, notes: str) -> AsyncGenerator[str, None]:
        # Step 1: Ingestion & Deterministic Clustering
        yield json.dumps({
            "agent_name": "AlertIngestionAgent",
            "stage": "INGESTING",
            "message": f"Normalizing batch of {len(alerts)} alerts. Evaluating asset criticality tiers..."
        }) + "\n"
        await asyncio.sleep(0.5)

        raw_alerts_dict = [a.model_dump() if hasattr(a, "model_dump") else a for a in alerts]
        cluster_results = self.plugin.cluster_and_prioritize(raw_alerts_dict)

        yield json.dumps({
            "agent_name": "AlertIngestionAgent",
            "stage": "COMPLETE",
            "message": f"Consolidated {len(alerts)} raw alerts into {cluster_results['consolidated_incidents_count']} incident clusters. MTTT Reduction: {cluster_results['mttt_metrics']['mttt_reduction_percentage']}%."
        }) + "\n"
        await asyncio.sleep(0.6)

        # Step 2: Threat Correlation & MITRE ATT&CK Mapping
        yield json.dumps({
            "agent_name": "ThreatCorrelationAgent",
            "stage": "CORRELATING",
            "message": "Correlating event telemetry against MITRE ATT&CK Enterprise Framework..."
        }) + "\n"

        correlation_prompt = f"""
You are the ThreatCorrelationAgent in a high-tier SOC.
Analyze this clustered incident telemetry:
{json.dumps(cluster_results, indent=2)}

Task:
1. Identify the likely Attack Chain (Initial Access, Execution, Persistence, Lateral Movement, Exfiltration).
2. Explicitly cite the exact MITRE ATT&CK technique IDs (e.g. T1110, T1059, T1041, etc.).
3. Determine if the threat is False Positive / Dev noise or an Active Hostile Intrusion.

Provide a concise, highly technical 4-sentence assessment.
"""
        response_mitre = await self.client.chat.completions.create(
            model="gemini-2.5-flash",
            messages=[{"role": "user", "content": correlation_prompt}],
            temperature=0.2
        )
        mitre_text = response_mitre.choices[0].message.content or ""

        yield json.dumps({
            "agent_name": "ThreatCorrelationAgent",
            "stage": "COMPLETE",
            "message": mitre_text
        }) + "\n"
        await asyncio.sleep(0.6)

        # Step 3: Shift Commander Executive Handover Brief
        yield json.dumps({
            "agent_name": "IncidentCommanderAgent",
            "stage": "SYNTHESIZING",
            "message": "Synthesizing executive shift-handover brief and remediation directives..."
        }) + "\n"

        commander_prompt = f"""
You are the IncidentCommanderAgent in an enterprise SOC.
Synthesize the final Shift Handover Briefing.

Clustered Incident Data:
{json.dumps(cluster_results, indent=2)}

Threat Correlation Findings:
{mitre_text}

Analyst Context / Shift Notes:
{notes}

Write a formal Markdown briefing adhering to this structure:
### 1. Executive Incident Verdict
- Current Threat Level (CRITICAL / HIGH / ELEVATED / LOW)
- Summary of verified active intrusions vs benign noise.

### 2. Attack Progression & MITRE ATT&CK Mapping
- Table or list of observed tactics, techniques, and affected Crown Jewel assets.

### 3. Immediate Containment Directives (Human-in-the-Loop)
- Concrete actions to execute immediately (e.g., host isolation, credential revocation, firewall blocklist).

### 4. Shift Handover & Operational Impact
- Impact statement and MTTT efficiency improvement metric ({cluster_results['mttt_metrics']['mttt_reduction_percentage']}% faster than manual baseline).
"""

        final_response = await self.client.chat.completions.create(
            model="gemini-2.5-flash",
            messages=[{"role": "user", "content": commander_prompt}],
            temperature=0.2
        )
        final_text = final_response.choices[0].message.content or ""

        yield json.dumps({
            "agent_name": "IncidentCommanderAgent",
            "stage": "COMPLETE",
            "message": final_text,
            "is_final": True
        }) + "\n"