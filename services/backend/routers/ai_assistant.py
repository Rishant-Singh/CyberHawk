"""AI Threat Assistant router — Gemini-powered chat, alert explanation, and recommendations."""

import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from core.security import get_current_user
from models.alert import Alert
from models.incident import Incident

router = APIRouter()
logger = logging.getLogger(__name__)

# ── Gemini client (lazy-initialized) ─────────────────────────────────────────

_gemini_client = None

def _get_gemini():
    """Lazily initialise the Gemini client using the new google-genai SDK."""
    global _gemini_client
    if _gemini_client is not None:
        return _gemini_client
    try:
        from google import genai
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            return None
        _gemini_client = genai.Client(api_key=api_key)
        return _gemini_client
    except ImportError:
        logger.warning("google-genai not installed; AI features will use fallback.")
        return None


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are CyberHawk AI, an expert cybersecurity analyst assistant embedded in a 
Security Operations Center (SOC) platform. You help analysts investigate threats, understand attack patterns,
and respond to security incidents. 

You have deep knowledge of:
- MITRE ATT&CK framework and techniques
- Network security, intrusion detection, and threat hunting
- Malware analysis and IOC investigation
- Incident response and forensics procedures
- Vulnerability management and patch prioritization

When responding:
- Be concise and actionable
- Use bullet points for recommendations
- Reference MITRE technique IDs (e.g., T1190) when relevant
- Prioritize by severity and likelihood of impact
- Assume the analyst is technically proficient
"""


CANDIDATE_MODELS = [
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-flash-latest",
    "gemini-3.7-flash",
]


async def _call_gemini(prompt: str) -> str:
    """Call Gemini API with model cascade fallback, or return a mock response if unavailable."""
    client = _get_gemini()
    if client is None:
        return _mock_response(prompt)
    
    last_error = None
    for model_name in CANDIDATE_MODELS:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=f"{SYSTEM_PROMPT}\n\nAnalyst: {prompt}"
            )
            if response and response.text:
                return response.text
        except Exception as e:
            last_error = e
            logger.warning(f"Gemini model {model_name} failed ({e}). Trying next fallback model...")
            continue

    logger.error(f"All Gemini models failed. Last error: {last_error}")
    return _mock_response(prompt)


def _mock_response(prompt: str) -> str:
    """Fallback rule-based response when Gemini is unavailable."""
    p = prompt.lower()
    if "explain" in p or "what is" in p:
        return (
            "**Threat Analysis** \n\n"
            "Based on the available indicators, this appears to be a network-based intrusion attempt. "
            "The high threat score indicates active exploitation behavior. \n\n"
            "**Key Concerns:**\n"
            "- Elevated anomaly score suggests deviation from baseline traffic patterns\n"
            "- Source IP has been flagged in multiple prior alerts\n"
            "- Attack pattern matches MITRE T1190 (Exploit Public-Facing Application)\n\n"
            "**Recommended Actions:**\n"
            "1. Block the source IP at the perimeter firewall immediately\n"
            "2. Review destination host for signs of compromise\n"
            "3. Capture packet data for forensic analysis\n"
            "4. Open an incident ticket and assign to Tier 2\n\n"
            "*Note: Connect a Gemini API key for AI-powered analysis.*"
        )
    elif "recommend" in p or "what should" in p or "next step" in p:
        return (
            "**Recommended Response Actions:**\n\n"
            "**Immediate (0-1 hour):**\n"
            "- Isolate affected endpoint from the network\n"
            "- Block attacker IP range at firewall\n"
            "- Preserve system logs and memory dumps\n\n"
            "**Short-term (1-24 hours):**\n"
            "- Run endpoint EDR scan on all hosts in the same subnet\n"
            "- Review lateral movement indicators (SMB, RDP, WMI)\n"
            "- Check for persistence mechanisms (scheduled tasks, registry keys)\n\n"
            "**Long-term:**\n"
            "- Patch the exploited vulnerability within 72 hours\n"
            "- Update detection rules in SIEM\n"
            "- Conduct post-incident review\n\n"
            "*Connect GEMINI_API_KEY for context-aware AI recommendations.*"
        )
    else:
        return (
            "I'm CyberHawk AI, your SOC assistant. I can help you:\n\n"
            "- **Explain** any alert or threat indicator\n"
            "- **Recommend** response and containment steps\n"
            "- **Investigate** IOCs (IPs, domains, hashes)\n"
            "- **Map** attacks to MITRE ATT&CK techniques\n"
            "- **Prioritize** incidents based on severity and context\n\n"
            "Try asking: *'Explain this alert'*, *'What should I do about this threat?'*, "
            "or *'How do I contain a ransomware attack?'*\n\n"
            "*Connect a GEMINI_API_KEY in your .env for full AI capabilities.*"
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/chat")
async def chat(
    payload: dict,
    _=Depends(get_current_user),
):
    """
    General-purpose cybersecurity chat.
    Body: { "message": "...", "history": [{"role": "user"|"assistant", "content": "..."}] }
    """
    message = payload.get("message", "").strip()
    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty")

    history = payload.get("history", [])

    # Build context from conversation history
    context_parts = []
    for turn in history[-6:]:  # last 3 exchanges
        role = "Analyst" if turn.get("role") == "user" else "CyberHawk AI"
        context_parts.append(f"{role}: {turn.get('content', '')}")

    full_prompt = "\n".join(context_parts + [f"Analyst: {message}"])
    response = await _call_gemini(full_prompt)

    return {
        "role": "assistant",
        "content": response,
        "model": "gemini-3.6-flash" if _get_gemini() else "mock",
    }


@router.post("/explain/{alert_id}")
async def explain_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Generate a plain-English AI explanation for a specific alert."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    prompt = f"""Analyze this security alert and provide a clear explanation for a SOC analyst:

Alert Details:
- Timestamp: {alert.timestamp}
- Source IP: {alert.src_ip}
- Destination IP: {alert.dst_ip}
- Protocol: {alert.protocol}
- Service: {alert.service}
- Threat Level: {alert.threat_level}
- Threat Score: {alert.threat_score}/100
- Anomaly Score: {alert.anomaly_score:.3f}
- Classification: {alert.classification}
- Attack Type: {alert.attack_type}
- MITRE Technique: {alert.mitre_technique}
- Country: {alert.geo_country}
- ML Explanation: {alert.explanation}

Provide:
1. A clear 2-3 sentence summary of what happened
2. Why this is {alert.threat_level} severity
3. Top 3 immediate actions the analyst should take
4. Any relevant MITRE ATT&CK context"""

    response = await _call_gemini(prompt)
    return {
        "alert_id": alert_id,
        "threat_level": alert.threat_level,
        "explanation": response,
        "model": "gemini-3.6-flash" if _get_gemini() else "mock",
    }


@router.post("/recommend/{incident_id}")
async def recommend_for_incident(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_user),
):
    """Generate AI-powered remediation recommendations for an incident."""
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalars().first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch a sample of linked alerts for context
    linked_alerts = []
    if incident.alert_ids:
        alert_result = await db.execute(
            select(Alert).where(Alert.id.in_(incident.alert_ids[:10]))
        )
        linked_alerts = alert_result.scalars().all()

    alert_summary = "\n".join([
        f"  - {a.threat_level} | {a.attack_type} | src:{a.src_ip} | MITRE:{a.mitre_technique}"
        for a in linked_alerts
    ]) or "  No linked alerts"

    prompt = f"""You are responding to a security incident. Provide detailed remediation recommendations.

Incident:
- Title: {incident.title}
- Severity: {incident.severity}
- Status: {incident.status}
- Description: {incident.description or 'Not provided'}
- Tags: {', '.join(incident.tags or [])}
- MITRE Techniques: {', '.join(incident.mitre_techniques or [])}

Linked Alerts Summary:
{alert_summary}

Please provide:
1. Executive summary (2 sentences)
2. Immediate containment steps (bullet points)
3. Investigation steps (what to look for)
4. Long-term remediation actions
5. Lessons learned / prevention measures"""

    response = await _call_gemini(prompt)
    return {
        "incident_id": incident_id,
        "severity": incident.severity,
        "recommendations": response,
        "model": "gemini-3.6-flash" if _get_gemini() else "mock",
    }


@router.get("/suggested-prompts")
async def get_suggested_prompts(_=Depends(get_current_user)):
    """Return a list of suggested prompts for the AI assistant UI."""
    return {
        "prompts": [
            "Explain the latest critical alert in detail",
            "What are the top threats in the last 24 hours?",
            "How do I contain a ransomware attack?",
            "What does MITRE T1190 mean and how do I detect it?",
            "Which assets are most at risk right now?",
            "Walk me through an incident response playbook",
            "How do I hunt for lateral movement in my network?",
            "What are signs of a command and control (C2) connection?",
        ]
    }
