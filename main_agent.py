import os
import operator
import uvicorn
import requests
import logging
import json
from typing import Annotated, TypedDict, List
from fastapi import FastAPI, Request, BackgroundTasks

# LangGraph & AI Imports
from langgraph.graph import StateGraph, END, START
from langchain_openai import ChatOpenAI
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

# --- LOGGING CONFIGURATION ---
# Sets up logging to print to the console (stdout)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Aegis-SOC")

# 1. INITIALIZE FASTAPI
web_trigger = FastAPI(title="Aegis Agentic Gateway")

class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]

# --- PREPROCESSING LOGIC ---

def preprocess_wazuh_data(raw_data: dict) -> dict:
    """
    Revised preprocessor for Wazuh Shuffle Integration format.
    Accesses data nested within the 'all_fields' key.
    """
    # Use .get() with an empty dict fallback to prevent crashes if a key is missing
    all_fields = raw_data.get("all_fields", {})
    rule = all_fields.get("rule", {})
    agent = all_fields.get("agent", {})
    data = all_fields.get("data", {})
    win_system = data.get("win", {}).get("system", {})

    # Extracting the actual PuTTY Privileges error message from your log
    log_message = win_system.get("message") or all_fields.get("full_log") or "No log content"

    clean_data = {
        "rule_id": rule.get("id"),
        "severity": rule.get("level"),
        "description": rule.get("description"),
        "agent_name": agent.get("name"),
        "source_ip": agent.get("ip", "Unknown"), # Agent IP found in all_fields -> agent -> ip
        "user": data.get("dstuser") or "Unknown",
        "full_log": log_message
    }

    return clean_data

# --- NODES ---

def analyst_node(state: AgentState):
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    system_msg = SystemMessage(content=(
        "You are an Expert SOC Triage Analyst. Your primary function is to ingest security alerts "
        "(such as Wazuh telemetry), perform rapid initial triage, and determine whether an event requires "
        "escalation to the Incident Response (IR) team.\n\n"

        "Your strict operational constraint:\n"
        "You are a triage and analysis agent only. You must NOT execute, recommend, or simulate any "
        "containment, mitigation, or remediation actions (e.g., do not block IPs, kill processes, or isolate hosts). "
        "Your output is strictly informational to empower the next tier of analysts.\n\n"

        "### MODERN SOC ANALYSIS DIRECTIVES\n"
        "1. Entity-Centric Triage: Trace the relationship between the Host, User, Process Tree, and Network Connections.\n"
        "2. Threat Intelligence & Network Correlation: Evaluate IPs, domains, hashes, and network flow anomalies.\n"
        "3. MITRE ATT&CK Mapping: Contextualize behavior by mapping to specific Tactics and Techniques.\n"
        "4. Fidelity & Alert Fatigue Assessment: Identify if the alert is a False Positive (FP) caused by benign admin behavior or scanners.\n"
        "5. Assume Breach Mentality: Prioritize credential access, defense evasion, or lateral movement indicators.\n\n"

        "### TRIAGE DISPOSITIONS\n"
        "Assign one of the following dispositions based on the evidence:\n"
        "- FALSE POSITIVE (FP): Detection fired incorrectly on benign/expected behavior. (Close Alert)\n"
        "- BENIGN TRUE POSITIVE (BTP): Rule fired correctly, but activity is authorized. (Close Alert)\n"
        "- SUSPICIOUS: Anomalous behavior lacking definitive proof of malicious intent. (Escalate to Tier 2)\n"
        "- TRUE POSITIVE (TP) / MALICIOUS: Confirmed IOC or clear adversarial behavior. (Critical Escalation to IR)\n\n"

        "### STRICT OUTPUT FORMAT\n"
        "You must output your analysis in the following structured format. Do not deviate.\n\n"

        "Disposition: [False Positive | Benign True Positive | Suspicious | True Positive]\n"
        "Escalation Decision: [Close Alert | Escalate to Tier 2 | Escalate to IR]\n"
        "Confidence Score: [0-100]%\n\n"

        "1. Executive Summary:\n"
        "[One concise sentence summarizing the 'Who, What, and Where' of the alert.]\n\n"

        "2. Entity Extraction:\n"
        "- Target Host: [Hostname/IP]\n"
        "- Actor/User: [Account Name]\n"
        "- Process: [Executable Name and PID]\n"
        "- Network Indicators: [Source/Dest IPs, Ports, or Domains involved]\n\n"

        "3. Analytical Findings:\n"
        "[A brief, 2-3 sentence technical justification for your disposition explaining why it is benign, suspicious, or malicious based on telemetry fields.]\n\n"

        "4. MITRE ATT&CK Context:\n"
        "- Tactic: [e.g., Execution, Credential Access]\n"
        "- Technique: [e.g., T1059.001 PowerShell]\n\n"

        "5. Escalation Handoff & Intelligence Gaps:\n"
        "- Missing Telemetry: [What data is missing that would increase your confidence?]\n"
        "- Recommended Tier 2 Action: [What exact query or search should the next analyst run?]\n"
        "- Detection Tuning Note: [Optional: 1-sentence recommendation to tune the rule.]\n"
    ))
    response = llm.invoke([system_msg] + state['messages'])
    return {"messages": [response]}

def notifier_node(state: AgentState):
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        logger.warning("Slack Webhook URL not found. Skipping notification.")
        return state

    last_analysis = state["messages"][-1].content
    payload = {
        "text": "🚨 *New AI Security Analysis*",
        "attachments": [{"color": "#f2c744", "text": last_analysis}]
    }
    try:
        response = requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()
        logger.info("Notification sent to Slack successfully.")
    except Exception as e:
        logger.error(f"Failed to send Slack notification: {e}")
        
    return state

# --- GRAPH BUILD ---

workflow = StateGraph(AgentState)
workflow.add_node("analyst", analyst_node)
workflow.add_node("notifier", notifier_node)
workflow.add_edge(START, "analyst")
workflow.add_edge("analyst", "notifier")
workflow.add_edge("notifier", END)
agent_engine = workflow.compile()

# --- ENDPOINTS ---

@web_trigger.post("/alert")
async def handle_wazuh_alert(request: Request, background_tasks: BackgroundTasks):
    # Capture raw data and log it immediately
    raw_data = await request.json()
    logger.info(f"📥 Received alert from Wazuh: {json.dumps(raw_data, indent=2)}")
    
    clean_data = preprocess_wazuh_data(raw_data)
    logger.info(f"🧹 Preprocessed Data: {json.dumps(clean_data, indent=2)}")
    
    background_tasks.add_task(run_investigation, clean_data)
    return {"status": "Cleaned and Queued"}

@web_trigger.get("/test")
async def handle_test_scenario(background_tasks: BackgroundTasks):
    mock_data = {"rule": {"id": "1001", "level": 10, "description": "Manual Test"}, "full_log": "Test log entry"}
    logger.info("🧪 Triggering Manual Test Scenario")
    background_tasks.add_task(run_investigation, mock_data)
    return {"status": "Test Started"}

def run_investigation(data):
    logger.info("🧠 Starting AI Investigation...")
    try:
        inputs = {"messages": [HumanMessage(content=str(data))]}
        agent_engine.invoke(inputs)
        logger.info("✅ Investigation complete.")
    except Exception as e:
        logger.error(f"❌ Investigation failed: {e}")

if __name__ == "__main__":
    uvicorn.run(web_trigger, host="0.0.0.0", port=8000)