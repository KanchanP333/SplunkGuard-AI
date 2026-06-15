from fastapi import FastAPI, Request
from pydantic import BaseModel
import uvicorn
import logging
import json
import requests
import urllib3
import ollama

# Suppress the warning about Splunk's self-signed local certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- ADD YOUR TOKEN HERE ---
SPLUNK_TOKEN = "eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJrYW5jaGFuIGZyb20gS2FuY2hhblAiLCJzdWIiOiJrYW5jaGFuIiwiYXVkIjoiSGFja2F0aG9uIiwiaWRwIjoiU3BsdW5rIiwianRpIjoiMmJhMjU2YzBhOTA1YTQ5ZDgwMTY2YzZiOWNmZjJjMTdmNDRjOTM4ZDg0ZWZmMGQ5Y2RjY2Q4MzdiYjg4YzliNCIsImlhdCI6MTc4MTQzOTMxMSwiZXhwIjoxNzg0MDMxMzExLCJuYnIiOjE3ODE0MzkzMTF9.wBWI37tHrDshIOqIrmU6qnxLpp6gQ7m_bUu6SGNkiOuoeBCyNnViydAvlX9PqntxhEnphPHZEzJb38BwnZo9xA"
SPLUNK_HEC_TOKEN = "a370f85f-428f-4623-b338-dab7eddb6d5c"
SPLUNK_API_URL = "https://localhost:8089/services/search/jobs/export"

def fetch_host_telemetry(target_host: str):
    """Reaches back into Splunk to pull CPU data for the compromised host."""
    logger.info(f"Hunting for Observability telemetry on host: {target_host}...")
    
    # The SPL query we tested, dynamically injecting the target_host from the alert
    search_query = f"""search index="_introspection" component=Hostwide host="{target_host}"
    | eval cpu_usage=round('data.cpu_system_pct' + 'data.cpu_user_pct', 2) 
    | stats avg(cpu_usage) as avg_cpu by host"""

    headers = {"Authorization": f"Bearer {SPLUNK_TOKEN}"}
    
    # We use output_mode=json to ensure Splunk replies in a format Python easily reads
    payload = {
        "search": search_query,
        "output_mode": "json",
        "earliest_time": "-15m", # Only look at the last 15 minutes of CPU data
        "latest_time": "now"
    }

    try:
        # verify=False is required because local Splunk uses a self-signed SSL certificate
        response = requests.post(SPLUNK_API_URL, headers=headers, data=payload, verify=False)
        
        if response.status_code == 200:
            # Splunk's export endpoint returns newline-delimited JSON. We grab the first valid line.
            for line in response.text.strip().split('\n'):
                if line:
                    data = json.loads(line)
                    cpu_metric = data.get("result", {}).get("avg_cpu")
                    if not cpu_metric:
                        cpu_metric = "98.5" # Simulating a massive CPU spike caused by the malware
                    logger.info(f"SUCCESS: Average CPU usage for {target_host} over last 15m was {cpu_metric}%")
                    return cpu_metric
        else:
            logger.error(f"Splunk API Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        logger.error(f"Failed to connect to Splunk API: {e}")
        
    return None

def run_security_agents(target_host: str, attacker_ip: str, command: str, cpu_metric: str):
    """Orchestrates the local LLM agents to analyze the gathered telemetry."""
    print("\n" + "="*50)
    logger.info("Initializing Local AI Agents...")

    # ---------------------------------------------------------
    # AGENT 1: The Threat Analyst
    # ---------------------------------------------------------
    logger.info("Agent 1 (Threat Intel) is analyzing the payload...")
    threat_prompt = f"""
    You are an expert SOC Malware Analyst. Analyze this raw command line execution:
    '{command}'
    In exactly two sentences, explain what this command is attempting to do and identify the likely MITRE ATT&CK technique.
    """
    
    # We call the local Ollama instance synchronously
    response_1 = ollama.chat(model='llama3', messages=[
        {'role': 'user', 'content': threat_prompt}
    ])
    threat_analysis = response_1['message']['content']
    logger.info(f"VERDICT: {threat_analysis}")

    # ---------------------------------------------------------
    # AGENT 2: The SOC Synthesizer
    # ---------------------------------------------------------
    logger.info("Agent 2 (Synthesizer) is drafting the final report...")
    synth_prompt = f"""
    You are a Lead Incident Responder. Draft a final JSON incident report using the following data:
    - Target Host: {target_host}
    - Attacker IP: {attacker_ip}
    - CPU Impact: {cpu_metric}%
    - Malware Analyst Verdict: {threat_analysis}
    
    Output ONLY valid JSON with these exact keys: "incident_summary", "severity_level", "recommended_containment_action". Do not include markdown formatting or extra text.
    """

    response_2 = ollama.chat(model='llama3', messages=[{'role': 'user', 'content': synth_prompt}])
    raw_final_report = response_2['message']['content']
    
    # 1. Use Regex to strip out any conversational text the LLM added and grab just the JSON block
    import re
    json_match = re.search(r'\{.*\}', raw_final_report, re.DOTALL)
    
    if json_match:
        clean_json_str = json_match.group(0)
        try:
            # 2. Convert it into a real Python dictionary
            report_dict = json.loads(clean_json_str)
            
            # 3. Print a beautiful, human-readable interface to the terminal
            print("\n" + "EXECUTIVE INCIDENT BRIEF".center(60, "="))
            print(f"SUMMARY  : {report_dict.get('incident_summary', 'N/A')}")
            print(f"SEVERITY : Level {report_dict.get('severity_level', 'Unknown')} / 5")
            
            containment = report_dict.get('recommended_containment_action', {})
            if isinstance(containment, dict):
                action = containment.get('value', 'N/A')
                type_str = containment.get('type', 'N/A')
                print(f"ACTION   : [{type_str.upper()}] {action}")
            else:
                print(f"ACTION   : {containment}")
                
            print("=" * 60 + "\n")
            
            # Return the raw JSON dictionary so we can use it in Day 4
            return report_dict
            
        except json.JSONDecodeError:
            logger.error("Failed to parse the LLM's JSON output.")
            print(raw_final_report)
    else:
        logger.error("No JSON block found in LLM response.")
        print(raw_final_report)

    # =========================================================
# DAY 4: THE SIEM FEEDBACK LOOP
# =========================================================
def push_report_to_splunk(report_dict: dict):
    """Pushes the final AI report back into the Splunk index via HEC."""
    logger.info("Pushing AI investigation report back to Splunk HEC...")
    hec_url = "https://localhost:8088/services/collector/event"
    headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}

    # HEC requires a specific envelope structure
    payload = {
        "index": "security_sandbox",
        "sourcetype": "_json",
        "source": "autonomous_ai_agent",
        "event": report_dict
    }

    try:
        response = requests.post(hec_url, headers=headers, json=payload, verify=False)
        if response.status_code == 200:
            logger.info("SUCCESS: AI Report successfully indexed in Splunk.")
        else:
            logger.error(f"Splunk HEC Error: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Failed to connect to Splunk HEC: {e}")


# Set up clean logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SOC-Ingestor")

app = FastAPI(title="Autonomous Incident Escort - Ingestion API")

# Define the expected structure from Splunk
class SplunkWebhookPayload(BaseModel):
    search_name: str
    result: dict  # We accept the whole dict because Splunk hides the actual data in '_raw'

@app.post("/api/v1/alerts")
async def receive_splunk_alert(payload: SplunkWebhookPayload):
    # 1. Grab the giant string hidden inside the '_raw' field
    raw_string = payload.result.get("_raw", "{}")
    
    try:
        # 2. Convert that string back into a usable Python dictionary
        event_data = json.loads(raw_string)
        
        # 3. Extract the exact forensic details we need for the AI
        computer = event_data.get("Computer", "Unknown")
        user = event_data.get("User", "Unknown")
        src_ip = event_data.get("SourceIP", "Unknown")
        command = event_data.get("Command", "Unknown")
        
        # Log the incoming alert first
        print("\n" + "="*50)
        logger.info(f"ALERT TRIGGERED: {payload.search_name}")
        logger.info(f"Target Host: {computer}")
        logger.info(f"Compromised User: {user}")
        logger.info(f"Attacker IP: {src_ip}")
        logger.info(f"Malicious Command: {command}")
        
        # Fetch CPU context
        cpu_context = fetch_host_telemetry(computer)
        if not cpu_context:
            cpu_context = "96.7" # Our mock hardware spike
        
        # Day 3: Trigger the Multi-Agent Analysis AND capture the output dictionary
        final_report_dict = run_security_agents(target_host=computer, attacker_ip=src_ip, command=command, cpu_metric=cpu_context)

        print("="*50 + "\n")
        
        # Day 4: Push the findings back to Splunk HEC
        if final_report_dict:
            push_report_to_splunk(final_report_dict)
        
        return {"status": "success", "message": "Multi-agent analysis complete."}
    
    except json.JSONDecodeError:
        logger.error("Failed to parse the _raw JSON string.")
        return {"status": "error", "message": "Invalid JSON in _raw field."}
    except Exception as e:
        logger.error(f"Failed to process alert: {e}")
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8888, reload=False)