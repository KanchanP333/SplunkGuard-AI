# Autonomous Incident Escort - Splunk Hackathon

[![Demo](https://img.shields.io/badge/SplunkGuard--AI-green)](https://drive.google.com/file/d/1xljIaf49VBCmZU_e_JVlPGMlxlGRfz4A/view?usp=sharing)

An intelligent incident response system that orchestrates local AI agents to analyze security threats in real-time. This application integrates Splunk observability data with a multi-agent LLM system to provide automated threat analysis and incident reporting.

## Project Overview

This project automates the incident response workflow by combining:
- **Splunk Integration**: Fetches telemetry data (CPU metrics, event logs) from Splunk
- **Multi-Agent AI System**: Deploys specialized AI agents for threat analysis
- **Real-time Response**: Analyzes security alerts and generates actionable incident reports
- **Feedback Loop**: Pushes findings back to Splunk for correlation and auditing

## Key Features

- **Threat Analyst Agent**: Analyzes suspicious command executions and identifies MITRE ATT&CK techniques
- **SOC Synthesizer Agent**: Generates comprehensive JSON incident reports with severity and containment actions
- **Telemetry Integration**: Correlates CPU metrics and observability data with security events
- **Splunk Webhook Integration**: Receives alerts via Splunk webhook callbacks
- **HEC Publishing**: Pushes generated reports back to Splunk for indexing and alerting

## Architecture

```
Splunk Alert → FastAPI Endpoint → Fetch Telemetry → Multi-Agent Analysis → Push Report to Splunk
                                                           ↓
                                              Threat Analyst Agent (Ollama)
                                              SOC Synthesizer Agent (Ollama)
```

### Workflow Steps

1. **Alert Reception**: Splunk sends a webhook alert to `/api/v1/alerts`
2. **Context Gathering**: Queries Splunk for recent CPU and system metrics
3. **Threat Analysis**: 
   - Agent 1 analyzes the malicious command and maps to MITRE ATT&CK
   - Agent 2 synthesizes findings into a formal incident report
4. **Report Publishing**: Pushes JSON report to Splunk HEC for indexing
5. **Executive Summary**: Displays formatted incident brief in terminal

## Prerequisites

- **Python 3.8+**
- **Splunk Instance** (with Search API and HEC enabled)
- **Ollama** (with llama3 model installed)
- **Local Network Access**: FastAPI server must be reachable by Splunk

## Installation

### 1. Clone or download the project

```bash
cd splunk-hackathon
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install and run Ollama

Download from [ollama.ai](https://ollama.ai) and ensure the llama3 model is available:

```bash
ollama pull llama3
ollama serve
```

## ⚙️ Configuration

Edit `app.py` and update the following constants:

```python
SPLUNK_TOKEN = "your-splunk-auth-token"  # Your Splunk API token
SPLUNK_HEC_TOKEN = "your-hec-token"      # Splunk HTTP Event Collector token
SPLUNK_API_URL = "https://localhost:8089/services/search/jobs/export"  # Splunk search endpoint
```

### Obtaining Tokens

1. **SPLUNK_TOKEN**: Create an auth token in Splunk → Settings → Tokens → Create New Token
2. **SPLUNK_HEC_TOKEN**: Set up an HEC input in Splunk → Settings → Data Inputs → HTTP Event Collector

## 🚀 Running the Application

```bash
python app.py
```

The API will start on `http://localhost:8888`

## 📡 API Endpoints

### POST `/api/v1/alerts`

Receives security alerts from Splunk and triggers the multi-agent analysis.

**Request Body:**
```json
{
  "search_name": "Suspicious Command Execution",
  "result": {
    "_raw": "{\"Computer\": \"workstation-01\", \"User\": \"admin\", \"SourceIP\": \"192.168.1.100\", \"Command\": \"powershell.exe -EncodedCommand ...\"}",
    "timestamp": "2026-06-15T10:30:00Z"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Multi-agent analysis complete."
}
```

## AI Agents

### Agent 1: Threat Analyst
- **Role**: Malware analysis expert
- **Task**: Analyzes command line execution and identifies MITRE ATT&CK techniques
- **Output**: 2-sentence verdict

### Agent 2: SOC Synthesizer
- **Role**: Incident response leader
- **Task**: Synthesizes all findings into a formal JSON report
- **Output**: JSON with incident_summary, severity_level (1-5), and recommended_containment_action

## Expected Output

When an alert is processed, the application prints an executive incident brief:

```
======================================EXECUTIVE INCIDENT BRIEF 🚨======================================
SUMMARY  : Adversary deployed a command injection attack targeting process execution on workstation-01
SEVERITY : Level 4 / 5
ACTION   : [IMMEDIATE] Isolate compromised host from network and preserve memory dump
============================================================
```
## 📊 Splunk Frontend Dashboard

The project includes a dedicated, real-time security triage dashboard built inside **Splunk Dashboard Studio** (Absolute Layout). This interface acts as the primary glass pane for security analysts, transforming the AI's raw JSON telemetry backend into a clean corporate ledger.

### Dashboard Architecture & Data Parsing
Because the Python feedback loop pushes data back via the HTTP Event Collector (HEC) using `source="autonomous_ai_agent"` and `sourcetype="_json"`, Splunk natively strips out the nested JSON objects. 

This architectural choice eliminates the need for complex field extractions, evaluations, or regex operations within the dashboard itself. Data is pulled efficiently and loaded directly into three custom visualization modules.

### Component Configuration

#### 1. Total Autonomous Investigations (Single Value Module)
Provides an executive count of how many automated triage jobs the multi-agent pipeline has executed.
- **Data Source Name**: `Total_AI_Count`
- **SPL Query**:
  ```spl
  index="security_sandbox" source="autonomous_ai_agent" | stats count

## Security Considerations

- **SSL Warnings**: The code suppresses warnings for self-signed Splunk certificates (localhost only)
- **Token Management**: Store tokens in environment variables or secure vaults in production
- **Network Security**: Ensure the API endpoint is only accessible from your Splunk instance
- **LLM Safety**: Review LLM-generated recommendations before taking containment actions

## Logs

Logs are output to the console with timestamps and severity levels:

```
2026-06-15 10:30:45,123 [INFO] ALERT TRIGGERED: Suspicious Command Execution
2026-06-15 10:30:46,456 [INFO] Hunting for Observability telemetry on host: workstation-01...
2026-06-15 10:30:47,789 [INFO] Agent 1 (Threat Intel) is analyzing the payload...
```

## Testing

To test the API locally, you can send a test alert:

```bash
curl -X POST http://localhost:8888/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "search_name": "Test Alert",
    "result": {
      "_raw": "{\"Computer\": \"test-host\", \"User\": \"testuser\", \"SourceIP\": \"10.0.0.1\", \"Command\": \"whoami\"}"
    }
  }'
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Connection refused to Splunk API | Verify SPLUNK_API_URL and firewall rules; ensure SSL certificate is trusted |
| Ollama connection error | Ensure `ollama serve` is running on localhost:11434 |
| JSON parsing errors | Check that Splunk _raw field contains valid JSON |
| HEC token rejected | Verify SPLUNK_HEC_TOKEN and HEC input configuration |

## Requirements

See `requirements.txt` for full dependency list:
- **fastapi**: Web framework for API endpoints
- **pydantic**: Data validation and modeling
- **uvicorn**: ASGI application server
- **requests**: HTTP client for Splunk API calls
- **urllib3**: Advanced HTTP client library
- **ollama**: Python client for local LLM inference

## Learning Resources

- [Splunk REST API Documentation](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTprolog)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Ollama Documentation](https://ollama.ai/docs)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

## License

This project is created for the Splunk Hackathon and is provided as-is.

---

**Note**: This is a proof-of-concept system. For production use, implement proper error handling, authentication, rate limiting, and audit logging.
