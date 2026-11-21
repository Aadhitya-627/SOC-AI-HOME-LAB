# SOC AI Home Lab

A self-hosted Security Operations Center (SOC) home lab combining security monitoring, network asset visibility, Grafana dashboards, and local AI-assisted alert investigation.

## Overview

This project demonstrates how open-source security tools can be integrated into a small SOC environment.

The lab uses Wazuh for security monitoring, NetAlertX for network asset discovery, Grafana for visualization, and Ollama to run a local AI model that assists with reviewing security alerts.

The AI component generates investigation summaries and recommendations. All findings require human review.

## Architecture

### Core components

| Component | Purpose |
|---|---|
| Wazuh | Security monitoring and alert generation |
| NetAlertX | Network asset discovery and visibility |
| Grafana | SOC dashboards and visualization |
| Ollama | Local AI model runtime |
| AI Analyst | Manual AI-assisted Wazuh alert analysis |
| AI Report Server | Makes the latest AI report available to Grafana |
| Health Monitor | Reports the status of SOC services |

See [Architecture Documentation](docs/architecture.md).

## Key Features

- Centralized security monitoring using Wazuh.
- Network asset visibility using NetAlertX.
- Grafana SOC dashboard.
- Local AI-assisted security alert investigation.
- JSON-based AI investigation reports.
- Human-review status for AI-generated findings.
- SOC infrastructure health monitoring.
- Local deployment without relying on a hosted AI API.

## AI Alert Investigation Workflow

1. Wazuh generates a security alert.
2. An analyst provides the alert JSON file.
3. The AI Analyst extracts selected event fields.
4. The event is sent to a locally running Ollama model.
5. The model generates a concise investigation summary.
6. The result is saved as a JSON report.
7. The report server provides the latest report to Grafana.

**Important:** AI analysis is manually triggered. It is not an autonomous incident-response system.

## Technology Stack

- Kali Linux
- Docker and Docker Compose
- Wazuh
- NetAlertX
- Grafana
- Ollama
- Qwen3 1.7B
- Python 3
- JSON

## Repository Structure

```text
SOC-AI-HOME-LAB/
├── ai-analyst/
│   ├── analyze_alert.py
│   └── report_server.py
├── health/
│   └── health_server.py
├── docs/
│   └── architecture.md
├── examples/
│   └── sample-ai-report.json
├── .gitignore
├── requirements.txt
└── README.md
```

## Requirements

- Linux environment (Kali Linux used in this lab)
- Python 3
- Docker and Docker Compose
- Wazuh deployment
- NetAlertX
- Grafana
- Ollama
- A compatible local AI model

Python scripts use the standard library, so no third-party Python packages are currently required.

## Installation

Clone the repository:

```bash
git clone https://github.com/Aadhitya-627/SOC-AI-HOME-LAB.git
cd SOC-AI-HOME-LAB
```

Install and configure Ollama separately, then download the model:

```bash
ollama pull qwen3:1.7b
```

Prepare an input alert file:

```text
ai-analyst/input/alert.json
```

Run the AI analyst:

```bash
python3 ai-analyst/analyze_alert.py
```

Run the report server:

```bash
python3 ai-analyst/report_server.py
```

Run the health monitor:

```bash
python3 health/health_server.py
```

The servers use environment variables for their network and directory settings. Configure them for your own Docker environment before connecting Grafana.

## Example Output

A sanitized example report is available at:

[`examples/sample-ai-report.json`](examples/sample-ai-report.json)

## Security and Limitations

- AI-generated findings are advisory, not verified security conclusions.
- Human review is required for every AI investigation.
- No automatic blocking or remediation is performed.
- AI analysis is manually triggered.
- Docker containers without health checks are reported as running rather than application-ready.
- The AI report server health check verifies TCP connectivity, not report validity.
- Configure network addresses and container names for your environment.
- Do not publish credentials, API tokens, private keys, real security logs, or private configuration files.

## Learning Outcomes

This project demonstrates practical experience with:

- SIEM deployment and security monitoring.
- Linux administration.
- Docker-based service deployment.
- Network asset visibility.
- Grafana dashboards.
- Local AI model integration.
- Python automation and JSON processing.
- Security alert investigation and human-in-the-loop workflows.

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes in an authorized lab environment.

## Author

**Aadhitya-627**

GitHub: https://github.com/Aadhitya-627
