# SOC AI Home Lab Architecture

## Overview

This project combines open-source security monitoring tools with
a locally hosted AI assistant for alert investigation.

## Components

- Wazuh: Security event collection, monitoring and alert generation.
- NetAlertX: Local network asset discovery and visibility.
- Grafana: SOC dashboard and visualization.
- Ollama: Local AI model runtime.
- AI Analyst: Reads a Wazuh alert JSON file and generates an advisory analysis.
- AI Report Server: Provides the latest AI report to Grafana.
- Health Monitor: Reports the operational status of SOC services.

## AI Analysis Workflow

1. Wazuh generates a security alert.
2. An analyst supplies the alert JSON to the AI Analyst.
3. The script extracts selected event fields.
4. The event is sent to a local Ollama model.
5. The generated analysis is saved as a JSON report.
6. The AI Report Server exposes the latest report.
7. Grafana displays the analysis and review status.

## Health Monitoring Workflow

1. The Health Monitor checks configured Docker containers.
2. It checks the Ollama system service.
3. It checks connectivity to the AI Report Server.
4. It returns service statuses as JSON.
5. Grafana displays the health information.

## Important Limitations

- AI analysis is manually triggered.
- AI output is advisory and requires human review.
- No automatic blocking, remediation or incident response is performed.
- Containers without Docker health checks are reported as running,
  not necessarily application-ready.
- AI Report Server health checks verify TCP connectivity, not report validity.
- Network addresses and container names must be configured for each environment.
