import json
import os
import socket
import subprocess
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.getenv("SOC_SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SOC_HEALTH_PORT", "8089"))
ALLOWED_CLIENT = os.getenv("SOC_ALLOWED_CLIENT", "127.0.0.1")
AI_REPORT_HOST = os.getenv("SOC_AI_REPORT_HOST", "127.0.0.1")
AI_REPORT_PORT = int(os.getenv("SOC_REPORT_PORT", "8088"))

CONTAINERS = {
    "Wazuh Manager": "single-node-wazuh.manager-1",
    "Wazuh Indexer": "single-node-wazuh.indexer-1",
    "Wazuh Dashboard": "single-node-wazuh.dashboard-1",
    "Grafana": "grafana",
    "NetAlertX": "netalertx",
}


def docker_status(container):
    try:
        result = subprocess.run(
            [
                "docker", "inspect",
                "--format",
                "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}",
                container
            ],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            return "unavailable", "Container not found"

        state, health = result.stdout.strip().split("|", 1)

        if state != "running":
            return state, "Container state: " + state

        if health == "unhealthy":
            return "unhealthy", "Docker health check failed"

        if health == "starting":
            return "starting", "Health check starting"

        if health == "no-healthcheck":
            return "running", "Running; no Docker health check configured"

        return "healthy", "Docker health check passed"

    except Exception as error:
        return "unknown", str(error)


def ollama_status():
    result = subprocess.run(
        ["systemctl", "is-active", "ollama"],
        capture_output=True,
        text=True,
        timeout=5
    )
    status = result.stdout.strip()
    return status, "systemd service status: " + status


def ai_report_status():
    try:
        with socket.create_connection((AI_REPORT, AI_REPORT_PORT), timeout=3):
            return "reachable", "AI report server TCP connection successful"
    except OSError:
        return "unavailable", "AI report server connection failed"


def collect_health():
    services = []

    for name, container in CONTAINERS.items():
        status, details = docker_status(container)
        services.append({
            "service": name,
            "status": status,
            "details": details
        })

    status, details = ollama_status()
    services.append({
        "service": "Ollama",
        "status": status,
        "details": details
    })

    status, details = ai_report_status()
    services.append({
        "service": "AI Report Server",
        "status": status,
        "details": details
    })

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "services": services
    }


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.client_address[0] != ALLOWED_CLIENT:
            self.send_error(403, "Access denied")
            return

        if self.path != "/health.json":
            self.send_error(404)
            return

        data = json.dumps(collect_health(), indent=2).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        print(self.client_address[0], "-", format % args)


server = ThreadingHTTPServer((HOST, PORT), HealthHandler)

print(f"SOC health endpoint: http://{HOST}:{PORT}/health.json")
print(f"Access restricted to Grafana container: {ALLOWED_CLIENT}")

server.serve_forever()
