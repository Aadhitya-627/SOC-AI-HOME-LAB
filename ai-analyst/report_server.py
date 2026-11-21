import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPORT_DIR = Path(
    os.getenv("SOC_REPORT_DIR", Path(__file__).resolve().parent / "reports")
)

HOST = os.getenv("SOC_SERVER_HOST", "127.0.0.1")
PORT = int(os.getenv("SOC_REPORT_PORT", "8088"))
ALLOWED_CLIENT = os.getenv("SOC_ALLOWED_CLIENT", "127.0.0.1")

class ReportHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.client_address[0] != ALLOWED_CLIENT:
            self.send_error(403, "Access denied")
            return

        if self.path != "/latest.json":
            self.send_error(404, "Not found")
            return

        files = sorted(
            REPORT_DIR.glob("analysis-*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True
        )

        if not files:
            self.send_error(404, "No AI reports available")
            return

        try:
            report = json.loads(files[0].read_text())
            alert = report.get("alert", {})
            rule = alert.get("rule", {})

            # Expose only the fields needed by Grafana.
            row = {
                "generated_at": report.get("generated_at"),
                "event_timestamp": alert.get("timestamp"),
                "rule_id": rule.get("id"),
                "rule_level": rule.get("level"),
                "rule_description": rule.get("description"),
                "agent_name": (alert.get("agent") or {}).get("name"),
                "analysis": report.get("analysis"),
                "review_status": report.get("review_status"),
                "generation_time_seconds":
                    report.get("generation_time_seconds")
            }

            body = json.dumps({"reports": [row]}).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        except (OSError, ValueError, TypeError):
            self.send_error(500, "Could not read latest report")

    def log_message(self, format, *args):
        print(f"{self.client_address[0]} - {format % args}")


print(f"AI report endpoint: http://{HOST}:{PORT}/latest.json")
print("Access restricted to the Grafana container.")

server = ThreadingHTTPServer((HOST, PORT), ReportHandler)
server.serve_forever()
