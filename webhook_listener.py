#!/usr/bin/env python3
import sys
import secrets
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import json

# --- CONFIGURATION ---
HOST = "0.0.0.0"
PORT = 8000

# 1. Define all valid tokens (e.g., for key rotation or multiple projects)
SECRET_TOKENS = [
    "ac3bc73bc9e6cfc1db21e3785cc1f69a",
    "c8ca267cb0e3167ee2bc32f78da3abd3"
]

# 2. Map specific endpoints to their hardcoded allowed commands
COMMAND_ROUTER = {
    "/automation/LinuxValidation": ["/opt/automation/LinuxValidation.sh"],
    "/automation/CiscoValidation": ["/opt/automation/CiscoValidation.sh"]
}
# ---------------------

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # 1. Validate Secret Token against the allowed list (Mitigates Timing Attacks)
        auth_header = self.headers.get("X-Webhook-Secret", "")
        
        # Check if the header matches *any* token in our allowed list safely
        is_authenticated = any(secrets.compare_digest(auth_header, token) for token in SECRET_TOKENS)
        
        if not is_authenticated:
            self.send_json_response(418 if auth_header == "" else 401, {"error": "Unauthorized"})
            return

        # 2. Route request based on the path
        # self.path extracts the endpoint (e.g., "/automation/deploy")
        if self.path not in COMMAND_ROUTER:
            self.send_json_response(404, {"error": f"Endpoint '{self.path}' not found or not mapped to a command."})
            return
            
        allowed_command = COMMAND_ROUTER[self.path]

        # 3. Process Request
        try:
            result = subprocess.run(
                allowed_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                close_fds=True,
            )
            
            response_data = {
                "status": "success" if result.returncode == 0 else "failed",
                "return_code": result.returncode,
                "stdout": result.stdout.strip() if result.stdout.strip() else "No output returned",
                "stderr": result.stderr.strip()
            }
            status_code = 200 if result.returncode == 0 else 500

        except subprocess.TimeoutExpired:
            response_data = {"status": "error", "message": "Command timed out"}
            status_code = 504
        except Exception as e:
            response_data = {"status": "error", "message": str(e)}
            status_code = 500

        # 4. Send Response back to Jira
        self.send_json_response(status_code, response_data)

    def send_json_response(self, status_code, data):
        """Helper to safely format and send JSON responses."""
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
        except Exception as e:
            print(f"Error sending response: {e}")

def run():
    # SWAP HTTPServer for ThreadingHTTPServer
    server = ThreadingHTTPServer((HOST, PORT), WebhookHandler)
    print(f"Webhook Listener running on port {PORT}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    run()
