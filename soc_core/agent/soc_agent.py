import os
import sys
import time
import socket
import platform
import subprocess
import json
import asyncio
from typing import Dict, Any

# We use standard libraries to avoid external dependency issues on client machines
try:
    import urllib.request as urllib_request
except ImportError:
    import urllib2 as urllib_request

class SOCAgent:
    """SOCRoot Remote Access Agent. Runs on the client environment."""
    
    def __init__(self, server_url: str, client_id: str, secret_key: str):
        self.server_url = server_url
        self.client_id = client_id
        self.secret_key = secret_key
        self.is_running = True

    def gather_inventory(self) -> Dict[str, Any]:
        """Gather environment inventory (OS, CPU, memory, hostname, open ports)."""
        inventory = {
            "client_id": self.client_id,
            "timestamp": time.time(),
            "system": {
                "os": platform.system(),
                "os_release": platform.release(),
                "os_version": platform.version(),
                "hostname": socket.gethostname(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version()
            },
            "network": {
                "fqdn": socket.getfqdn(),
                "local_ip": self._get_local_ip()
            },
            "wazuh_agent": self._get_wazuh_status()
        }
        
        # Fast local port scanner for standard services
        inventory["network"]["open_ports"] = self._scan_local_ports([21, 22, 80, 443, 8080, 55000, 1514, 1515])
        return inventory

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_wazuh_status(self) -> Dict[str, Any]:
        """Check if Wazuh agent is installed and running."""
        status = {"installed": False, "status": "unknown"}
        # Check standard binary path or systemctl
        for path in ["/var/ossec/bin/wazuh-control", "/var/ossec/bin/ossec-control"]:
            if os.path.exists(path):
                status["installed"] = True
                break
                
        if status["installed"]:
            try:
                res = subprocess.run(["systemctl", "is-active", "wazuh-agent"], capture_output=True, text=True)
                status["status"] = res.stdout.strip()
            except Exception:
                status["status"] = "running_legacy"
        return status

    def _scan_local_ports(self, ports) -> list:
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                result = s.connect_ex(("127.0.0.1", port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
        return open_ports

    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a remote action received from the SOCRoot control plane."""
        # Simple security controls: restrict shell expansion or command types if needed
        # For full agent capability, we execute in shell safely
        try:
            print(f"[SOC Agent] Executing remote command: {command}")
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            return {
                "status": "success",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "message": "Command timed out after 30 seconds"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Execution failed: {str(e)}"
            }

    async def run(self):
        """Main event loop. Establishes WebSocket connection and processes tasks."""
        import websockets # Only import inside run so agent loading has minimal dependencies
        
        ws_url = f"{self.server_url.replace('http', 'ws')}/agent/ws/{self.client_id}"
        print(f"[SOC Agent] Connecting to control plane at {ws_url}...")
        
        while self.is_running:
            try:
                async with websockets.connect(ws_url) as websocket:
                    print("[SOC Agent] Connected successfully. Sending initial inventory...")
                    
                    # 1. Send initial inventory
                    inventory = self.gather_inventory()
                    await websocket.send(json.dumps({"action": "inventory", "data": inventory}))
                    
                    # 2. Wait for incoming commands
                    async for message in websocket:
                        payload = json.loads(message)
                        action = payload.get("action")
                        
                        if action == "execute":
                            cmd = payload.get("command")
                            res = self.execute_command(cmd)
                            # Return RPC response back
                            await websocket.send(json.dumps({
                                "status": "success",
                                "result": res
                            }))
            except Exception as e:
                print(f"[SOC Agent] Connection lost or error: {str(e)}. Reconnecting in 5 seconds...")
                await asyncio.sleep(5)

if __name__ == "__main__":
    # Standard entrypoint when executed standalone
    # Custom values are injected dynamically by the download router
    SERVER_URL = "http://localhost:8000"
    CLIENT_ID = "sample_client"
    SECRET_KEY = "sample_secret"
    
    agent = SOCAgent(SERVER_URL, CLIENT_ID, SECRET_KEY)
    asyncio.run(agent.run())
