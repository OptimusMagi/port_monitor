#TODO: Port 4481 Monitor

import socket
import psutil
import time
from datetime import datetime
from typing import Dict, List
import json


class PortMonitor:
    def __init__(self, port: int = 4481):
        self.port = port
        self.connection_log = []
        self.alert_threshold = 5

    def check_port_access(self) -> Dict:
        """Check if port 4481 is being accessed"""
        try:
            # Check active connections on port 4481
            connections = psutil.net_connections()
            port_connections = [
                conn for conn in connections
                if conn.laddr.port == self.port and conn.status == 'ESTABLISHED'
            ]

            result = {
                'timestamp': datetime.now().isoformat(),
                'port': self.port,
                'active_connections': len(port_connections),
                'connections': [
                    {
                        'remote_ip': conn.raddr.ip if conn.raddr else 'Unknown',
                        'remote_port': conn.raddr.port if conn.raddr else 'Unknown',
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    for conn in port_connections
                ],
                'unauthorized_attempts': self.detect_unauthorized(port_connections)
            }

            self.connection_log.append(result)
            return result

        except Exception as e:
            return {'error': str(e), 'timestamp': datetime.now().isoformat()}

    def detect_unauthorized(self, connections: List) -> List:
        """Detect potentially unauthorized access attempts"""
        unauthorized = []
        whitelist_ips = ['192.168.1.100', '10.0.0.50']  # Your authorized IPs

        for conn in connections:
            remote_ip = conn.raddr.ip if conn.raddr else 'Unknown'
            if remote_ip not in whitelist_ips and remote_ip != 'Unknown':
                unauthorized.append({
                    'ip': remote_ip,
                    'port': conn.raddr.port if conn.raddr else 'Unknown',
                    'timestamp': datetime.now().isoformat()
                })

        return unauthorized

    def get_security_report(self) -> str:
        """Generate security report for the LLM"""
        recent_logs = self.connection_log[-10:]  # Last 10 checks

        if not recent_logs:
            return "No recent port activity detected."

        report = f"Port {self.port} Security Report:\n"
        report += f"Total checks: {len(self.connection_log)}\n"

        unauthorized_count = sum(len(log.get('unauthorized_attempts', [])) for log in recent_logs)
        report += f"Unauthorized attempts (last 10 checks): {unauthorized_count}\n"

        if unauthorized_count > 0:
            report += "RECOMMENDATION: Investigate unauthorized access attempts immediately.\n"

        return report
