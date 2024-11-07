import socket
import json
import concurrent.futures
from typing import Dict, List, Optional
import os
import argparse
import time
from datetime import datetime

class PortScanner:
    def __init__(self):
        """Initialize scanner"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        ports_file = os.path.join(script_dir, "ports.json")
            
        try:
            with open(ports_file) as f:
                data = json.load(f)
                self.ports_data = data["ports"]
                print(f"Loaded {len(self.ports_data)} port entries")
        except Exception as e:
            print(f"Warning: Could not load ports data: {e}")
            self.ports_data = {}

    def get_service(self, port: int) -> str:
        """Get service name for a port number"""
        port_str = str(port)
        try:
            if port_str in self.ports_data:
                port_info = self.ports_data[port_str]
                if isinstance(port_info, list):
                    info = port_info[0]
                else:
                    info = port_info
                return info.get("description", "Unknown")
        except (KeyError, IndexError):
            pass
        return "Unknown"

    def check_port(self, host: str, port: int) -> Dict:
        """Check if a port is open"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        
        try:
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service = self.get_service(port)
                print(f"Found open port {port}: {service}")
                return {
                    "port": port,
                    "status": "OPEN",
                    "service": service
                }
        except (socket.timeout, socket.error):
            pass
        finally:
            sock.close()
            
        return {
            "port": port,
            "status": "CLOSED",
            "service": self.get_service(port)
        }

    def scan(self, host: str, start_port: int = 1, end_port: int = 65535, threads: int = 16) -> List[Dict]:
        """Scan port range for open ports"""
        results = []
        ports_scanned = 0
        total_ports = end_port - start_port + 1
        start_time = time.time()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_port = {
                    executor.submit(self.check_port, host, port): port 
                    for port in range(start_port, end_port + 1)
                }
                
                for future in concurrent.futures.as_completed(future_to_port):
                    try:
                        result = future.result()
                        ports_scanned += 1
                        
                        if ports_scanned % 1000 == 0:
                            elapsed = time.time() - start_time
                            rate = ports_scanned / elapsed
                            progress = (ports_scanned / total_ports) * 100
                            print(f"Progress: {progress:.1f}% ({ports_scanned}/{total_ports} ports) "
                                  f"- {rate:.0f} ports/sec")
                        
                        if result["status"] == "OPEN":
                            results.append(result)
                    except Exception as e:
                        port = future_to_port[future]
                        print(f"Error scanning port {port}: {e}")

        except KeyboardInterrupt:
            print("\nScan interrupted by user. Processing results...")
            
        return sorted(results, key=lambda x: x["port"])

def generate_html_report(results: List[Dict], host: str, start_time: datetime, end_time: datetime) -> str:
    """Generate HTML report of scan results"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Port Scan Report - {host}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            .header {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Port Scan Report</h1>
            <p>Target Host: {host}</p>
            <p>Start Time: {start_time}</p>
            <p>End Time: {end_time}</p>
            <p>Duration: {(end_time - start_time).total_seconds():.2f} seconds</p>
        </div>
        <table>
            <tr>
                <th>Port</th>
                <th>Status</th>
                <th>Service</th>
            </tr>
    """
    
    for result in results:
        html += f"""
            <tr>
                <td>{result['port']}</td>
                <td>{result['status']}</td>
                <td>{result['service']}</td>
            </tr>
        """
        
    html += """
        </table>
    </body>
    </html>
    """
    return html

def main():
    parser = argparse.ArgumentParser(description='TCP Port Scanner')
    parser.add_argument('host', help='Target host to scan')
    parser.add_argument('-p', '--ports', help='Port range (e.g., 1-1024)', default='1-65535')
    parser.add_argument('-t', '--threads', type=int, help='Number of threads', default=16)
    parser.add_argument('-o', '--output', help='Output file (supports .txt or .html)')
    
    args = parser.parse_args()
    start_port, end_port = map(int, args.ports.split('-'))
    scanner = PortScanner()
    
    start_time = datetime.now()
    print(f"Starting scan of {args.host} at {start_time}")
    
    try:
        results = scanner.scan(args.host, start_port, end_port, args.threads)
        end_time = datetime.now()
        
        if not results:
            print("No open ports found")
            return
            
        # Generate reports
        if args.output:
            if args.output.endswith('.html'):
                html_content = generate_html_report(results, args.host, start_time, end_time)
                with open(args.output, 'w') as f:
                    f.write(html_content)
            else:
                with open(args.output, 'w') as f:
                    f.write(f"Port Scan Report for {args.host}\n")
                    f.write(f"Scan Time: {start_time} to {end_time}\n\n")
                    for result in results:
                        f.write(f"Port {result['port']}: {result['status']} - {result['service']}\n")
            print(f"\nResults written to {args.output}")
            
        # Always print to console
        print("\nOpen ports:")
        for result in results:
            print(f"Port {result['port']}: {result['service']}")
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")

if __name__ == "__main__":
    main()