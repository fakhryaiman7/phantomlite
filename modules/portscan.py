"""
PhantomLite Port Scanner Module
Asynchronous port scanner to identify common open ports and services.
"""
import asyncio
import socket
from typing import List, Dict, Set, Optional
from dataclasses import dataclass


@dataclass
class PortResult:
    port: int
    state: str  # 'open', 'closed', 'filtered'
    service: str = "unknown"
    banner: str = ""


class PortScanner:
    COMMON_PORTS = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        111: "rpcbind",
        135: "msrpc",
        139: "netbios-ssn",
        143: "imap",
        443: "https",
        445: "microsoft-ds",
        993: "imaps",
        995: "pop3s",
        1723: "pptp",
        3306: "mysql",
        3389: "ms-wbt-server",
        5432: "postgresql",
        5900: "vnc",
        8080: "http-proxy",
        8443: "https-proxy",
        9000: "php-fpm",
        9090: "zeus-admin",
        27017: "mongodb"
    }
    
    def __init__(self, timeout: float = 1.5, logger=None):
        self.timeout = timeout
        self.logger = logger
        self.results: List[PortResult] = []
    
    async def scan_port(self, host: str, port: int) -> Optional[PortResult]:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            
            service = self.COMMON_PORTS.get(port, "unknown")
            banner = ""
            
            # Simple banner grabbing for some services
            try:
                if port in [21, 22, 25, 110, 143]:
                    banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                    banner = banner_data.decode('utf-8', errors='ignore').strip()
            except:
                pass
            
            writer.close()
            await writer.wait_closed()
            
            return PortResult(port=port, state='open', service=service, banner=banner)
            
        except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror):
            return None
        except Exception:
            return None
    
    async def scan_host(self, host: str, ports: List[int] = None) -> List[PortResult]:
        if not ports:
            ports = list(self.COMMON_PORTS.keys())
            
        if self.logger:
            self.logger.scan(f"Scanning {len(ports)} ports on {host}...")
            
        tasks = [self.scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = [r for r in results if r is not None]
        self.results.extend(open_ports)
        
        if self.logger and open_ports:
            self.logger.success(f"Found {len(open_ports)} open ports on {host}")
            
        return open_ports


async def scan_ports(host: str, ports: List[int] = None, logger=None) -> List[PortResult]:
    scanner = PortScanner(logger=logger)
    return await scanner.scan_host(host, ports)
