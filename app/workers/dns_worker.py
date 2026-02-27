"""
app/workers/dns_worker.py

A QThread worker that performs DNS lookups.
Features:
- Supports specific types (A, AAAA, MX...) or "ALL".
- Auto-detects IP addresses for Reverse DNS (PTR).
- Clean output with ELABORATED, ALIGNED column headers.
"""

from PyQt5.QtCore import QThread, pyqtSignal
import socket
import logging
import ipaddress

# Try to import dnspython
try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger(__name__)

class DNSLookupWorker(QThread):
    result_ready = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, query_input, record_type="A"):
        super().__init__()
        self.query_input = query_input.strip()
        self.record_type = record_type

    def run(self):
        logger.info(f"DNS Lookup: {self.query_input} ({self.record_type})")
        output = []

        if not self.query_input:
            self.error_occurred.emit("Please enter a valid domain or IP.")
            return

        # 1. Check if input is an IP address (Reverse Lookup)
        is_ip = False
        try:
            ipaddress.ip_address(self.query_input)
            is_ip = True
        except ValueError:
            is_ip = False

        # 2. Determine what queries to run
        queries_to_run = []
        
        if is_ip:
            # If it's an IP, we MUST do a PTR lookup, ignore dropdown choice
            queries_to_run.append(('PTR', self.query_input))
            output.append(f"; Performing Reverse DNS (PTR) for {self.query_input}...")
        elif self.record_type == "ALL":
            # Run common types
            for t in ["A", "AAAA", "MX", "NS", "TXT"]:
                queries_to_run.append((t, self.query_input))
        else:
            # Run specific type
            queries_to_run.append((self.record_type, self.query_input))

        # 3. Execute Queries
        for r_type, target in queries_to_run:
            try:
                if HAS_DNSPYTHON:
                    self._query_dnspython(target, r_type, output, is_ip)
                else:
                    self._query_socket(target, r_type, output, is_ip)
            except Exception as e:
                logger.debug(f"Query failed for {r_type}: {e}")

        if not output:
            output.append("No records found.")
        else:
            # Add Elaborated Header at the top
            # We use f-string padding (:<N) to ensure alignment
            header = f"; {'DOMAIN NAME':<30} {'TIME TO LIVE':<15} {'CLASS':<10} {'RECORD TYPE':<15} {'DATA / ANSWER'}"
            output.insert(0, header)
            output.insert(1, "-" * 90) # Longer separator line

        self.result_ready.emit("\n".join(output))

    def _query_dnspython(self, target, r_type, output, is_ip):
        try:
            q_name = target
            if is_ip and r_type == 'PTR':
                # Convert IP '8.8.8.8' -> '8.8.8.8.in-addr.arpa'
                q_name = dns.reversename.from_address(target)
            
            answers = dns.resolver.resolve(q_name, r_type)
            
            for rdata in answers:
                # Clean format aligning with header
                # Domain Name (30) | TTL (15) | Class (10) | Type (15) | Data
                output.append(f"{target:<30} {str(answers.ttl):<15} {'IN':<10} {r_type:<15} {rdata.to_text()}")
                
        except dns.resolver.NoAnswer:
            pass 
        except dns.resolver.NXDOMAIN:
            output.append(f"; NXDOMAIN: {target} does not exist.")
        except Exception as e:
            output.append(f"; Error ({r_type}): {str(e)}")

    def _query_socket(self, target, r_type, output, is_ip):
        """Fallback if dnspython is missing."""
        # Manual alignment matching the header above
        if is_ip:
            try:
                # Reverse lookup
                host = socket.gethostbyaddr(target)[0]
                output.append(f"{target:<30} {'N/A':<15} {'IN':<10} {'PTR':<15} {host}")
            except Exception:
                output.append(f"; PTR lookup failed for {target}")
            return

        # Standard Forward Lookups
        try:
            if r_type == 'A':
                res = socket.getaddrinfo(target, None, socket.AF_INET)
                seen = set()
                for item in res:
                    ip = item[4][0]
                    if ip not in seen:
                        output.append(f"{target:<30} {'N/A':<15} {'IN':<10} {'A':<15} {ip}")
                        seen.add(ip)
            elif r_type == 'AAAA':
                res = socket.getaddrinfo(target, None, socket.AF_INET6)
                seen = set()
                for item in res:
                    ip = item[4][0]
                    if ip not in seen:
                        output.append(f"{target:<30} {'N/A':<15} {'IN':<10} {'AAAA':<15} {ip}")
                        seen.add(ip)
            else:
                output.append(f"; Type {r_type} not supported without 'dnspython' library.")
        except socket.gaierror:
            pass
