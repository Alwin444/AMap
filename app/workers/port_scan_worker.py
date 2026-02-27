"""
app/workers/port_scan_worker.py

A QThread worker that performs a TCP Connect scan on a target IP.
Checks a list of ports to see if they are open.
FIXED: Improved banner grabbing and standard service name lookup.
"""

from PyQt5.QtCore import QThread, pyqtSignal
import socket
import logging

# Configure logging
logger = logging.getLogger(__name__)

class PortScanWorker(QThread):
    """
    Scans a list of ports on a specific target.
    Emits 'result_ready' for each port checked.
    """
    result_ready = pyqtSignal(dict) # Emits {host, port, status, banner}
    scan_finished = pyqtSignal()    # Emits when all ports are checked
    
    def __init__(self, target_ip, ports):
        super().__init__()
        self.target_ip = target_ip
        # Ensure ports is a list of integers
        self.ports = ports if isinstance(ports, list) else [] 
        self.is_running = True

    def run(self):
        logger.info(f"Starting port scan on {self.target_ip} for {len(self.ports)} ports.")
        
        for port in self.ports:
            if not self.is_running:
                break
            
            status = "Closed"
            banner = ""
            service_name = "Unknown"
            
            try:
                # 1. Get standard service name (e.g., 80 -> HTTP, 22 -> SSH)
                try:
                    service_name = socket.getservbyport(port, 'tcp').upper()
                except:
                    service_name = f"TCP/{port}"

                # 2. Create socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5) # Fast connect timeout
                
                # 3. Attempt connection
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    status = "Open"
                    
                    # 4. Advanced Banner Grabbing
                    try:
                        # Increase timeout slightly for reading data
                        sock.settimeout(1.5)
                        
                        # Method A: Passive Listen (Works for SSH, FTP, SMTP)
                        # These protocols send a "Welcome" message immediately.
                        raw_banner = sock.recv(1024)
                        
                        if not raw_banner:
                            # Method B: Active Probe (Works for HTTP)
                            # If silence, send a generic HTTP HEAD request to provoke a reply.
                            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                            raw_banner = sock.recv(1024)
                            
                        if raw_banner:
                            # Decode and clean up the banner
                            banner_text = raw_banner.decode('utf-8', errors='ignore').strip()
                            # Only take the first line to keep the table clean
                            banner = banner_text.split('\n')[0][:50] 
                    except:
                        # Connection worked, but reading failed/timed out.
                        # This is common for firewalls or silent services.
                        pass 
                
                sock.close()
                
            except Exception as e:
                logger.debug(f"Error scanning port {port}: {e}")
                status = "Error"
            
            # 5. Format the final display string
            # e.g., "SSH: SSH-2.0-OpenSSH..." or just "HTTP"
            display_banner = service_name
            if banner:
                display_banner += f": {banner}"
            
            # Emit result
            scan_result = {
                'host': self.target_ip,
                'port': port,
                'status': status,
                'banner': display_banner if status == "Open" else ""
            }
            self.result_ready.emit(scan_result)
            
        logger.info("Port scan finished.")
        self.scan_finished.emit()

    def stop(self):
        self.is_running = False
        self.wait()
