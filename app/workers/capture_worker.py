"""
app/workers/capture_worker.py

A QThread worker that captures network traffic in real-time using Scapy.
Includes THROTTLING and LIGHTWEIGHT ANOMALY DETECTION.
"""

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import sniff, conf
import logging
import time
import binascii

# Configure logging
logger = logging.getLogger(__name__)

class CaptureWorker(QThread):
    """
    Runs a packet capture on a specified interface.
    Emits 'packet_captured' signal for each packet processed.
    """
    packet_captured = pyqtSignal(dict)
    capture_finished = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, interface, bpf_filter=""):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.is_running = True
        self._packet_count = 0
        self._last_emit_time = 0

    def run(self):
        logger.info(f"Starting capture on {self.interface} with filter '{self.bpf_filter}'")
        self.is_running = True
        self._packet_count = 0
        self._last_emit_time = 0
        
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda x: not self.is_running
            )
        except Exception as e:
            logger.error(f"Capture failed: {e}")
            self.error_occurred.emit(str(e))
        
        logger.info("Capture worker thread finished.")
        self.capture_finished.emit()

    def stop(self):
        self.is_running = False

    def _process_packet(self, packet):
        if not self.is_running: return

        # --- Throttling: Max 20 updates/sec ---
        current_time = time.time()
        if current_time - self._last_emit_time < 0.05:
            return 
        self._last_emit_time = current_time

        try:
            self._packet_count += 1
            
            # 1. Basic Info
            pkt_info = {
                'no': self._packet_count,
                'time': time.strftime('%H:%M:%S', time.localtime(packet.time)),
                'src': "Unknown",
                'dst': "Unknown",
                'proto': "Unknown",
                'info': packet.summary(),
                'payload': "",
                'alert': None, # New field for anomalies
                'color': None  # New field for UI coloring
            }

            # 2. Layer Parsing
            if packet.haslayer('IP'):
                pkt_info['src'] = packet['IP'].src
                pkt_info['dst'] = packet['IP'].dst
                pkt_info['proto'] = "IP"
            elif packet.haslayer('IPv6'):
                pkt_info['src'] = packet['IPv6'].src
                pkt_info['dst'] = packet['IPv6'].dst
                pkt_info['proto'] = "IPv6"
            elif packet.haslayer('ARP'):
                pkt_info['src'] = packet['ARP'].psrc
                pkt_info['dst'] = packet['ARP'].pdst
                pkt_info['proto'] = "ARP"
                pkt_info['color'] = "#ffebcd" # Blanched Almond (Light Orange)

            # 3. Protocol Refinement & Anomaly Detection
            if packet.haslayer('TCP'): 
                pkt_info['proto'] = 'TCP'
                pkt_info['color'] = "#e6e6fa" # Lavender
                
                # Check for suspicious TCP Flags
                flags = packet['TCP'].flags
                if flags == 0: 
                    pkt_info['alert'] = "NULL Scan Detected"
                    pkt_info['color'] = "#ff4500" # Orange Red
                elif flags == 0x29: # FIN, PSH, URG
                    pkt_info['alert'] = "Xmas Scan Detected"
                    pkt_info['color'] = "#ff4500"

            elif packet.haslayer('UDP'): 
                pkt_info['proto'] = 'UDP'
                pkt_info['color'] = "#f0f8ff" # Alice Blue
                
            elif packet.haslayer('ICMP'): 
                pkt_info['proto'] = 'ICMP'
                pkt_info['color'] = "#ffe4e1" # Misty Rose

            # 4. Payload Analysis (Lightweight DPI)
            try:
                raw_bytes = bytes(packet)
                hex_str = binascii.hexlify(raw_bytes).decode('utf-8')
                pkt_info['payload'] = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
                
                # Check for cleartext credentials in raw payload
                ascii_payload = str(raw_bytes)
                if "Authorization: Basic" in ascii_payload:
                    pkt_info['alert'] = "Plaintext Auth Found!"
                    pkt_info['color'] = "#ff0000" # Bright Red
                elif "password" in ascii_payload.lower():
                    pkt_info['alert'] = "Possible Credential Leak"
                    pkt_info['color'] = "#ff0000"

            except:
                pkt_info['payload'] = "[Error extracting payload]"

            self.packet_captured.emit(pkt_info)

        except Exception as e:
            logger.debug(f"Error processing packet: {e}")
