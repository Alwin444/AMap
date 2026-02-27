"""
app/workers/pcap_worker.py

A QThread worker that reads a PCAP file asynchronously.
Uses Scapy's PcapReader to iterate through packets without loading the whole file into RAM.
"""

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import PcapReader, conf
import logging
import time
import binascii

# Configure logging
logger = logging.getLogger(__name__)

class PcapLoaderWorker(QThread):
    """
    Reads a .pcap file and emits signal for each packet.
    """
    packet_read = pyqtSignal(dict)    # Emits processed packet data
    finished = pyqtSignal()           # Emits when file is fully read
    error_occurred = pyqtSignal(str)  # Emits if file cannot be read

    def __init__(self, filename):
        super().__init__()
        self.filename = filename
        self.is_running = True

    def run(self):
        logger.info(f"Starting PCAP load: {self.filename}")
        packet_count = 0
        
        try:
            # PcapReader is an iterator, efficient for large files
            with PcapReader(self.filename) as pcap_reader:
                for packet in pcap_reader:
                    if not self.is_running:
                        break
                    
                    packet_count += 1
                    self._process_packet(packet, packet_count)
                    
                    # Small sleep every 50 packets to prevent UI lockup during fast load
                    if packet_count % 50 == 0:
                        time.sleep(0.01)

        except Exception as e:
            logger.error(f"Error reading PCAP: {e}")
            self.error_occurred.emit(str(e))
        
        logger.info(f"Finished loading {packet_count} packets.")
        self.finished.emit()

    def stop(self):
        self.is_running = False

    def _process_packet(self, packet, count):
        """Extracts info and emits signal."""
        try:
            pkt_info = {
                'no': count,
                'time': time.strftime('%H:%M:%S', time.localtime(int(packet.time))),
                'src': "Unknown",
                'dst': "Unknown",
                'proto': "Unknown",
                'info': packet.summary(),
                'payload': "",
                'color': None,
                'alert': None
            }

            # Layer 3 (IP)
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
                pkt_info['color'] = "#ffebcd" # Light orange

            # Layer 4 (Transport)
            if packet.haslayer('TCP'): 
                pkt_info['proto'] = 'TCP'
                pkt_info['color'] = "#e6e6fa" # Lavender
            elif packet.haslayer('UDP'): 
                pkt_info['proto'] = 'UDP'
                pkt_info['color'] = "#f0f8ff" # Alice Blue
            elif packet.haslayer('ICMP'): 
                pkt_info['proto'] = 'ICMP'
                pkt_info['color'] = "#ffe4e1" # Misty Rose

            # Payload (Hex)
            try:
                raw_bytes = bytes(packet)
                hex_str = binascii.hexlify(raw_bytes).decode('utf-8')
                pkt_info['payload'] = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
            except:
                pass

            self.packet_read.emit(pkt_info)

        except Exception as e:
            logger.debug(f"Error parsing packet {count}: {e}")
