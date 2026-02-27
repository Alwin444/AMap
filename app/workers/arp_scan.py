"""
app/workers/arp_scan.py

A QThread worker that performs network scanning to discover devices.
Supports Scapy ARP and Nmap.
FIXED: 
- Detects 'Private/Randomized' MAC addresses used by mobile phones.
- Robust Nmap parsing logic.
- Correct Local Time for 'Last Seen'.
"""

from PyQt5.QtCore import QThread, pyqtSignal
from scapy.all import ARP, Ether, srp
import logging
import datetime
import subprocess
import shutil
import socket
import re
from app.utils.oui import lookup_vendor
from app.utils.network import get_local_ip, get_mac_address

logger = logging.getLogger(__name__)

class ArpScanWorker(QThread):
    device_found = pyqtSignal(dict)
    scan_finished = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, interface, ip_range="192.168.1.0/24", use_nmap=False, timeout=3):
        super().__init__()
        self.interface = interface
        self.ip_range = ip_range
        self.use_nmap = use_nmap
        self.timeout = timeout
        self.is_running = True

    def run(self):
        logger.info(f"Starting scan on {self.interface}...")
        
        # 1. Add Localhost (Self)
        self._add_local_device()

        # 2. Run Scan
        if self.use_nmap and shutil.which("nmap"):
            self._run_nmap_scan()
        else:
            if self.use_nmap:
                logger.warning("Nmap not found, falling back to Scapy.")
            self._run_scapy_scan()
        
        self.scan_finished.emit()

    def _get_now_str(self):
        """Returns current local time string."""
        return datetime.datetime.now().strftime('%H:%M:%S')

    def _add_local_device(self):
        """Manually adds the machine running the app."""
        try:
            my_ip = get_local_ip(self.interface)
            my_mac = get_mac_address(self.interface)
            hostname = socket.gethostname()
            
            if my_ip and my_ip != "127.0.0.1" and my_mac != "00:00:00:00:00:00":
                self._emit_device(my_ip, my_mac, f"{hostname} (Self)")
        except Exception:
            pass

    def _run_scapy_scan(self):
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.ip_range)
            answered, _ = srp(packet, timeout=self.timeout, iface=self.interface, verbose=0)

            for sent, received in answered:
                if not self.is_running: break
                if received.haslayer(ARP):
                    self._emit_device(received[ARP].psrc, received[ARP].hwsrc)
        except Exception as e:
            self.error_occurred.emit(f"Scapy Error: {e}")

    def _run_nmap_scan(self):
        """Runs Nmap and parses output line-by-line manually for reliability."""
        try:
            # -sn: Ping Scan (ARP on local)
            # -e: Interface
            command = ["nmap", "-sn", "-e", self.interface, self.ip_range]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            current_ip = None
            current_host = "Unknown"

            for line in process.stdout:
                if not self.is_running: 
                    process.terminate()
                    break
                
                line = line.strip()

                # 1. Parse IP and Hostname Line
                if line.startswith("Nmap scan report for"):
                    parts = line.replace("Nmap scan report for ", "")
                    if "(" in parts:
                        split_host = parts.split("(")
                        current_host = split_host[0].strip()
                        current_ip = split_host[1].replace(")", "").strip()
                    else:
                        current_host = "Unknown"
                        current_ip = parts.strip()
                    continue

                # 2. Parse MAC Line
                if line.startswith("MAC Address:"):
                    if current_ip:
                        rest = line.replace("MAC Address: ", "")
                        mac = rest.split(" ")[0].strip()
                        
                        vendor_hint = None
                        if "(" in rest:
                            vendor_hint = rest.split("(")[1].replace(")", "").strip()
                        
                        self._emit_device(current_ip, mac, current_host, vendor_hint)
                        current_ip = None

            process.wait()
            
            # Cleanup for devices without MAC lines (rare, but possible)
            if current_ip:
                 self._fallback_arp_lookup(current_ip, current_host)

        except Exception as e:
            self.error_occurred.emit(f"Nmap Error: {e}")

    def _fallback_arp_lookup(self, ip, hostname):
        """Reads /proc/net/arp to find a MAC if Nmap missed it."""
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            self._emit_device(ip, mac, hostname)
                        return
        except:
            pass

    def _is_private_mac(self, mac):
        """Checks if a MAC address is locally administered (Private/Randomized)."""
        try:
            # Remove separators and get the second hex digit
            clean_mac = mac.replace(":", "").replace("-", "")
            if not clean_mac: return False
            
            # Get the first byte (first 2 chars)
            first_byte = int(clean_mac[:2], 16)
            
            # Check the "Locally Administered" bit (2nd least significant bit of the first byte)
            # If this bit is 1, the MAC is private/randomized.
            return (first_byte & 0b00000010) != 0
        except:
            return False

    def _emit_device(self, ip, mac, hostname="Unknown", vendor_hint=None):
        if not mac: return

        # 1. Resolve Vendor (OUI File)
        vendor = lookup_vendor(mac)
        
        # 2. Use Nmap hint if OUI failed
        if (not vendor or vendor == "Unknown") and vendor_hint:
            vendor = vendor_hint
            
        # 3. Check for Private MAC (Mobile Privacy)
        if (not vendor or vendor == "Unknown") and self._is_private_mac(mac):
            vendor = "Private / Randomized"

        # 4. Resolve Hostname (if missing)
        if hostname == "Unknown":
            try:
                h = socket.gethostbyaddr(ip)
                hostname = h[0]
            except: pass

        device = {
            'ip': ip,
            'mac': mac,
            'vendor': vendor if vendor else "Unknown",
            'hostname': hostname,
            'seen': self._get_now_str()
        }
        self.device_found.emit(device)

    def stop(self):
        self.is_running = False
        self.wait()
