"""
app/utils/network.py

Core networking utilities for the WiFi Manager.
Handles fetching system IP, Gateway, Interfaces, Public IP, and ARP entries.
Optimized: Prioritizes native Linux methods (psutil, /proc) over Scapy for speed.
"""

import socket
import psutil
import requests
import logging
import os

# Configure logging
logger = logging.getLogger(__name__)

def get_interfaces():
    """
    Returns a list of ALL available network interface names.
    Excludes loopback ('lo') but includes interfaces that might be 'down'.
    """
    try:
        stats = psutil.net_if_stats()
        # Return interfaces that are NOT loopback.
        return [
            iface for iface, stat in stats.items() 
            if iface != "lo" and not iface.startswith("loop")
        ]
    except Exception as e:
        logger.error(f"Error fetching interfaces: {e}")
        return []

def get_local_ip(iface=None):
    """
    Gets the IPv4 address of the machine or a specific interface.
    """
    try:
        # Method 1: Specific Interface (Fastest via psutil)
        if iface:
            addrs = psutil.net_if_addrs()
            if iface in addrs:
                for addr in addrs[iface]:
                    if addr.family == socket.AF_INET: # IPv4
                        return addr.address
        
        # Method 2: Default Route (Fallback if no interface specified)
        # This finds the IP used to reach the internet without connecting.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.1)
            s.connect(("8.8.8.8", 80)) 
            return s.getsockname()[0]
    except Exception as e:

        return "127.0.0.1"

def get_default_gateway():
    """
    Returns the default gateway IP.
    Optimized to read Linux procfs directly to avoid Scapy overhead.
    """
    # Method 1: Linux /proc/net/route (Instant)
    try:
        if os.path.exists("/proc/net/route"):
            with open("/proc/net/route") as f:
                for line in f:
                    fields = line.strip().split()
                    # Destination 00000000 is default route, Flags & 2 is RTF_GATEWAY
                    if len(fields) >= 4 and fields[1] == '00000000' and int(fields[3], 16) & 2:
                        # Convert hex IP to dotted decimal (little-endian)
                        return socket.inet_ntoa(int(fields[2], 16).to_bytes(4, 'little'))
    except Exception:
        pass
        
    # Method 2: Scapy (Fallback - Slow but reliable)
    try:
        from scapy.all import conf
        route = conf.route.route("0.0.0.0")
        return route[2]
    except Exception as e:
        logger.error(f"Error getting gateway: {e}")
        return "Unknown"

def get_mac_address(iface=None):
    """
    Returns the MAC address of the interface.
    Prioritizes psutil to avoid Scapy overhead.
    """
    # 1. Try using psutil (Standard Linux method)
    try:
        if not iface:
            # Find primary interface if none provided
            defaults = get_interfaces()
            if defaults:
                iface = defaults[0]

        if iface:
            addrs = psutil.net_if_addrs()
            if iface in addrs:
                for addr in addrs[iface]:
                    if addr.family == psutil.AF_LINK: # AF_LINK is the MAC layer
                        return addr.address
    except Exception:
        pass

    # 2. Fallback to Scapy (Slower)
    try:
        from scapy.all import get_if_hwaddr, conf
        target_iface = iface if iface else conf.iface
        return get_if_hwaddr(target_iface)
    except Exception:
        return "00:00:00:00:00:00"

def get_public_ip():
    """
    Fetches public IP from an external API.
    Note: This is a blocking call; runs in ip_worker.
    """
    try:
        # Reduced timeout to prevent UI hang feel if thread is slow
        response = requests.get('https://api.ipify.org', timeout=2)
        if response.status_code == 200:
            return response.text
    except Exception:
        pass
    return "Unavailable"

def get_dns_servers():
    """
    Attempts to read /etc/resolv.conf on Linux to find DNS servers.
    """
    dns_servers = []
    try:
        if os.path.exists('/etc/resolv.conf'):
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        parts = line.split()
                        if len(parts) > 1:
                            dns_servers.append(parts[1])
    except Exception:
        pass
    
    if not dns_servers:
        return ["Unknown", "Unknown"]
    
    # Pad with 'N/A' if only one DNS found
    if len(dns_servers) == 1:
        dns_servers.append("N/A")
        
    return dns_servers[:2]

def get_arp_mac(ip):
    """
    Reads /proc/net/arp to find the MAC address for a given IP.
    Useful for finding Gateway MAC without active scanning.
    """
    try:
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as f:
          
                next(f)
                for line in f:
                    parts = line.split()
                    
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac
    except Exception:
        pass
    return None
