"""
app/utils/persistence.py

Utilities for saving and loading data.
Handles CSV exports for table data and PCAP file management.
"""

import csv
import logging
from scapy.all import wrpcap, rdpcap

# Configure logging
logger = logging.getLogger(__name__)

def export_to_csv(data: list, headers: list, filename: str):
    """
    Exports a list of dictionaries (or rows) to a CSV file.
    
    Args:
        data: List of lists or dicts containing the row data.
        headers: List of strings for the CSV header row.
        filename: Target file path.
    """
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for row in data:
                # If row is a dict, convert to list based on headers order
                if isinstance(row, dict):
                    row_data = [row.get(h.lower(), "") for h in headers]
                else:
                    row_data = row
                writer.writerow(row_data)
                
        logger.info(f"Successfully exported data to {filename}")
        return True
    except Exception as e:
        logger.error(f"Failed to export CSV: {e}")
        return False

def save_pcap_file(packets, filename: str):
    """
    Saves a list of Scapy packets to a .pcap file.
    """
    try:
        wrpcap(filename, packets)
        logger.info(f"Saved {len(packets)} packets to {filename}")
        return True
    except Exception as e:
        logger.error(f"Failed to save PCAP: {e}")
        return False

def load_pcap_file(filename: str):
    """
    Loads a .pcap file using Scapy.
    Returns a list of packets.
    """
    try:
        packets = rdpcap(filename)
        logger.info(f"Loaded {len(packets)} packets from {filename}")
        return packets
    except Exception as e:
        logger.error(f"Failed to load PCAP: {e}")
        return []
