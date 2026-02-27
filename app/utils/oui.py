"""
app/utils/oui.py

Utility to resolve MAC addresses to Vendor names using the OUI database.
"""

import csv
import os
import logging

logger = logging.getLogger(__name__)

class OuiLookup:
    _instance = None
    _db = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(OuiLookup, cls).__new__(cls)
            cls._instance._load_database()
        return cls._instance

    def _load_database(self):
        """Loads the OUI CSV into a dictionary."""

        current_file = os.path.abspath(__file__)
        
        # Directory traversal:
        # wifi_manager/app/utils/oui.py (current_file)
        #  -> AMap/app/utils (dirname)
        #  -> AMap/app (dirname)
        #  -> AMap (dirname)
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        
        csv_path = os.path.join(base_dir, 'data', 'oui_sample.csv')

        if not os.path.exists(csv_path):
            logger.warning(f"OUI file not found at {csv_path}. Vendor lookup will fail.")
            return

        try:
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                for row in reader:
                    # Skip empty lines or header if not strictly matching format
                    if len(row) >= 3 and row[0] != 'Registry':
                        # Format: Registry, Assignment(MAC Prefix), Org Name
                        mac_prefix = row[1].strip()
                        vendor = row[2].strip()
                        
                        # normalize prefix: 00-1A-2B or 00:1A:2B -> 001A2B
                        clean_prefix = mac_prefix.replace(':', '').replace('-', '').upper()
                        
                        # Basic validation (must be hex and at least 6 chars)
                        if len(clean_prefix) >= 6:
                             self._db[clean_prefix[:6]] = vendor
                             
            logger.info(f"Loaded {len(self._db)} OUI records.")
        except Exception as e:
            logger.error(f"Failed to load OUI database: {e}")

    def get_vendor(self, mac_address):
        if not mac_address: return "Unknown"
        
        # Clean MAC input: 00:1A:2B... -> 001A2B
        clean_mac = mac_address.replace(':', '').replace('-', '').upper()
        
        # Need at least 6 chars (OUI)
        if len(clean_mac) < 6: return "Unknown"
            
        oui = clean_mac[:6]
        
        # Return vendor if found, else "Unknown"
        return self._db.get(oui, "Unknown")

def lookup_vendor(mac_address):
    """Global helper function to lookup vendor."""
    return OuiLookup().get_vendor(mac_address)
