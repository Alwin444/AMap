AMap 

A sleek, GUI-driven Network Mapping and Analysis Desktop Application built with Python (PySide6).

Features

Network Analysis: ARP/IP Device Discovery, Port Scanning, WiFi Scanning, and Traffic Monitoring.

Web Intelligence: DNS Lookup, WHOIS Queries, SSL Certificate Checker, and Traceroute.

Utilities: PCAP Import/Export, Speed Test, and System Uptime Dashboard.

Installation

Clone the repository and navigate to the project directory.

Create a virtual environment and install dependencies:

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt


Usage

Launch the application by running the main entry point:

python wifi_manager_gui.py


Note: Packet sniffing and certain network scanning features may require Administrator (Windows) or Root (Linux/macOS) privileges.
