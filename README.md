🌐 AMapA sleek, GUI-driven Network Mapping and Analysis Desktop Application built with Python & PySide6.</div><hr/>📖 OverviewAMap provides network administrators, security enthusiasts, and everyday users with a robust suite of tools to monitor, analyze, and map local networks, analyze packets, and perform various web intelligence lookups. By utilizing dedicated background workers, the application ensures a buttery-smooth graphical interface even during intensive network operations.✨ Features🔍 Local Network AnalysisDevice Discovery: ARP/IP Scans to identify connected devices, MAC addresses, and vendors (OUI lookup).Port Scanning: Fast, multi-threaded TCP/UDP port scans on target IP addresses.WiFi Scanning: Discover nearby wireless networks, signal strengths, and security protocols.Traffic Monitoring: Live network traffic sniffing and visual statistics.🌐 Web & Domain IntelligenceDNS & Subdomain: Resolve domain records and perform subdomain enumeration.WHOIS Queries: Retrieve domain registration details.SSL Certificate Checker: Inspect SSL/TLS certificate chains and expiration dates.Traceroute: Trace the exact path packets take to reach a network host.🛠️ Utilities & ManagementPCAP Tooling: Import .pcap files for deep offline analysis or save live captures.Speed Test: Built-in internet bandwidth tester (Ping, Download, Upload).System Dashboard: Quick views for firewall status, default gateway, and system uptime.🚀 Getting StartedPrerequisitesPython 3.8+WinPcap / Npcap (For Windows users) or libpcap (For Linux/macOS) - Required for packet sniffing functionality.InstallationClone the repository:git clone [https://github.com/yourusername/AMap.git](https://github.com/yourusername/AMap.git)
cd AMap
Set up a virtual environment and install dependencies:For Windows:python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
For Linux / macOS:python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
UsageTo launch the application, ensure your virtual environment is active and run:For Windows:python wifi_manager_gui.py
For Linux / macOS:python3 wifi_manager_gui.py
⚠️ Note: Features like ARP scanning or live packet sniffing often require Administrator (Windows) or Root/sudo (Linux/macOS) privileges to interact directly with network interfaces.📂 Project StructureThe project follows a clean, modular architecture separating UI views from heavy worker threads:AMap/
├─ app/                     # Core Application Package
│  ├─ main.py               # Main application loop initialization
│  ├─ main_window.py        # Primary GUI window and layout
│  ├─ pages/                # UI Views (Devices, Port Scan, Traffic, DNS, etc.)
│  ├─ workers/              # Background Threads (ARP, Sniffing, WHOIS, etc.)
│  ├─ models/               # Data structures (Packet, Device)
│  └─ utils/                # Helper functions (Network math, OUI parsing)
├─ data/                    # Local databases (OUI CSVs, JSON datasets)
├─ pcap_outputs/            # Saved capture files and exported data
├─ requirements.txt         # Python dependencies
├─ wifi_manager_gui.py      # Main entry point launcher
└─ README.md                # Project documentation
⚠️ DisclaimerThis tool is intended for educational purposes and authorized network administration only. Unauthorized scanning, sniffing, or probing of networks and devices that you do not own or have explicit permission to test is strictly prohibited. The developers assume no liability and are not responsible for any misuse or damage caused by this program.🤝 ContributingContributions, issues, and feature requests are highly welcome!Fork the ProjectCreate your Feature Branch (git checkout -b feature/AmazingFeature)Commit your Changes (git commit -m 'Add some AmazingFeature')Push to the Branch (git push origin feature/AmazingFeature)Open a Pull Request📄 LicenseDistributed under the MIT License. See LICENSE for more information.
