"""
app/workers/firewall_worker.py

A QThread worker that detects Web Application Firewalls (WAF) 
or Network Firewalls.

"""

from PyQt5.QtCore import QThread, pyqtSignal
import requests
import logging
import urllib3

# Suppress SSL warnings for clearer logs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logger = logging.getLogger(__name__)

class FirewallScanWorker(QThread):
    """
    Scans a target (URL or IP) for Firewall/WAF signatures.
    """
    log = pyqtSignal(str) # Log messages
    result = pyqtSignal(dict) # Final report
    finished = pyqtSignal()

    def __init__(self, target):
        super().__init__()
        self.target = target
        self.is_running = True

    def run(self):
        self.log.emit(f"Starting Firewall/WAF detection for {self.target}...")
        
        if not self.target.startswith("http"):
            url = f"http://{self.target}"
        else:
            url = self.target
            
        try:
            domain = url.split("//")[-1].split("/")[0]
        except:
            domain = self.target
            
        # Default Report
        report = {
            "target": domain, 
            "waf": "None Detected", 
            "presence": "No",   
            "status": "Scanning..."
        }

        # ---------------------------------------------------------
        # WAF SIGNATURE DATABASE
        # ---------------------------------------------------------
        WAF_DB = {
            "Cloudflare": {
                "headers": ["cf-ray", "__cfduid", "cf-cache-status", "cf-request-id"],
                "server": ["cloudflare"]
            },
            "Google / GFE": {
                "headers": ["x-google-cache-control"],
                "server": ["gws", "gfe", "esf"]
            },
            "Akamai": {
                "headers": ["x-akamai-transformed", "akamai-origin-hop", "x-akamai-request-id"],
                "server": ["akamaighost", "akamai"]
            },
            "Imperva Incapsula": {
                "headers": ["x-iinfo", "x-cdn", "incap-ses", "visid_incap"],
                "server": ["incapsula"]
            },
            "AWS CloudFront (WAF)": {
                "headers": ["x-amz-cf-id", "x-amz-id-1"],
                "server": ["cloudfront"]
            },
            "F5 BIG-IP": {
                "headers": ["x-cnection", "x-wa-info"],
                "server": ["big-ip", "bigip"]
            },
            "ModSecurity": {
                "headers": ["x-mod-security"],
                "server": ["mod_security", "modsecurity"]
            },
            "Sucuri": {
                "headers": ["x-sucuri-id", "x-sucuri-cache"],
                "server": ["sucuri"]
            },
             "Nginx (Generic)": {
                "headers": [],
                "server": ["nginx"]
            },
             "Apache (Generic)": {
                "headers": [],
                "server": ["apache"]
            }
        }

        try:
            # 1. Passive Analysis (Headers)
            try:
                r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, verify=False)
                
                report["status"] = "Online"
                headers = {k.lower(): v.lower() for k, v in r.headers.items()}
                self.log.emit(f"Received response: {r.status_code} {r.reason}")
                
                detected_wafs = set()
                
                for waf_name, sigs in WAF_DB.items():
                    for h in sigs.get("headers", []):
                        if h in headers:
                            detected_wafs.add(waf_name)
                            self.log.emit(f"Signature found: Header '{h}'")
                    
                    if "server" in headers:
                        server_val = headers["server"]
                        for s in sigs.get("server", []):
                            if s in server_val:
                                detected_wafs.add(waf_name)
                                self.log.emit(f"Signature found: Server '{server_val}'")

                if detected_wafs:
                    report["waf"] = ", ".join(list(detected_wafs))
                    # Check if it's a real WAF or just a web server
                    if any(x in ["Nginx (Generic)", "Apache (Generic)"] for x in detected_wafs) and len(detected_wafs) == 1:
                         report["presence"] = "No (Server Only)"
                    else:
                         report["presence"] = "Yes"
                         
                    self.log.emit(f"POSITIVE MATCH: {report['waf']}")
                else:
                    if "server" in headers:
                        server_name = headers["server"]
                        report["waf"] = f"Server: {server_name}"
                        report["presence"] = "No (Server Only)"
                    else:
                        self.log.emit("No vendor signatures found.")

            except requests.exceptions.ConnectTimeout:
                report["status"] = "Timed Out"
                report["presence"] = "Yes (Network Firewall)"
                report["waf"] = "Traffic Dropped"
                self.log.emit("Connection timed out. Host down or packets dropped.")
                self.result.emit(report)
                self.finished.emit()
                return
            except requests.exceptions.SSLError:
                report["status"] = "SSL Error"
                self.log.emit("SSL Handshake failed.")
            except requests.exceptions.ConnectionError:
                report["status"] = "Unreachable"
                self.log.emit("Failed to establish connection.")
                self.result.emit(report)
                self.finished.emit()
                return

            # 2. Active Provocation (If passive failed or inconclusive)
            if report["presence"] == "No" and report["status"] == "Online":
                self.log.emit("Attempting active provocation (sending suspicious payload)...")
                
                payloads = [
                    {"id": "1' OR '1'='1"},
                    {"q": "<script>alert('WAF')</script>"}
                ]
                
                blocked = False
                for p in payloads:
                    if not self.is_running: break
                    try:
                        r_bad = requests.get(url, params=p, timeout=5, headers={"User-Agent": "Mozilla/5.0"}, verify=False)
                        if r_bad.status_code in [403, 406, 501]:
                            blocked = True
                            self.log.emit(f"Attack blocked! (Status {r_bad.status_code})")
                            break
                    except:
                        pass

                if blocked:
                    report["presence"] = "Yes"
                    if "None" in report["waf"] or "Server" in report["waf"]:
                        report["waf"] = "Generic WAF (Behavioral)"
                    self.log.emit("Server blocked suspicious request. WAF present.")
                else:
                    self.log.emit("Suspicious payloads were NOT blocked.")

        except Exception as e:
            self.log.emit(f"Critical Scan Error: {e}")
            report["status"] = "Error"
        
        self.result.emit(report)
        self.finished.emit()

    def stop(self):
        self.is_running = False
        self.wait()
