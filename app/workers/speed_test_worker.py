"""
app/workers/speed_test_worker.py

Runs internet speed test using speedtest-cli library in a background thread.
FIXED: Added secure=True to prevent HTTP 403 Forbidden errors.
"""

from PyQt5.QtCore import QThread, pyqtSignal
import speedtest
import logging

# Configure logging
logger = logging.getLogger(__name__)

class SpeedTestWorker(QThread):
    # Signal emits: (test_type, percentage, current_speed_value)
    # test_type: 'ping', 'download', 'upload'
    progress_update = pyqtSignal(str, float, float)
    
    # Signal emits final results dict
    finished = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.is_running = True

    def run(self):
        logger.info("Starting speed test worker...")
        results = {'ping': 0.0, 'download': 0.0, 'upload': 0.0}
        
        try:
            # FIX: Use secure=True to force HTTPS. 
            # This bypasses the 403 Forbidden error on the config URL.
            st = speedtest.Speedtest(secure=True)
            
            if not self.is_running: return

            # 1. Get Best Server (Ping)
            self.progress_update.emit('ping', 0, 0)
            st.get_best_server()
            ping = st.results.ping
            results['ping'] = ping
            self.progress_update.emit('ping', 100, ping)
            
            if not self.is_running: return

            # 2. Download Test
            self.progress_update.emit('download', 10, 0)
            # download() returns bits/s, convert to Mbps
            download_speed = st.download() / 1024 / 1024 
            results['download'] = download_speed
            self.progress_update.emit('download', 100, download_speed)

            if not self.is_running: return

            # 3. Upload Test
            self.progress_update.emit('upload', 10, 0)
            upload_speed = st.upload() / 1024 / 1024 
            results['upload'] = upload_speed
            self.progress_update.emit('upload', 100, upload_speed)

            self.finished.emit(results)

        except Exception as e:
            logger.error(f"Speedtest failed: {e}")
            
            # Provide a more helpful error message for the 403 case
            error_msg = str(e)
            if "403" in error_msg:
                error_msg = "Access Denied (403). Try: pip install speedtest-cli --upgrade"
                
            self.error_occurred.emit(error_msg)
            self.finished.emit({}) # Emit empty on error

    def stop(self):
        self.is_running = False
        self.wait()
