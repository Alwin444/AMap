"""
app/main.py

Main entry point for the WiFi Manager application.
This file is responsible for:
- Initializing the QApplication.
- Loading the main stylesheet from main_window.
- Creating and showing the MainWindow.
- Running the application event loop.
"""

import sys
from PyQt5 import QtWidgets
from app.main_window import MainWindow, CYBER_STYLESHEET

def run_app():
    """
    Initializes and runs the Qt application.
    """
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(CYBER_STYLESHEET)
    
    try:
        win = MainWindow()
        win.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Error launching main window: {e}")
        # TODO: Add logging here (I have not included it)
        sys.exit(1)

if __name__ == '__main__':
    # This check is for when the module is executed directly
    run_app()
