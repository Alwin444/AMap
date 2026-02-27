"""
app/pages/base_page.py

Contains the BasePage and SummaryCard classes, which are used by
all other pages to maintain a consistent look and feel.
"""

from PyQt5 import QtWidgets, QtCore, QtGui

# --- Utility small widget: summary card ---
class SummaryCard(QtWidgets.QFrame):
    def __init__(self, title: str, value: str, parent=None):
        super().__init__(parent)
        self.setObjectName('card')
        self.setProperty('class', 'card') # For QSS
        self.setMinimumHeight(70)
        layout = QtWidgets.QVBoxLayout(self)
        t = QtWidgets.QLabel(title)
        t.setProperty('class', 'card-title')
        v = QtWidgets.QLabel(value)
        v.setProperty('class', 'card-value')
        layout.addWidget(t)
        layout.addWidget(v)
        layout.setSpacing(4)
        layout.setContentsMargins(12,8,12,8)
        self.value_label = v

    def set_value(self, text: str):
        self.value_label.setText(text)

# --- BasePage ---
class BasePage(QtWidgets.QWidget):
    def __init__(self, title: str):
        super().__init__()
        self.layout = QtWidgets.QVBoxLayout(self)
        self.layout.setContentsMargins(16, 16, 16, 16)
        self.title = QtWidgets.QLabel(title)
        self.title.setObjectName('PageTitle')
        self.layout.addWidget(self.title)

    def get_layout(self):
        return self.layout
