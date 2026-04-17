"""QSS stylesheets for modern UI."""

MAIN_STYLESHEET = """
QMainWindow {
    background-color: #f8f9fa;
}

QLabel {
    color: #212529;
}

QPushButton {
    background-color: #007bff;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 6px 12px;
    font-weight: bold;
    font-size: 12px;
}

QPushButton:hover {
    background-color: #0056b3;
}

QPushButton:pressed {
    background-color: #003d82;
}

QPushButton#dangerButton {
    background-color: #dc3545;
}

QPushButton#dangerButton:hover {
    background-color: #a02830;
}

QTableWidget {
    background-color: white;
    alternate-background-color: #f8f9fa;
    gridline-color: #e0e0e0;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
}

QTableWidget::item {
    padding: 4px;
    border: none;
}

QTableWidget::item:selected {
    background-color: #007bff;
    color: white;
}

QHeaderView::section {
    background-color: #f8f9fa;
    color: #212529;
    padding: 4px;
    border: 1px solid #e0e0e0;
    font-weight: bold;
}

QTabWidget::pane {
    border: 1px solid #e0e0e0;
}

QTabBar::tab {
    background-color: #e9ecef;
    color: #212529;
    padding: 6px 12px;
    border: 1px solid #e0e0e0;
    border-bottom: none;
}

QTabBar::tab:selected {
    background-color: white;
    color: #007bff;
    font-weight: bold;
}

QGroupBox {
    color: #212529;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 8px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 3px;
}

QScrollBar:vertical {
    background-color: #f8f9fa;
    width: 12px;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background-color: #b0b8bf;
    border-radius: 4px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #94a0a8;
}

QLineEdit {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 4px;
    background-color: white;
    color: #212529;
}

QLineEdit:focus {
    border: 2px solid #007bff;
}

QComboBox {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 4px;
    background-color: white;
}

QComboBox::down-arrow {
    image: none;
}

QSpinBox, QDoubleSpinBox {
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 4px;
    background-color: white;
}

QCheckBox {
    color: #212529;
    spacing: 4px;
}

.riskHighBadge {
    background-color: #dc3545;
    color: white;
    border-radius: 4px;
    padding: 2px 6px;
}

.riskMediumBadge {
    background-color: #ffc107;
    color: #212529;
    border-radius: 4px;
    padding: 2px 6px;
}

.riskLowBadge {
    background-color: #28a745;
    color: white;
    border-radius: 4px;
    padding: 2px 6px;
}

.dashboardCard {
    background-color: white;
    border: 1px solid #e0e0e0;
    border-radius: 8px;
    padding: 12px;
}

.dashboardTitle {
    font-size: 14px;
    font-weight: bold;
    color: #495057;
}

.dashboardValue {
    font-size: 18px;
    font-weight: bold;
    color: #212529;
}
"""
