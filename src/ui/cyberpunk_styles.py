"""
Cyberpunk surveillance-style QSS and styling system.

Color palette:
- background: #0a0f14
- neon green: #00ff9c
- cyan: #00eaff
- warning yellow: #ffc400
- danger red: #ff3b3b
- purple accent: #8a5cff
"""

# Color definitions
COLORS = {
    'bg_dark': '#0a0f14',
    'bg_panel': '#0d1117',
    'bg_hover': '#161b22',
    'border_dark': '#30363d',
    
    'neon_green': '#00ff9c',
    'neon_cyan': '#00eaff',
    'neon_purple': '#8a5cff',
    'neon_pink': '#ff006e',
    
    'warning_yellow': '#ffc400',
    'danger_red': '#ff3b3b',
    'success_green': '#00ff9c',
    
    'text_primary': '#e6edf3',
    'text_secondary': '#8b949e',
    'text_muted': '#6e7681',
    
    'grid_lines': '#21262d',
}

# QSS Stylesheet for main application
MAIN_STYLESHEET = f"""
/* ============================================
   GLOBAL APPLICATION STYLING
   ============================================ */

QMainWindow {{
    background-color: {COLORS['bg_dark']};
    border: 1px solid {COLORS['border_dark']};
}}

QWidget {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['text_primary']};
}}

/* ============================================
   PANELS AND FRAMES
   ============================================ */

QFrame {{
    background-color: {COLORS['bg_panel']};
    border: 1px solid {COLORS['border_dark']};
    border-radius: 4px;
}}

QFrame.neon-border {{
    border: 2px solid {COLORS['neon_cyan']};
    border-radius: 4px;
    background-color: {COLORS['bg_panel']};
}}

QFrame.warning-border {{
    border: 2px solid {COLORS['danger_red']};
    border-radius: 4px;
    background-color: {COLORS['bg_panel']};
}}

/* ============================================
   BUTTONS - NEON STYLE
   ============================================ */

QPushButton {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['neon_green']};
    border: 2px solid {COLORS['neon_green']};
    border-radius: 4px;
    padding: 6px 12px;
    font-family: 'Courier New', monospace;
    font-weight: bold;
    font-size: 11px;
    text-transform: uppercase;
}}

QPushButton:hover {{
    background-color: {COLORS['bg_hover']};
    color: #ffffff;
    border: 2px solid {COLORS['neon_cyan']};
    box-shadow: 0 0 10px {COLORS['neon_green']};
}}

QPushButton:pressed {{
    background-color: {COLORS['neon_green']};
    color: {COLORS['bg_dark']};
    border: 2px solid {COLORS['neon_green']};
}}

QPushButton.danger {{
    color: {COLORS['danger_red']};
    border: 2px solid {COLORS['danger_red']};
}}

QPushButton.danger:hover {{
    border: 2px solid {COLORS['danger_red']};
}}

QPushButton.warning {{
    color: {COLORS['warning_yellow']};
    border: 2px solid {COLORS['warning_yellow']};
}}

QPushButton.warning:hover {{
    border: 2px solid {COLORS['warning_yellow']};
}}

/* ============================================
   LABELS AND TEXT
   ============================================ */

QLabel {{
    color: {COLORS['text_primary']};
    background-color: transparent;
}}

QLabel.title {{
    font-family: 'Courier New', monospace;
    font-size: 14px;
    font-weight: bold;
    color: {COLORS['neon_cyan']};
    text-transform: uppercase;
}}

QLabel.section {{
    font-family: 'Courier New', monospace;
    font-size: 12px;
    font-weight: bold;
    color: {COLORS['neon_green']};
    text-transform: uppercase;
}}

QLabel.status {{
    font-family: 'Courier New', monospace;
    font-size: 10px;
    color: {COLORS['text_secondary']};
}}

QLabel.risk-high {{
    color: {COLORS['danger_red']};
    font-weight: bold;
}}

QLabel.risk-medium {{
    color: {COLORS['warning_yellow']};
    font-weight: bold;
}}

QLabel.risk-low {{
    color: {COLORS['neon_green']};
    font-weight: bold;
}}

/* ============================================
   TABLES AND LISTS
   ============================================ */

QTableWidget {{
    background-color: {COLORS['bg_panel']};
    gridline-color: {COLORS['grid_lines']};
    border: 1px solid {COLORS['border_dark']};
    border-radius: 4px;
}}

QTableWidget::item {{
    padding: 4px;
    border-bottom: 1px solid {COLORS['grid_lines']};
}}

QTableWidget::item:selected {{
    background-color: {COLORS['neon_cyan']};
    color: {COLORS['bg_dark']};
}}

QHeaderView::section {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['neon_green']};
    padding: 4px;
    border-right: 1px solid {COLORS['grid_lines']};
    border-bottom: 2px solid {COLORS['neon_green']};
    font-family: 'Courier New', monospace;
    font-size: 10px;
    text-transform: uppercase;
    font-weight: bold;
}}

QListWidget {{
    background-color: {COLORS['bg_panel']};
    border: 1px solid {COLORS['border_dark']};
    border-radius: 4px;
}}

QListWidget::item:selected {{
    background-color: {COLORS['neon_cyan']};
    color: {COLORS['bg_dark']};
}}

/* ============================================
   TABS
   ============================================ */

QTabWidget {{
    background-color: {COLORS['bg_dark']};
}}

QTabWidget::pane {{
    border: 1px solid {COLORS['border_dark']};
    background-color: {COLORS['bg_dark']};
}}

QTabBar::tab {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_secondary']};
    border: 1px solid {COLORS['border_dark']};
    border-bottom: 2px solid {COLORS['border_dark']};
    padding: 8px 20px;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    text-transform: uppercase;
}}

QTabBar::tab:selected {{
    background-color: {COLORS['bg_dark']};
    color: {COLORS['neon_cyan']};
    border-bottom: 2px solid {COLORS['neon_cyan']};
}}

QTabBar::tab:hover:!selected {{
    color: {COLORS['text_primary']};
}}

/* ============================================
   SCROLL BARS
   ============================================ */

QScrollBar:vertical {{
    background-color: {COLORS['bg_panel']};
    width: 12px;
    border: 1px solid {COLORS['border_dark']};
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS['neon_green']};
    border-radius: 6px;
    min-height: 20px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLORS['neon_cyan']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    border: none;
    background: none;
}}

/* ============================================
   INPUT FIELDS
   ============================================ */

QLineEdit, QTextEdit {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_dark']};
    border-radius: 4px;
    padding: 4px;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    selection-background-color: {COLORS['neon_cyan']};
}}

QLineEdit:focus, QTextEdit:focus {{
    border: 2px solid {COLORS['neon_cyan']};
}}

/* ============================================
   SLIDERS
   ============================================ */

QSlider::groove:horizontal {{
    background-color: {COLORS['bg_panel']};
    border: 1px solid {COLORS['border_dark']};
    height: 8px;
    border-radius: 4px;
}}

QSlider::handle:horizontal {{
    background-color: {COLORS['neon_green']};
    border: 1px solid {COLORS['neon_cyan']};
    width: 16px;
    margin: -4px 0;
    border-radius: 8px;
}}

QSlider::handle:horizontal:hover {{
    background-color: {COLORS['neon_cyan']};
}}

/* ============================================
   COMBO BOX
   ============================================ */

QComboBox {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_dark']};
    border-radius: 4px;
    padding: 4px 8px;
    font-family: 'Courier New', monospace;
}}

QComboBox:hover {{
    border: 1px solid {COLORS['neon_cyan']};
}}

QComboBox::drop-down {{
    background-color: {COLORS['bg_panel']};
    border: none;
    width: 20px;
}}

QComboBox QAbstractItemView {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
    selection-background-color: {COLORS['neon_cyan']};
}}

/* ============================================
   MENU BAR
   ============================================ */

QMenuBar {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['neon_green']};
    border-bottom: 1px solid {COLORS['border_dark']};
    spacing: 0;
}}

QMenuBar::item:selected {{
    background-color: {COLORS['bg_hover']};
    color: {COLORS['neon_cyan']};
}}

QMenu {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['neon_cyan']};
}}

QMenu::item:selected {{
    background-color: {COLORS['neon_cyan']};
    color: {COLORS['bg_dark']};
}}

/* ============================================
   STATUS BAR
   ============================================ */

QStatusBar {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_secondary']};
    border-top: 1px solid {COLORS['neon_green']};
}}

QStatusBar::item {{
    border: none;
}}

/* ============================================
   DIALOG
   ============================================ */

QDialog {{
    background-color: {COLORS['bg_dark']};
    border: 2px solid {COLORS['neon_cyan']};
}}

/* ============================================
   SPIN BOX
   ============================================ */

QSpinBox, QDoubleSpinBox {{
    background-color: {COLORS['bg_panel']};
    color: {COLORS['text_primary']};
    border: 1px solid {COLORS['border_dark']};
    border-radius: 4px;
    padding: 4px;
    font-family: 'Courier New', monospace;
}}

QSpinBox::up-button, QDoubleSpinBox::up-button {{
    background-color: {COLORS['bg_panel']};
    border-left: 1px solid {COLORS['border_dark']};
}}

QSpinBox::down-button, QDoubleSpinBox::down-button {{
    background-color: {COLORS['bg_panel']};
    border-left: 1px solid {COLORS['border_dark']};
}}
"""

# Compact sizes for monitor view
MONITOR_STYLESHEET = f"""
QTableWidget {{
    font-size: 9px;
    font-family: 'Courier New', monospace;
}}

QTableWidget::item {{
    padding: 2px;
}}

QHeaderView::section {{
    font-size: 8px;
    padding: 2px;
}}
"""
