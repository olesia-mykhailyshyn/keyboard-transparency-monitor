"""
Custom neon/cyberpunk widgets for the Keyboard Transparency Monitor.
"""

from PySide6.QtWidgets import (
    QPushButton, QFrame, QLabel, QWidget, QVBoxLayout, QHBoxLayout,
    QProgressBar
)
from PySide6.QtCore import Qt, QTimer, QSize, QRect, QPropertyAnimation, QEasingCurve, Property
from PySide6.QtGui import QColor, QPalette, QPainter, QFont, QPen, QBrush

from ..cyberpunk_styles import COLORS


class NeonButton(QPushButton):
    """A neon-styled button with glowing effects."""
    
    def __init__(self, text="", parent=None, style="default"):
        super().__init__(text, parent)
        self.style = style
        self.setFont(QFont("Courier New", 10, QFont.Bold))
        self.setCursor(Qt.PointingHandCursor)
        self.glow_level = 0
        
        # Setup glow animation
        self.glow_timer = QTimer()
        self.glow_timer.timeout.connect(self.update_glow)
        
    def enterEvent(self, event):
        """Start glow animation on hover."""
        self.glow_timer.start(50)
        super().enterEvent(event)
    
    def leaveEvent(self, event):
        """Stop glow animation when leaving."""
        self.glow_timer.stop()
        self.glow_level = 0
        self.update()
        super().leaveEvent(event)
    
    def update_glow(self):
        """Update glow animation."""
        self.glow_level = (self.glow_level + 1) % 20
        self.update()
    
    def paintEvent(self, event):
        """Custom paint with glow effect."""
        super().paintEvent(event)
        
        if self.glow_level > 0:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            
            # Draw glow
            glow_color = QColor(COLORS['neon_green'] if self.style == "default" else COLORS['danger_red'])
            glow_color.setAlpha(30 + (self.glow_level * 3))
            
            painter.setPen(QPen(glow_color, 2))
            painter.setBrush(QBrush(glow_color))
            
            rect = self.rect().adjusted(-2, -2, 2, 2)
            painter.drawRect(rect)


class GlowFrame(QFrame):
    """A frame with optional glow effect."""
    
    def __init__(self, glow_color=COLORS['neon_cyan'], parent=None):
        super().__init__(parent)
        self.glow_color = glow_color
        self.glow_intensity = 0.0
        self.is_pulsing = False
        
        # Pulse animation
        self.pulse_timer = QTimer()
        self.pulse_timer.timeout.connect(self.update_pulse)
        self.pulse_direction = 1
        
    def set_pulsing(self, enabled: bool):
        """Enable or disable pulsing glow."""
        self.is_pulsing = enabled
        if enabled:
            self.pulse_timer.start(50)
        else:
            self.pulse_timer.stop()
            self.glow_intensity = 0.0
            self.update()
    
    def update_pulse(self):
        """Update pulse animation."""
        if self.is_pulsing:
            self.glow_intensity += self.pulse_direction * 0.05
            if self.glow_intensity >= 1.0:
                self.glow_intensity = 1.0
                self.pulse_direction = -1
            elif self.glow_intensity <= 0.0:
                self.glow_intensity = 0.0
                self.pulse_direction = 1
            self.update()
    
    def paintEvent(self, event):
        """Paint with glow effect."""
        super().paintEvent(event)
        
        if self.glow_intensity > 0:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            
            glow_color = QColor(self.glow_color)
            glow_color.setAlpha(int(100 * self.glow_intensity))
            
            painter.setPen(QPen(glow_color, 2))
            painter.setBrush(QBrush(glow_color))
            
            rect = self.rect().adjusted(-1, -1, 1, 1)
            painter.drawRect(rect)


class RiskIndicator(QWidget):
    """Custom risk level indicator widget."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.risk_level = 0  # 0-100
        self.risk_color = COLORS['neon_green']
        self.setMinimumHeight(30)
        self.setMinimumWidth(100)
        
    def set_risk(self, level: int):
        """Set risk level (0-100)."""
        self.risk_level = max(0, min(100, level))
        
        # Choose color based on level
        if self.risk_level < 30:
            self.risk_color = COLORS['neon_green']
        elif self.risk_level < 60:
            self.risk_color = COLORS['warning_yellow']
        else:
            self.risk_color = COLORS['danger_red']
        
        self.update()
    
    def paintEvent(self, event):
        """Paint risk indicator."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Background bar
        painter.fillRect(5, 10, self.width() - 10, 10, QColor(COLORS['bg_panel']))
        painter.drawRect(5, 10, self.width() - 10, 10)
        
        # Risk bar
        filled_width = int((self.width() - 10) * (self.risk_level / 100))
        painter.fillRect(5, 10, filled_width, 10, QColor(self.risk_color))
        
        # Border
        painter.setPen(QPen(QColor(self.risk_color), 1))
        painter.drawRect(5, 10, self.width() - 10, 10)
        
        # Text label
        painter.setPen(QPen(QColor(COLORS['text_secondary']), 1))
        painter.setFont(QFont("Courier New", 7))
        painter.drawText(10, 5, f"RISK: {self.risk_level}%")


class ConfidenceBar(QWidget):
    """Custom confidence level indicator."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.confidence = 0  # 0-100
        self.setMinimumHeight(20)
        self.setMinimumWidth(100)
    
    def set_confidence(self, level: int):
        """Set confidence level (0-100)."""
        self.confidence = max(0, min(100, level))
        self.update()
    
    def paintEvent(self, event):
        """Paint confidence bar."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Background
        painter.fillRect(0, 0, self.width(), self.height(), QColor(COLORS['bg_panel']))
        painter.setPen(QPen(QColor(COLORS['border_dark']), 1))
        painter.drawRect(0, 0, self.width() - 1, self.height() - 1)
        
        # Confidence bar (cyan)
        filled_width = int(self.width() * (self.confidence / 100))
        painter.fillRect(0, 0, filled_width, self.height(), QColor(COLORS['neon_cyan']))
        
        # Text
        painter.setPen(QPen(QColor(COLORS['text_secondary']), 1))
        painter.setFont(QFont("Courier New", 8))
        text = f"CONFIDENCE: {self.confidence}%"
        painter.drawText(5, 2, self.width() - 10, self.height(), Qt.AlignLeft | Qt.AlignVCenter, text)


class ScannerIndicator(QWidget):
    """Animated radar-style scanner indicator."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.angle = 0
        self.is_scanning = False
        
        # Animation timer
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.update_scan)
        
        self.setMinimumSize(150, 150)
        self.setMaximumSize(200, 200)
    
    def set_scanning(self, enabled: bool):
        """Start or stop scanning animation."""
        self.is_scanning = enabled
        if enabled:
            self.scan_timer.start(50)
        else:
            self.scan_timer.stop()
    
    def update_scan(self):
        """Update scanner animation."""
        self.angle = (self.angle + 3) % 360
        self.update()
    
    def paintEvent(self, event):
        """Paint scanner radar."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        center_x = self.width() // 2
        center_y = self.height() // 2
        radius = min(self.width(), self.height()) // 2 - 5
        
        # Draw circles (radar grid)
        painter.setPen(QPen(QColor(COLORS['neon_green']), 1))
        painter.setBrush(QBrush(QColor(COLORS['bg_panel'])))
        painter.drawEllipse(center_x - radius, center_y - radius, radius * 2, radius * 2)
        
        # Draw grid lines
        painter.setPen(QPen(QColor(COLORS['grid_lines']), 1))
        for i in range(1, 3):
            r = int(radius * (i / 3))
            painter.drawEllipse(center_x - r, center_y - r, r * 2, r * 2)
        
        # Draw crosshairs
        painter.setPen(QPen(QColor(COLORS['grid_lines']), 1))
        painter.drawLine(center_x - radius, center_y, center_x + radius, center_y)
        painter.drawLine(center_x, center_y - radius, center_x, center_y + radius)
        
        # Draw scanning sweep
        painter.setPen(QPen(QColor(COLORS['neon_cyan']), 2))
        painter.drawLine(center_x, center_y, 
                        int(center_x + radius * __import__('math').cos(__import__('math').radians(self.angle))),
                        int(center_y + radius * __import__('math').sin(__import__('math').radians(self.angle))))
        
        # Draw inner glow
        if self.is_scanning:
            glow_color = QColor(COLORS['neon_cyan'])
            glow_color.setAlpha(50)
            painter.setBrush(QBrush(glow_color))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(center_x - 5, center_y - 5, 10, 10)


class ActivityWave(QWidget):
    """Animated waveform activity indicator."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.activity_level = 0
        self.wave_offset = 0
        self.is_animating = False
        
        self.wave_timer = QTimer()
        self.wave_timer.timeout.connect(self.update_wave)
        
        self.setMinimumHeight(60)
    
    def set_activity(self, level: int):
        """Set activity level (0-100)."""
        self.activity_level = max(0, min(100, level))
        self.update()
    
    def start_animation(self):
        """Start wave animation."""
        self.is_animating = True
        self.wave_timer.start(50)
    
    def stop_animation(self):
        """Stop wave animation."""
        self.is_animating = False
        self.wave_timer.stop()
        self.update()
    
    def update_wave(self):
        """Update wave animation."""
        self.wave_offset = (self.wave_offset + 2) % 360
        self.update()
    
    def paintEvent(self, event):
        """Paint waveform."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Background
        painter.fillRect(self.rect(), QColor(COLORS['bg_panel']))
        painter.drawRect(self.rect())
        
        # Draw waveform
        painter.setPen(QPen(QColor(COLORS['neon_cyan']), 2))
        
        import math
        points = []
        for x in range(self.width()):
            y_val = self.activity_level / 100.0 * self.height() / 3
            y = self.height() // 2 + int(y_val * math.sin(math.radians(x * 2 + self.wave_offset)))
            points.append((x, y))
        
        for i in range(len(points) - 1):
            painter.drawLine(int(points[i][0]), int(points[i][1]), 
                           int(points[i+1][0]), int(points[i+1][1]))
        
        # Draw axis line
        painter.setPen(QPen(QColor(COLORS['grid_lines']), 1))
        painter.drawLine(0, self.height() // 2, self.width(), self.height() // 2)


class StatusIndicator(QWidget):
    """Blinking status indicator."""
    
    def __init__(self, status_text="IDLE", color=COLORS['neon_green'], parent=None):
        super().__init__(parent)
        self.status_text = status_text
        self.color = color
        self.blink_state = True
        
        self.blink_timer = QTimer()
        self.blink_timer.timeout.connect(self.toggle_blink)
        self.blink_timer.start(500)
        
        self.setMinimumSize(24, 24)
    
    def set_status(self, text: str, color: str = None):
        """Update status text and color."""
        self.status_text = text
        if color:
            self.color = color
        self.update()
    
    def toggle_blink(self):
        """Toggle blink state."""
        self.blink_state = not self.blink_state
        self.update()
    
    def paintEvent(self, event):
        """Paint status indicator."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw indicator circle
        if self.blink_state:
            painter.setBrush(QBrush(QColor(self.color)))
        else:
            painter.setBrush(QBrush(QColor(COLORS['bg_panel'])))
        
        painter.setPen(QPen(QColor(self.color), 2))
        painter.drawEllipse(2, 2, 20, 20)
