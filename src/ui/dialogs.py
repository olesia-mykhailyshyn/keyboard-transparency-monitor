"""
Dialog windows for user interactions and warnings.

Includes:
- Trade-off warnings when blocking processes
- Privacy guarantee display
- Ethical warning system
- Input dialogs for user decisions
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTextEdit, QCheckBox, QMessageBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QPixmap, QIcon


class TradeoffDialog(QDialog):
    """Dialog explaining trade-offs of blocking a process."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Blocking Trade-offs")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        # Title
        title = QLabel("⚠️  Blocking a Process - Trade-offs")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Content
        content = QTextEdit()
        content.setReadOnly(True)
        content.setText("""
<h3>Potential Benefits:</h3>
<ul>
  <li>✓ Improves privacy by preventing process execution</li>
  <li>✓ Gives you control over what runs on your system</li>
  <li>✓ Can prevent malicious behavior</li>
</ul>

<h3>Potential Risks:</h3>
<ul>
  <li>✗ May break legitimate application functionality</li>
  <li>✗ Could affect system features or accessibility tools</li>
  <li>✗ May cause unexpected behavior</li>
  <li>✗ Might prevent software updates or background services</li>
</ul>

<h3>Recommendation:</h3>
<p>Only block processes you're certain are suspicious.
If unsure, use "Ignore" or "Monitor" instead.</p>
        """)
        layout.addWidget(content)

        # Confirmation
        understanding = QCheckBox("I understand the risks and want to block this process")
        layout.addWidget(understanding)

        # Buttons
        button_layout = QHBoxLayout()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        ok_btn = QPushButton("Block Process")
        ok_btn.setStyleSheet("QPushButton { background-color: #f44336; }")
        ok_btn.clicked.connect(self.accept)
        ok_btn.setEnabled(False)
        understanding.toggled.connect(ok_btn.setEnabled)
        button_layout.addWidget(ok_btn)

        layout.addLayout(button_layout)
        self.setLayout(layout)


class PrivacyGuaranteeDialog(QDialog):
    """Dialog displaying privacy guarantee."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Privacy Guarantee")
        self.setGeometry(100, 100, 600, 300)

        layout = QVBoxLayout()

        # Icon and title
        title = QLabel("🔒 Your Privacy is Protected")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Content
        content = QLabel("""
<h3>Privacy Guarantee</h3>

<p><b>This application does NOT:</b></p>
<ul>
  <li>✗ Capture your keystrokes</li>
  <li>✗ Store keystroke data</li>
  <li>✗ Record what you type</li>
  <li>✗ Send data to external servers</li>
  <li>✗ Track your activity</li>
</ul>

<p><b>This application ONLY:</b></p>
<ul>
  <li>✓ Analyzes process metadata (names, paths, resources)</li>
  <li>✓ Stores analysis results locally on your device</li>
  <li>✓ Uses heuristics to detect suspicious behavior</li>
  <li>✓ Respects your complete control and privacy</li>
</ul>

<p>All data is stored locally. You have full control over what is monitored.</p>
        """)
        layout.addWidget(content)

        # OK button
        ok_btn = QPushButton("Understood")
        ok_btn.clicked.connect(self.accept)
        layout.addWidget(ok_btn)

        self.setLayout(layout)


class EthicalWarningDialog(QDialog):
    """Dialog warning user about blocking too many processes."""

    def __init__(self, parent=None, blocked_count: int = 0):
        super().__init__(parent)
        self.setWindowTitle("⚠️ Ethical Warning")
        self.setGeometry(100, 100, 600, 350)

        layout = QVBoxLayout()

        # Title
        title = QLabel("⚠️  System Health Warning")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Content
        content = QTextEdit()
        content.setReadOnly(True)
        content.setText(f"""
<h3>You have blocked {blocked_count} processes.</h3>

<h3>Considerations:</h3>
<ul>
  <li><b>System Stability:</b> Blocking too many processes may cause system instability</li>
  <li><b>Functionality:</b> Essential services may be affected</li>
  <li><b>Accessibility:</b> Accessibility features or productivity tools might be blocked</li>
  <li><b>Updates:</b> Software updates or critical patches may not run</li>
</ul>

<h3>Recommendations:</h3>
<ul>
  <li>Verify each blocked process is truly suspicious</li>
  <li>Use "Ignore" for borderline processes</li>
  <li>Monitor system behavior after making changes</li>
  <li>Consider unblocking processes that cause issues</li>
</ul>

<p><b>Remember:</b> This tool is for transparency and informed decision-making,
not aggressive system hardening.</p>
        """)
        layout.addWidget(content)

        # Buttons
        button_layout = QHBoxLayout()

        ok_btn = QPushButton("I'll be careful")
        ok_btn.clicked.connect(self.accept)
        button_layout.addWidget(ok_btn)

        button_layout.addStretch()
        layout.addLayout(button_layout)

        self.setLayout(layout)


class InputExplanationDialog(QDialog):
    """Dialog explaining why a process is considered to have input access."""

    def __init__(self, process_name: str, indicators: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Why {process_name} Detected?")
        self.setGeometry(100, 100, 600, 400)

        layout = QVBoxLayout()

        # Title
        title = QLabel(f"Why is {process_name} flagged?")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Explanation
        explanation = QLabel("""
This process shows signs that may indicate keyboard/input device access attempts.

We detected the following suspicious patterns:
        """)
        layout.addWidget(explanation)

        # Indicators
        indicators_text = QTextEdit()
        indicators_text.setReadOnly(True)
        content = "<ul>"
        for indicator in indicators:
            content += f"<li>{indicator}</li>"
        content += "</ul>"
        indicators_text.setText(content)
        layout.addWidget(indicators_text)

        # Uncertainty note
        note = QLabel("""
<b>Note:</b> This is a heuristic-based detection. The process may be:
• Legitimately using input APIs (accessibility tools, game controllers, etc.)
• Running under false suspicion due to name/path patterns
• Part of your normal workflow

Please make an informed decision based on whether you recognize this process.
        """)
        note.setWordWrap(True)
        note.setStyleSheet("color: #666; padding: 10px; background-color: #f9f9f9; border-radius: 4px;")
        layout.addWidget(note)

        # OK button
        ok_btn = QPushButton("Understood")
        ok_btn.clicked.connect(self.accept)
        layout.addWidget(ok_btn)

        self.setLayout(layout)


class SafeProcessExplanationDialog(QDialog):
    """Dialog explaining why a process is considered safe."""

    def __init__(self, process_name: str, reasons: list, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Why {process_name} is Safe")
        self.setGeometry(100, 100, 600, 300)

        layout = QVBoxLayout()

        # Title
        title = QLabel(f"✅ Why {process_name} is Considered Safe")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)

        # Explanation
        explanation = QTextEdit()
        explanation.setReadOnly(True)
        content = "<ul>"
        for reason in reasons:
            content += f"<li>{reason}</li>"
        content += "</ul>"
        explanation.setText(content)
        layout.addWidget(explanation)

        # OK button
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        layout.addWidget(ok_btn)

        self.setLayout(layout)
