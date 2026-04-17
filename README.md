# Keyboard Transparency Monitor

A proof-of-concept system designed to detect and alert when running processes may be attempting unauthorized access to keyboard input devices on Windows systems. This project demonstrates modern software architecture principles through a hybrid Python backend with PySide6 desktop UI and a React 18+ web frontend.

## What This System Does

The Keyboard Transparency Monitor continuously scans running processes and evaluates them against multiple risk signals to identify potentially malicious keyboard monitoring activity. The system uses a weighted scoring algorithm that analyzes process metadata including executable names, file paths, system privileges, handle counts, digital signatures, and behavioral patterns. When a process reaches a risk threshold, the system generates an alert and stores comprehensive details in a local SQLite database for audit purposes. Users can manually block or trust processes, and the system tracks all user decisions for transparency and accountability.

## Why It Exists

This project was created for Brown University's CS1952B course to demonstrate competency in full-stack systems design. It showcases experience with multi-threaded backend architecture, database design, user interface development across multiple platforms, and the practical constraints of modern operating systems. The system intentionally explores real limitations in detecting input device access on Windows, providing educational value about OS-level security boundaries that developers must understand.

## Quick Start

After cloning the repository, follow these steps to set up and run the system.

### Prerequisites

Ensure you have Python 3.8 or higher installed on your system. You can verify this by opening a terminal and running `python --version`. The system requires Windows 10 or Windows 11 for full functionality, though parts of the codebase support macOS and Linux with degraded capabilities.

### Installation & Environment Setup

Begin by creating a Python virtual environment to isolate dependencies. Open a terminal in the cloned project directory and run `python -m venv .venv` to create a virtual environment. On Windows, activate it with `.venv\Scripts\activate`. On macOS or Linux, use `source .venv/bin/activate`.

With the virtual environment activated, install all required dependencies by running `pip install -r requirements.txt`. This will install PySide6 for the desktop interface, psutil for process monitoring, Flask for the API layer, and other supporting libraries. The installation typically takes 2-3 minutes depending on your internet connection.

### Running the Application

The system offers two ways to run, depending on what you want to test.

To launch the application with a simulated process list (demo mode), execute `python app.py --demo`. This mode does not require administrator privileges and demonstrates the full user interface with seven pre-configured suspicious processes at varying risk levels. Demo mode is ideal for testing the UI, understanding how the system scores processes, and exploring the interface without needing to monitor your actual system processes.

To run the application against real running processes on your system, simply execute `python app.py` without any flags. Note that real-time monitoring of actual processes on Windows requires administrator privileges, so run the application as Administrator for full functionality. The application will show genuine running processes and score them based on real metadata.

## Understanding the Architecture

The system is organized into several key layers that communicate with each other. The platform layer handles Windows-specific operations including process scanning and keyboard detection heuristics. The core layer contains the main business logic, including the risk scoring engine that evaluates processes, services for managing process monitoring, and managers for alerts and user actions. The storage layer provides SQLite database functionality with repository pattern implementation for clean data access. The UI layer includes both the PySide6 desktop application with a cyberpunk aesthetic and API endpoints that support the React web frontend. All components communicate through well-defined interfaces and use threading to ensure the UI remains responsive during background monitoring operations.

## Important Limitations: Why Only Demo Works for Real Detection

The system cannot achieve reliable real-time keyboard detection due to fundamental limitations in Windows architecture and API restrictions. This limitation does not represent a code quality issue but rather reflects real-world constraints that even professional antivirus software must work around.

Windows deliberately restricts unprivileged user-mode applications from directly accessing raw input device data. The keyboard driver and raw input events exist at the kernel level, and Microsoft does not provide standard APIs for user-mode processes to inspect which applications are currently accessing input devices. This design choice exists to protect user security by preventing arbitrary applications from snooping on keyboard input used for passwords and sensitive operations.

The system attempts multiple heuristic detection methods including analyzing process names for keywords like "keylogger" or "hook", examining file paths for suspicious locations like TEMP directories, inspecting handle counts for abnormal numbers that might indicate I/O monitoring, validating digital signatures of executables, and analyzing parent-child process relationships. While these heuristics successfully identify obvious and careless keylogging attempts, a sophisticated attacker can easily bypass them by using a legitimate process name, placing the executable in a normal system directory, and implementing advanced evasion techniques like DLL injection or code hooking at a low level.

Detecting actual keyboard access would require either a kernel-mode driver with full system privileges, which is what commercial antivirus software uses but requires extensive Microsoft certification, or ETW (Event Tracing for Windows) with administrator-level access and complex event filtering. Both approaches are beyond the scope of this educational project and would add hundreds of hours of development time.

For these reasons, the practical implementation is limited to demo mode where the system can show its architectural design and UI capabilities without making unsupportable claims about real detection accuracy. The demo mode contains seven simulated processes with varying risk profiles that demonstrate how the scoring system works in practice. Real-time monitoring of actual system processes is available but provides only heuristic-based detection that will miss sophisticated attacks.

## Running the Demo

The demo mode is the recommended way to explore the system and understand its capabilities. Launch it with `python app.py --demo`. The interface shows a modern cyberpunk-themed dashboard with a table of processes, each displaying its name, process ID, calculated risk score, status indicator, and available actions. The demo includes seven simulated processes ranging from obviously suspicious ones like "keylogger.exe" that score 95% as CRITICAL, to legitimately suspicious names like "monitor.exe" that score 45% as MEDIUM, down to system processes like "explorer.exe" that correctly score 12% as LOW risk.

You can interact with the demo by clicking on processes to see detailed information, manually marking processes as trusted or blocked, and observing how the risk scoring algorithm evaluates different suspicious characteristics. The demo updates in real time as you interact with it and stores your decisions in the local database. This provides a complete demonstration of the system's architecture and UI without the limitations of real keyboard detection.

## Project Structure

The source code is organized under the `src/` directory with clear separation of concerns. The `core/` subdirectory contains the risk scoring engine, process scanning logic, alert management, and user action logging. The `platform/` subdirectory handles platform-specific operations with adapters for Windows, macOS, and Linux. The `storage/` subdirectory manages SQLite database connections and implements repositories for data access. The `ui/` subdirectory contains the PySide6 desktop application code, including the main window, various UI panels and dialogs, and a cyberpunk-themed styling system. Tests are provided in the `tests/` directory, and demo simulation code is in the `demo/` directory.

Comprehensive architecture documentation is available in the `docs/` directory, including fourteen UML diagrams covering different abstraction levels from component diagrams to sequence diagrams to database schemas. An interactive HTML viewer is provided at `docs/diagrams-viewer.html` that allows exploring all diagrams in your browser without additional tools.

## Building and Development

The system uses standard Python tooling. After setting up the virtual environment and installing dependencies, you can run the application directly with Python. For development, the codebase is organized for easy navigation and modification. The demo mode is isolated from production code, making it safe to experiment. The database schema is defined in `src/storage/database.py` and can be inspected or modified through standard SQLite tools.

## Documentation

Comprehensive documentation about the system architecture, design decisions, and detected problems is available in the `docs/` directory. Start with `RENDERING_GUIDE.md` to understand how to view the UML diagrams. The `SPECIFICATION.md` file provides detailed technical specifications. All diagrams are in PlantUML format and can be viewed online at plantuml.com/plantuml, rendered locally with PlantUML tools, or viewed interactively in the browser using the provided HTML viewer.

## Project Status

The system represents a fully functional proof-of-concept implementation demonstrating modern software architecture, effective UI design, comprehensive database modeling, and practical understanding of OS-level security constraints. The demo mode works perfectly and showcases all system capabilities. Real-time monitoring of actual processes is available but operates with heuristic-based detection rather than guaranteed accuracy due to the Windows API limitations discussed above. This project successfully achieves its educational goal of demonstrating full-stack systems design and architectural knowledge.
