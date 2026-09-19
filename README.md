# Netcat — Deep Packet Inspection & Threat Detection Suite

Netcat is a high-performance network monitoring, deep packet inspection (DPI), threat detection, and forensic analysis application built with Python (PyQt6 GUI) and C++.

## Features

- **Deep Packet Inspection (DPI)**: High-speed C++ DPI engine for packet parsing, SNI extraction, and fast path connection tracking.
- **Threat Detection Engine**: Real-time packet analysis, security rule evaluation, and active blocking capability.
- **Forensic & Security Logging**: SQLite-backed incident database, event auditing, and activity logging.
- **Interactive Dashboard**: PyQt6 desktop UI with live interface monitoring, traffic statistics, and real-time visualization charts.
- **Automated PDF & Markdown Reporting**: Automated incident analysis and summary report generation.

## Getting Started

### Prerequisites

- Python 3.11+
- Npcap / WinPcap installed (for Windows packet capture)
- C++ Compiler & CMake (if rebuilding the DPI engine)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/dashmeet2023/Netcat.git
   cd Netcat
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Usage

Run `netcat_app.py` (with administrator privileges required for raw packet capture):
```bash
python netcat_app.py
```

## Project Structure

- `netcat_app.py`: Main entry point for the PyQt6 application.
- `netcat/`: Core Python modules (GUI, detector, DPI wrapper, database manager, blocker, reporter).
- `Packet_analyzer_extracted/`: C++ source code for the high-performance DPI engine.
- `requirements.txt`: Python package dependencies.
