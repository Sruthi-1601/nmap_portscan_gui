# nmap_portscan_gui
Network Port Scanner - Internship Project

A Python desktop application with a GUI for network security analysis and port scanning. Built with Tkinter and Nmap, this tool allows users to scan any target IP address and discover open, closed, and filtered ports — with real-time animations, color-coded results, and export features.

Features

Custom Port Range — Scan any range from port 1 to 65,535
Service Name Detection — Automatically identifies services (Port 22 = SSH, Port 80 = HTTP, etc.)
Color-Coded Results — Open ports in green, Closed in red, Filtered in amber
Typewriter Animation — Results appear character by character like a real terminal
Radar Spinner — Rotating radar animation in the corner during scanning
Button Pulse Animation — Start Scan button pulses while scan is active
Background Threading — UI never freezes during long scans
Animated Progress Bar — Visual progress indicator during every scan
Live Elapsed Timer — Shows how many seconds the scan has been running
Export Results — Save full scan report as .txt or .csv file
Scan Summary — Shows total Open / Closed / Filtered count after every scan
Professional Clean UI — Minimal white and grey theme


Technologies Used
TechnologyPurposePython 3Core programming languageTkinterGUI frameworkNmapNetwork scanning enginepython-nmapPython wrapper for NmapThreadingBackground scanning (UI stays live)SocketService name lookupMathRadar animation calculationsDatetimeTimestamps and elapsed time

Requirements

Python 3.x
Nmap installed on your system
python-nmap library


Installation
Step 1 — Install Python
Download and install Python from python.org.
During installation, make sure to tick "Add Python to PATH".
Step 2 — Install Nmap
Download and install Nmap from nmap.org/download.html.
Step 3 — Install python-nmap
Open Command Prompt and run:
pip install python-nmap

How to Run
python portscanergui.py

How to Use

Enter the Target IP address or hostname (e.g. 127.0.0.1 for your own computer)
Set the Port Range (e.g. Start: 1, End: 1024)
Optionally enable Service Detection (-sV) or OS Detection (-O)
Click Start Scan
Watch results appear in real time with color coding
Click Save Results to export as .txt or .csv


Port States Explained
StateMeaningOpenA service is actively running and accepting connectionsClosedPort is reachable but no service is runningFilteredA firewall is blocking — scanner cannot determine the state

Project Structure
nmap_portscan_gui/
├── portscanergui.py    # Main application file
└── README.md           # Project documentation

Internship Details

Internship — VOIS AICTE Internship — Batch 3
Domain — Cyber Security
Project — Network Port Scanner with GUI
Year — 2026


Disclaimer
This tool is built for educational purposes as part of the VOIS AICTE Internship program. Only scan networks and devices you have permission to scan. Unauthorized port scanning may be illegal.

Author
Kothamasi Sruthi
Stanley College of Engineering and Technology for Women
