Network Scanner
Identify active devices, open ports, OS versions, and potential vulnerabilities using Nmap and ARP scans. Choose between three scan levels for tailored depth and speed!

Key Features:
Three Scan Levels:
Basic: Fast detection of OS, services, and common vulnerabilities (-O -sV --script=vuln).
Advanced: Full TCP port scan + top UDP ports with aggressive checks (-p- --top-ports 1000 -A -sS -sU).
Extreme: Exhaustive check including brute-force and custom scripts (-p- -A -sS -sU --script=brute).
Scanning Flow: ARP scan → OS detection → open port analysis → vulnerability checks.
Report Generation: Save results to text files with timestamps (e.g., scan_report_Advanced_2023-10-25.txt).

# Dependencies:

Python 3+. We recommend to create a virtual environment to avoid breaking system packages

`python -m venv path/to/venv/`

`. ./venv/bin/activate`

scapy

`pip install scapy`

python-nmap

`pip install python-nmap`

Nmap installed on the system 

`sudo apt install nmap`


# Installation:

`git clone https://github.com/your-repo/advanced-scanner.git`

`cd advanced-scanner`

# Ensure required modules are installed:

`pip install -r requirements.txt`

# Run the Scanner:

`sudo python3 network_scanner.py`

# Troubleshooting Tips:

Always run as root/sudo to access Nmap’s full capabilities.
Test on networks where you have permission (compliance with legal/ethical guidelines is your responsibility).
If no hosts are found, try using a smaller subnet range (e.g., 192.168.0.0/24).

# Contributing:

Report bugs or suggest features here. PRs for improved error handling, new scripts, and performance optimizations are welcome!
