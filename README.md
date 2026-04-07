Advanced Network Vulnerability Scanner
Identify active devices, open ports, OS versions, and potential vulnerabilities using Nmap and ARP scans. Choose between three scan levels for tailored depth and speed!

Key Features:
Three Scan Levels:
Basic: Fast detection of OS, services, and common vulnerabilities (-O -sV --script=vuln).
Advanced: Full TCP port scan + top UDP ports with aggressive checks (-p- --top-ports 1000 -A -sS -sU).
Extreme: Exhaustive check including brute-force and custom scripts (-p- -A -sS -sU --script=brute).
Scanning Flow: ARP scan → OS detection → open port analysis → vulnerability checks.
Report Generation: Save results to text files with timestamps (e.g., scan_report_Advanced_2023-10-25.txt).

Usage Example:

sudo python3 network_scanner.py 

[*] Network Scanner
Scan Levels:
1. Basic (Fast - OS, services, basic vulns)
2. Advanced (TCP all ports + Top 1000 UDP + full scripts)
3. Extreme (All TCP/UDP + brute-force + aggressive scans)
[?] Select scan level (1-3): 2
[?] Enter IP range/subnet (e.g., 192.168.1.0/24): 10.0.0.0/24
[*] Scanning network 10.0.0.0/24 for live hosts...
[+] Host 10.0.0.53 (MAC: 00:1B:7A:AA:BB:CC)
    [VULN] ssh-hostkey: SSH host key fingerprint (RSA) found.
    OS Detection:
      - Ubuntu Linux 22.04 LTS (Accuracy: 95%)


Dependencies:
Python 3+
scapy (pip install scapy)
python-nmap (pip install python-nmap)
Nmap installed on the system (sudo apt install nmap).

Installation:

git clone https://github.com/your-repo/advanced-scanner.git
cd advanced-scanner
# Ensure required modules are installed:
pip install -r requirements.txt  # (optional: create a requirements file for scapy and python-nmap) 

Run the Scanner:

sudo python3 full_scanner.py  

Troubleshooting Tips:
Always run as root/sudo to access Nmap’s full capabilities.
Test on networks where you have permission (compliance with legal/ethical guidelines is your responsibility).
If no hosts are found, try using a smaller subnet range (e.g., 192.168.0.0/24).
Contributing:
Report bugs or suggest features here. PRs for improved error handling, new scripts, and performance optimizations are welcome!

This README emphasizes the tool’s versatility while highlighting its user-friendly design. Feel free to customize further or add badges (e.g., code quality, CI status) if you’re publishing the repo publicly. 😊


3 Citations


26.09 tok/sec
1238 tokens
10.99s
Stop reason: EOS Token Found
