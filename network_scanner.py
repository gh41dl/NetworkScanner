import scapy.all as scapy
import nmap
from datetime import datetime
import os

def get_user_input():
    """Prompt the user to select scan level."""
    print("\n[*] Network Scanner")
    print("=" * 60)
    print("Scan Levels:")
    print("1. Basic (Fast - OS, services, basic vulns)")
    print("2. Advanced (TCP all ports + Top 1000 UDP + full scripts)")
    print("3. Extreme (All TCP/UDP + brute-force + aggressive scans)")
    level = input("[?] Select scan level (1-3): ").strip()
    ip_range = input(
        "[?] Enter IP range/subnet [default:192.168.1.0/24]: "
    ).strip()

    if not ip_range:
        print("[-] No input provided. Using default: 192.168.1.0/24")
        ip_range = "192.168.1.0/24"

    return level, ip_range

def scan_network(ip_range):
    """Scan the network using ARP to find live hosts."""
    print(f"\n[*] Scanning network {ip_range} for live hosts...")
    arp_request_broadcast = scapy.ARP(pdst=ip_range)
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    arp_request = scapy.Ether(dst=broadcast_mac) / arp_request_broadcast
    answered_list, unanswered_list = scapy.srp(
        arp_request, timeout=1, verbose=False
    )

    live_hosts = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        live_hosts.append({"ip": ip, "mac": mac})

    return live_hosts


def basic_scan(nm, host):
    """Basic scan: OS, services, and quick vuln checks."""
    nm.scan(hosts=host["ip"], arguments="-O -sV --script=vuln")
    report = f"[+] Host {host['ip']} (MAC: {host['mac']})\n"

    # Check if the IP is present in Nmap results
    if host["ip"] not in nm.all_hosts():
        return f"[-] Failed to retrieve scan data for host {host['ip']}."

    if nm[host["ip"]].state() == "up":
        report += "[+] OS Detection:\n"
        os_matches = nm[host["ip"]].get("osmatch", [])
        for os in os_matches:
            report += f"  - {os['name']} (Accuracy: {os['accuracy']}%)\n"

        # Add error handling here if 'all_protocols' is missing
        try:
            all_protos = nm[host["ip"]].all_protocols()
        except KeyError:
            all_protos = []

        report += "[+] Open Ports:\n"
        for proto in all_protos:
            ports = nm[host["ip"]][proto].keys()
            for port in ports:
                service = nm[host["ip"]][proto][port]
                report += f"  - {port}/{proto}: {service['name']} (Version: {service.get('version', 'Unknown')})\n"

        if "script" in nm[host["ip"]]:
            for script_id, output in nm[host["ip"]]["script"].items():
                report += f"  - [VULN] {script_id}: {output}\n"
    else:
        return f"[!] Host {host['ip']} is down or unreachable."

    return report


def advanced_scan(nm, host):
    """Advanced scan: All TCP ports + Top 1000 UDP + full scripts."""
    nm.scan(hosts=host["ip"], arguments="-p- --top-ports 1000 -A -sS -sU --script=vulners,exploit")
    report = f"[+] Host {host['ip']} (MAC: {host['mac']})\n"
    if nm[host["ip"]].state() == "up":
        try:
            report += "[+] OS Detection:\n"
            for os in nm[host["ip"]]["osmatch"]:
                report += f"  - {os['name']} (Accuracy: {os['accuracy']}%)\n"
        except KeyError:
            pass

        report += "[+] Open Ports & Vulnerabilities:\n"
        for proto in nm[host["ip"]].all_protocols():
            ports = nm[host["ip"]][proto].keys()
            for port in ports:
                service = nm[host["ip"]][proto][port]
                report += f"  - Port: {port}/{proto}\n"
                if 'script' in service and isinstance(service['script'], dict):
                    script_output = "\n    ".join([f"{k}: {v}" for k, v in service['script'].items()])
                    report += f"    [VULN] Scripts Found:\n    {script_output}\n"
        # Add OS-specific scripts output
        if "osscript" in nm[host["ip"]]:
            report += "[+] OS-Specific Vulnerabilities:\n"
            for script_id, output in nm[host["ip"]]["osscript"].items():
                report += f"    - {script_id}: {output}\n"

    return report


def extreme_scan(nm, host):
    """Extreme scan: All TCP/UDP + brute-force + aggressive methods."""
    nm.scan(hosts=host["ip"], arguments="-p- -A --min-rate 1000 -T5 --script=vulners,exploit,brute,nmap VulnDB --open")
    report = f"[+] Host {host['ip']} (MAC: {host['mac']})\n"
    if nm[host["ip"]].state() == "up":
        try:
            report += "[+] OS Detection:\n"
            for os in nm[host["ip"]]["osmatch"]:
                report += f"  - {os['name']} (Accuracy: {os['accuracy']}%)\n"
        except KeyError:
            pass

        report += "[+] Open Ports & Vulnerabilities:\n"
        # Collect both TCP and UDP results
        for proto in nm[host["ip"]].all_protocols():
            ports = sorted(nm[host["ip"]][proto].keys())  # Sort output for readability
            for port in ports:
                service = nm[host["ip"]][proto][port]
                report += f"    - Port: {port}/{proto}\n"
                if 'script' in service and isinstance(service['script'], dict):
                    script_output = "\n      ".join([f"{k}: {v}" for k, v in service['script'].items()])
                    report += f"      [VULN] Scripts Found:\n      {script_output}\n"

        # Add OS-specific scripts output
        if "osscript" in nm[host["ip"]]:
            report += "[+] OS-Specific Vulnerabilities:\n"
            for script_id, output in nm[host["ip"]]["osscript"].items():
                report += f"    - {script_id}: {output}\n"

    return report



def save_report(report_data, scan_level):
    """Save the scan results to a text file."""
    scan_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_report_{scan_level}_{scan_time}.txt"
    with open(filename, "w") as f:
        f.write(f"Network Vulnerability Scan Report - {scan_level} Level\n")
        f.write("=" * 60 + "\n\n")
        f.write(report_data)
    print(f"\n[+] {scan_level} report saved to '{filename}'.")

def main():
    level, ip_range = get_user_input()
    scan_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    live_hosts = scan_network(ip_range)

    if not live_hosts:
        print("[-] No live hosts found.")
        return

    nm = nmap.PortScanner()

    # Basic Scan (Fast)
    if level == "1":
        report_data = ""
        for host in live_hosts:
            report_data += basic_scan(nm, host)
        save_report(report_data, "Basic")

    # Advanced Scan
    elif level == "2":
        report_data = ""
        for host in live_hosts:
            print(f"\n[*] Running Advanced scan on {host['ip']}...")
            report_data += advanced_scan(nm, host)
        save_report(report_data, "Advanced")

    # Extreme Scan (Slowest)
    elif level == "3":
        report_data = ""
        for host in live_hosts:
            print(f"\n[*] Running Extreme scan on {host['ip']}...")
            report_data += extreme_scan(nm, host)
        save_report(report_data, "Extreme")
    else:
        print("[-] Invalid scan level. Exiting.")

if __name__ == "__main__":
    main()
