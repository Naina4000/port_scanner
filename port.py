import socket
import argparse
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

print("""
====================================
      SOC Port Exposure Monitor
====================================
""")

# -------------------- Argument Parser --------------------
parser = argparse.ArgumentParser(description="SOC-Focused Multi-threaded Port Scanner")
parser.add_argument("-t", "--target", required=True, help="Target IP Address or Domain")
parser.add_argument("-sp", "--startport", type=int, default=1, help="Start Port")
parser.add_argument("-ep", "--endport", type=int, default=1024, help="End Port")

args = parser.parse_args()

target_input = args.target
start_port = args.startport
end_port = args.endport

# -------------------- Resolve Domain --------------------
try:
    target = socket.gethostbyname(target_input)
except socket.gaierror:
    print("Invalid target.")
    exit()

print(f"Scanning Target: {target} ({target_input})")
print(f"Port Range: {start_port} - {end_port}")
print("Scan started at:", datetime.now())
print("-" * 50)

# -------------------- Load Risk Database --------------------
try:
    with open("risk_database.json", "r") as db_file:
        risk_db = json.load(db_file)
except FileNotFoundError:
    print("risk_database.json file not found.")
    exit()

open_ports = []

# -------------------- Port Scan Function --------------------
def scan_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))

        if result == 0:
            try:
                detected_service = socket.getservbyport(port)
            except:
                detected_service = "Unknown"

            try:
                banner = s.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "No Banner"

            port_str = str(port)

            if port_str in risk_db:
                risk_info = risk_db[port_str]
                service_name = risk_info["service"]
                risk_level = risk_info["risk_level"]
                description = risk_info["description"]
            else:
                service_name = detected_service
                risk_level = "Low"
                description = "No known major risks recorded."

            print(f"[OPEN] Port {port} | Risk: {risk_level}")

            open_ports.append({
                "port": port,
                "service": service_name,
                "banner": banner,
                "risk_level": risk_level,
                "description": description
            })

        s.close()

    except:
        pass


# -------------------- Multi-threaded Scan --------------------
ports = range(start_port, end_port + 1)

with ThreadPoolExecutor(max_workers=200) as executor:
    executor.map(scan_port, ports)

# -------------------- File Names --------------------
scan_filename = f"scan_{target}.json"
compare_filename = f"compare_{target}.json"

# -------------------- Load Previous Scan --------------------
previous_ports = []

if os.path.exists(scan_filename):
    with open(scan_filename, "r") as old_file:
        old_data = json.load(old_file)
        previous_ports = [entry["port"] for entry in old_data["open_ports"]]

current_ports = [entry["port"] for entry in open_ports]

new_ports = list(set(current_ports) - set(previous_ports))
closed_ports = list(set(previous_ports) - set(current_ports))

# -------------------- Always Create Comparison File --------------------
compare_data = {
    "target": target,
    "timestamp": str(datetime.now()),
    "new_ports": new_ports,
    "closed_ports": closed_ports,
    "status": "Changes detected" if (new_ports or closed_ports) else "No changes detected"
}

with open(compare_filename, "w") as compare_file:
    json.dump(compare_data, compare_file, indent=4)

if new_ports or closed_ports:
    print("\n[CHANGE DETECTED]")
    if new_ports:
        print(f"Newly Opened Ports: {new_ports}")
    if closed_ports:
        print(f"Closed Ports: {closed_ports}")
else:
    print("\nNo changes detected from previous scan.")

print(f"Comparison report saved as {compare_filename}")

# -------------------- Always Save New Scan --------------------
scan_data = {
    "target": target,
    "original_input": target_input,
    "timestamp": str(datetime.now()),
    "open_ports": open_ports
}

with open(scan_filename, "w") as f:
    json.dump(scan_data, f, indent=4)

print("\nScan Completed.")
print(f"Total Open Ports Found: {len(open_ports)}")
print(f"Report saved as {scan_filename}")
