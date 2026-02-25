import socket
import argparse
import json
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
    print("Risk database file not found.")
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
                service = socket.getservbyport(port)
            except:
                service = "Unknown"

            try:
                banner = s.recv(1024).decode().strip()
            except:
                banner = "No Banner"

            port_str = str(port)

            if port_str in risk_db:
                risk_info = risk_db[port_str]
                risk_level = risk_info["risk_level"]
                description = risk_info["description"]
            else:
                risk_level = "Low"
                description = "No known major risks recorded."

            print(f"[OPEN] Port {port} | Service: {service}")
            print(f"Risk Level: {risk_level}")
            print(f"Description: {description}")
            print("-" * 50)

            if risk_level == "High":
                print(f"[ALERT] HIGH RISK SERVICE DETECTED ON PORT {port}")

            open_ports.append({
                "port": port,
                "service": service,
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

# -------------------- JSON Report Generation --------------------
scan_data = {
    "target": target,
    "original_input": target_input,
    "timestamp": str(datetime.now()),
    "open_ports": open_ports
}

filename = f"scan_{target}.json"

with open(filename, "w") as f:
    json.dump(scan_data, f, indent=4)

print("\nScan Completed.")
print(f"Total Open Ports Found: {len(open_ports)}")
print(f"Report saved as {filename}")
