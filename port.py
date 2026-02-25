import socket
import threading
import argparse
from datetime import datetime

print("""
====================================
      Advanced Port Scanner
====================================
""")

# Argument Parser
parser = argparse.ArgumentParser(description="Advanced Multi-threaded Port Scanner")
parser.add_argument("-t", "--target", required=True, help="Target IP Address")
parser.add_argument("-sp", "--startport", type=int, default=1, help="Start Port")
parser.add_argument("-ep", "--endport", type=int, default=1024, help="End Port")

args = parser.parse_args()

target = args.target
start_port = args.startport
end_port = args.endport

print(f"Scanning Target: {target}")
print(f"Port Range: {start_port} - {end_port}")
print("Scanning started at:", datetime.now())
print("-" * 50)

lock = threading.Lock()
open_ports = []

def scan_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))

        if result == 0:
            try:
                banner = s.recv(1024).decode().strip()
            except:
                banner = "No Banner"

            with lock:
                print(f"[OPEN] Port {port} | Service: {banner}")
                open_ports.append((port, banner))

        s.close()
    except:
        pass

threads = []

for port in range(start_port, end_port + 1):
    thread = threading.Thread(target=scan_port, args=(port,))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

# Save Results
with open("scan_results.txt", "w") as file:
    file.write(f"Scan Results for {target}\n")
    file.write(f"Scanned at: {datetime.now()}\n\n")
    for port, banner in open_ports:
        file.write(f"Port {port} OPEN | Service: {banner}\n")

print("\nScanning Completed.")
print(f"Total Open Ports Found: {len(open_ports)}")
print("Results saved in scan_results.txt")
