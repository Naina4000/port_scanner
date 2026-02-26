import socket
import argparse
import json
import os
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

print("""
====================================
      **SOC Port Exposure Monitor**

====================================
""")

# -------------------- Logging Setup --------------------
logging.basicConfig(
    **filename="scanner.log",**

    **level=logging.INFO,**

    **format="%(asctime)s - %(levelname)s - %(message)s"**

)

logging.info("Scan initiated")

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
    **target = socket.gethostbyname(target\_input)**

except socket.gaierror:
    **print("Invalid target.")**

    **logging.error("Invalid target provided")**

    **exit()**




print(f"Scanning Target: {target} ({target_input})")
print(f"Port Range: {start_port} - {end_port}")
print("Scan started at:", datetime.now())
print("-" * 50)

logging.info(f"Scanning target {target}")

# -------------------- Load Risk Database --------------------
with open("risk_database.json", "r") as db_file:
    **risk\_db = json.load(db\_file)**




open_ports = []
total_risk_score = 0
high_count = 0
medium_count = 0
low_count = 0

# -------------------- Port Scan Function --------------------
def scan_port(port):
    **global total\_risk\_score, high\_count, medium\_count, low\_count**



    **try:**

        **s = socket.socket(socket.AF\_INET, socket.SOCK\_STREAM)**

        **s.settimeout(1)**

        **result = s.connect\_ex((target, port))**



        **if result == 0:**

            **port\_str = str(port)**



            **if port\_str in risk\_db:**

                **risk\_info = risk\_db\[port\_str]**

                **service\_name = risk\_info\["service"]**

                **risk\_level = risk\_info\["risk\_level"]**

                **description = risk\_info\["description"]**

                **severity\_score = risk\_info.get("severity\_score", 3)**

            **else:**

                **service\_name = "Unknown"**

                **risk\_level = "Low"**

                **description = "No known major risks recorded."**

                **severity\_score = 2**



            **total\_risk\_score += severity\_score**



            **if risk\_level == "High":**

                **high\_count += 1**

            **elif risk\_level == "Medium":**

                **medium\_count += 1**

            **else:**

                **low\_count += 1**



            **print(f"\[OPEN] Port {port} | Risk: {risk\_level} | Severity: {severity\_score}")**



            **open\_ports.append({**

                **"port": port,**

                **"service": service\_name,**

                **"risk\_level": risk\_level,**

                **"severity\_score": severity\_score,**

                **"description": description**

            **})**



        **s.close()**



    **except:**

        **pass**







# -------------------- Multi-threaded Scan --------------------
ports = range(start_port, end_port + 1)
with ThreadPoolExecutor(max_workers=200) as executor:
    **executor.map(scan\_port, ports)**




# -------------------- Overall Risk Classification --------------------
if total_risk_score <= 10:
    **overall\_risk = "Low"**

elif total_risk_score <= 25:
    **overall\_risk = "Moderate"**

elif total_risk_score <= 40:
    **overall\_risk = "High"**

else:
    **overall\_risk = "Critical"**




# -------------------- Alert Threshold Logic --------------------
alert_status = "NORMAL"

if overall_risk == "Critical":
    **alert\_status = "CRITICAL ALERT"**

    **print("\\n⚠️  CRITICAL RISK THRESHOLD EXCEEDED ⚠️")**

    **logging.critical("Critical exposure threshold exceeded")**




# -------------------- Save Final Report --------------------
report_filename = f"soc_full_report_{target}.json"

full_report = {
    **"target": target,**

    **"timestamp": str(datetime.now()),**

    **"summary": {**

        **"total\_open\_ports": len(open\_ports),**

        **"high\_risk": high\_count,**

        **"medium\_risk": medium\_count,**

        **"low\_risk": low\_count,**

        **"total\_risk\_score": total\_risk\_score,**

        **"overall\_host\_risk": overall\_risk,**

        **"alert\_status": alert\_status**

    **},**

    **"open\_ports": open\_ports**

}

with open(report_filename, "w") as f:
    **json.dump(full\_report, f, indent=4)**




# -------------------- Console Summary --------------------
print("\n====================================")
print("SCAN SUMMARY")
print("====================================")
print(f"Total Open Ports: {len(open_ports)}")
print(f"High Risk: {high_count}")
print(f"Medium Risk: {medium_count}")
print(f"Low Risk: {low_count}")
print(f"Total Risk Score: {total_risk_score}")
print(f"Overall Host Risk Level: {overall_risk}")
print(f"Alert Status: {alert_status}")
print("====================================")

print(f"\nReport saved as {report_filename}")
print("Logs saved in scanner.log")
