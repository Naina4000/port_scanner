import socket
import argparse
import json
import os
import logging
import time
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
    \*\*level=logging.INFO,\*\*

    \*\*format="%(asctime)s - %(levelname)s - %(message)s"\*\*



)

# -------------------- Argument Parser --------------------
parser = argparse.ArgumentParser(description="SOC-Focused Multi-threaded Port Scanner")
parser.add_argument("-t", "--target", required=True, help="Target IP Address or Domain")
parser.add_argument("-sp", "--startport", type=int, default=1, help="Start Port")
parser.add_argument("-ep", "--endport", type=int, default=1024, help="End Port")
parser.add_argument("--monitor", type=int, help="Enable continuous monitoring (seconds interval)")

args = parser.parse_args()

target_input = args.target
start_port = args.startport
end_port = args.endport
monitor_interval = args.monitor

# -------------------- Resolve Domain --------------------
try:
    **target = socket.gethostbyname(target\_input)**

except socket.gaierror:
    **print("Invalid target.")**
    \*\*exit()\*\*









# -------------------- Load Risk Database --------------------
with open("risk_database.json", "r") as db_file:
    **risk\_db = json.load(db\_file)**



# -------------------- Scan Function --------------------
def perform_scan():

    **open\_ports = \[]**
    \*\*total\\\_risk\\\_score = 0\*\*

    \*\*high\\\_count = 0\*\*

    \*\*medium\\\_count = 0\*\*

    \*\*low\\\_count = 0\*\*



    \*\*print("\\\\n----------------------------------------")\*\*

    \*\*print("Scanning at:", datetime.now())\*\*

    \*\*print("----------------------------------------")\*\*



    \*\*def scan\\\_port(port):\*\*

        \*\*nonlocal total\\\_risk\\\_score, high\\\_count, medium\\\_count, low\\\_count\*\*



        \*\*try:\*\*

            \*\*s = socket.socket(socket.AF\\\_INET, socket.SOCK\\\_STREAM)\*\*

            \*\*s.settimeout(1)\*\*

            \*\*result = s.connect\\\_ex((target, port))\*\*



            \*\*if result == 0:\*\*

                \*\*port\\\_str = str(port)\*\*



                \*\*if port\\\_str in risk\\\_db:\*\*

                    \*\*risk\\\_info = risk\\\_db\\\[port\\\_str]\*\*

                    \*\*service\\\_name = risk\\\_info\\\["service"]\*\*

                    \*\*risk\\\_level = risk\\\_info\\\["risk\\\_level"]\*\*

                    \*\*severity\\\_score = risk\\\_info.get("severity\\\_score", 3)\*\*

                \*\*else:\*\*

                    \*\*service\\\_name = "Unknown"\*\*

                    \*\*risk\\\_level = "Low"\*\*

                    \*\*severity\\\_score = 2\*\*



                \*\*total\\\_risk\\\_score += severity\\\_score\*\*



                \*\*if risk\\\_level == "High":\*\*

                    \*\*high\\\_count += 1\*\*

                \*\*elif risk\\\_level == "Medium":\*\*

                    \*\*medium\\\_count += 1\*\*

                \*\*else:\*\*

                    \*\*low\\\_count += 1\*\*



                \*\*print(f"\\\[OPEN] Port {port} | Risk: {risk\\\_level}")\*\*



                \*\*open\\\_ports.append({\*\*

                    \*\*"port": port,\*\*

                    \*\*"service": service\\\_name,\*\*

                    \*\*"risk\\\_level": risk\\\_level,\*\*

                    \*\*"severity\\\_score": severity\\\_score\*\*

                \*\*})\*\*



            \*\*s.close()\*\*

        \*\*except:\*\*

            \*\*pass\*\*



    \*\*ports = range(start\\\_port, end\\\_port + 1)\*\*

    \*\*with ThreadPoolExecutor(max\\\_workers=200) as executor:\*\*

        \*\*executor.map(scan\\\_port, ports)\*\*



    \*\*# Risk Classification\*\*

    \*\*if total\\\_risk\\\_score <= 10:\*\*

        \*\*overall\\\_risk = "Low"\*\*

    \*\*elif total\\\_risk\\\_score <= 25:\*\*

        \*\*overall\\\_risk = "Moderate"\*\*

    \*\*elif total\\\_risk\\\_score <= 40:\*\*

        \*\*overall\\\_risk = "High"\*\*

    \*\*else:\*\*

        \*\*overall\\\_risk = "Critical"\*\*



    \*\*print("\\\\nSCAN SUMMARY")\*\*

    \*\*print("Total Risk Score:", total\\\_risk\\\_score)\*\*

    \*\*print("Overall Risk Level:", overall\\\_risk)\*\*



    \*\*if overall\\\_risk == "Critical":\*\*

        \*\*print("⚠️  CRITICAL ALERT ⚠️")\*\*

        \*\*logging.critical("Critical risk detected")\*\*



    \*\*# Save report\*\*

    \*\*report\\\_filename = f"soc\\\_monitor\\\_report\\\_{target}.json"\*\*



    \*\*report\\\_data = {\*\*

        \*\*"target": target,\*\*

        \*\*"timestamp": str(datetime.now()),\*\*

        \*\*"total\\\_risk\\\_score": total\\\_risk\\\_score,\*\*

        \*\*"overall\\\_risk": overall\\\_risk,\*\*

        \*\*"open\\\_ports": open\\\_ports\*\*

    \*\*}\*\*



    \*\*with open(report\\\_filename, "w") as f:\*\*

        \*\*json.dump(report\\\_data, f, indent=4)\*\*



    \*\*print("Report updated:", report\\\_filename)\*\*















# -------------------- Execution Mode --------------------
if monitor_interval:
    **print(f"\\nContinuous Monitoring Enabled (Interval: {monitor\_interval} seconds)")**
    \*\*try:\*\*

        \*\*while True:\*\*

            \*\*perform\\\_scan()\*\*

            \*\*time.sleep(monitor\\\_interval)\*\*

    \*\*except KeyboardInterrupt:\*\*

        \*\*print("\\\\nMonitoring stopped by user.")\*\*



else:
    **perform\_scan()**
