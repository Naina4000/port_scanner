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
      SOC Port Exposure Monitor
====================================
""")

# -------------------- Logging Setup (SIEM-Ready Format) --------------------
logging.basicConfig(
    filename="scanner.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
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
    target = socket.gethostbyname(target_input)
except socket.gaierror:
    print("Invalid target.")
    exit()

# -------------------- Load Risk Database --------------------
with open("risk_database.json", "r") as db_file:
    risk_db = json.load(db_file)


# -------------------- Scan Function --------------------
def perform_scan():

    open_ports = []
    total_risk_score = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    print("\n----------------------------------------")
    print("Scanning at:", datetime.now())
    print("----------------------------------------")

    def scan_port(port):
        nonlocal total_risk_score, high_count, medium_count, low_count

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))

            if result == 0:
                port_str = str(port)

                if port_str in risk_db:
                    risk_info = risk_db[port_str]
                else:
                    risk_info = {
                        "service": "Unknown",
                        "risk_level": "Low",
                        "severity_score": 2,
                        "category": "Unknown",
                        "exposure_type": "Unknown",
                        "mitre_reference": "N/A",
                        "cvss_reference": "N/A",
                        "recommended_action": "Review manually.",
                        "description": "No intelligence available."
                    }

                total_risk_score += risk_info["severity_score"]

                if risk_info["risk_level"] == "High":
                    high_count += 1
                elif risk_info["risk_level"] == "Medium":
                    medium_count += 1
                else:
                    low_count += 1

                print(f"[OPEN] Port {port} | Risk: {risk_info['risk_level']} | Severity: {risk_info['severity_score']}")

                # -------- SIEM Structured Log --------
                logging.info(
                    f"event=PORT_OPEN "
                    f"target={target} "
                    f"port={port} "
                    f"service={risk_info['service']} "
                    f"risk={risk_info['risk_level']} "
                    f"severity={risk_info['severity_score']} "
                    f"category={risk_info['category']} "
                    f"mitre={risk_info['mitre_reference']}"
                )

                open_ports.append({
                    "port": port,
                    **risk_info
                })

            s.close()

        except:
            pass

    # -------------------- Multi-threaded Scan --------------------
    ports = range(start_port, end_port + 1)
    with ThreadPoolExecutor(max_workers=200) as executor:
        executor.map(scan_port, ports)

    # -------------------- Risk Classification --------------------
    if total_risk_score <= 10:
        overall_risk = "Low"
    elif total_risk_score <= 25:
        overall_risk = "Moderate"
    elif total_risk_score <= 40:
        overall_risk = "High"
    else:
        overall_risk = "Critical"

    alert_status = "NORMAL"

    if overall_risk == "Critical":
        alert_status = "CRITICAL ALERT"
        print("\n⚠️  CRITICAL ALERT THRESHOLD EXCEEDED ⚠️")
        logging.critical(
            f"event=CRITICAL_ALERT "
            f"target={target} "
            f"total_risk_score={total_risk_score}"
        )

    # -------------------- Risk Ranking --------------------
    sorted_ports = sorted(open_ports, key=lambda x: x["severity_score"], reverse=True)
    top_exposures = sorted_ports[:3]

    print("\nTop Critical Exposures:")
    for idx, port in enumerate(top_exposures, start=1):
        print(f"{idx}. Port {port['port']} | Severity: {port['severity_score']} | Risk: {port['risk_level']}")

    # -------------------- Risk Trend Tracking --------------------
    report_filename = f"soc_monitor_report_{target}.json"
    trend_status = "No Previous Data"
    previous_score = None

    if os.path.exists(report_filename):
        with open(report_filename, "r") as old_file:
            old_data = json.load(old_file)
            previous_score = old_data.get("summary", {}).get("total_risk_score")

            if previous_score is not None:
                if total_risk_score > previous_score:
                    trend_status = "Increased"
                    logging.warning(
                        f"event=RISK_INCREASE "
                        f"target={target} "
                        f"previous_score={previous_score} "
                        f"current_score={total_risk_score}"
                    )
                elif total_risk_score < previous_score:
                    trend_status = "Decreased"
                    logging.info(
                        f"event=RISK_DECREASE "
                        f"target={target} "
                        f"previous_score={previous_score} "
                        f"current_score={total_risk_score}"
                    )
                else:
                    trend_status = "Stable"

    print("Risk Trend:", trend_status)

    # -------------------- Save JSON Report --------------------
    report_data = {
        "target": target,
        "timestamp": str(datetime.now()),
        "summary": {
            "total_open_ports": len(open_ports),
            "high_risk": high_count,
            "medium_risk": medium_count,
            "low_risk": low_count,
            "total_risk_score": total_risk_score,
            "overall_risk": overall_risk,
            "alert_status": alert_status,
            "risk_trend": trend_status
        },
        "prioritized_exposures": top_exposures,
        "open_ports": sorted_ports
    }

    with open(report_filename, "w") as f:
        json.dump(report_data, f, indent=4)

    print("\nSCAN SUMMARY")
    print("Total Open Ports:", len(open_ports))
    print("Total Risk Score:", total_risk_score)
    print("Overall Risk Level:", overall_risk)
    print("Alert Status:", alert_status)
    print("Risk Trend:", trend_status)
    print("Report updated:", report_filename)


# -------------------- Execution Mode --------------------
if monitor_interval:
    print(f"\nContinuous Monitoring Enabled (Interval: {monitor_interval} seconds)")
    try:
        while True:
            perform_scan()
            time.sleep(monitor_interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
else:
    perform_scan()
