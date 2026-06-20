from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Raw
from app.alerts.alerts import log_alert

# =========================================
# TRACKERS
# =========================================

port_scan_tracker = {}

syn_tracker = {}

icmp_tracker = {}

bruteforce_tracker = {}

# =========================================
# SQL INJECTION KEYWORDS
# =========================================

sql_keywords = [
    "SELECT",
    "UNION",
    "DROP",
    "INSERT",
    "DELETE",
    "' OR 1=1",
    "--"
]

# =========================================
# MAIN DETECTION FUNCTION
# =========================================

def detect(packet):

    # =====================================
    # IP CHECK
    # =====================================

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    # =====================================
    # PORT SCAN DETECTION
    # =====================================

    if packet.haslayer(TCP):

        dst_port = packet[TCP].dport

        if src_ip not in port_scan_tracker:
            port_scan_tracker[src_ip] = set()

        port_scan_tracker[src_ip].add(dst_port)

        if len(port_scan_tracker[src_ip]) > 5:

            alert_message = f"[ALERT] Possible Port Scan Detected from {src_ip}"

            log_alert(alert_message)

    # =====================================
    # SYN FLOOD DETECTION
    # =====================================

    if packet.haslayer(TCP):

        if packet[TCP].flags == "S":

            if src_ip not in syn_tracker:
                syn_tracker[src_ip] = 0

            syn_tracker[src_ip] += 1

            print(f"SYN Packet from {src_ip} : {syn_tracker[src_ip]}")

            if syn_tracker[src_ip] > 20:

                alert_message = f"[ALERT] Possible SYN Flood Attack from {src_ip}"

                log_alert(alert_message)

    # =====================================
    # ICMP FLOOD DETECTION
    # =====================================

    if packet.haslayer(ICMP):

        if src_ip not in icmp_tracker:
            icmp_tracker[src_ip] = 0

        icmp_tracker[src_ip] += 1

        print(f"ICMP Packet from {src_ip} : {icmp_tracker[src_ip]}")

        if icmp_tracker[src_ip] > 20:

            alert_message = f"[ALERT] Possible ICMP Flood Attack from {src_ip}"

            log_alert(alert_message)

    # =====================================
    # BRUTE FORCE DETECTION
    # =====================================

    if packet.haslayer(TCP):

        sensitive_ports = [22, 21, 3389]

        dst_port = packet[TCP].dport

        if dst_port in sensitive_ports:

            if src_ip not in bruteforce_tracker:
                bruteforce_tracker[src_ip] = 0

            bruteforce_tracker[src_ip] += 1

            print(f"Login Attempt from {src_ip} : {bruteforce_tracker[src_ip]}")

            if bruteforce_tracker[src_ip] > 10:

                alert_message = f"[ALERT] Possible Brute Force Attack from {src_ip}"

                log_alert(alert_message)

    # =====================================
    # SQL INJECTION DETECTION
    # =====================================

    if packet.haslayer(Raw):

        payload = str(packet[Raw].load)

        for keyword in sql_keywords:

            if keyword.lower() in payload.lower():

                alert_message = f"[ALERT] Possible SQL Injection Attempt from {src_ip}"

                log_alert(alert_message)

                break
