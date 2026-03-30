"""
Author: Basira Zaki
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

# Print Python version and OS name
print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")

# Dictionary mapping common port numbers to their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


class NetworkTool:

    def __init__(self, target):
        self.__target = target
    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter lets us control how the target value
    # is read and written without exposing the private attribute directly.
    # The setter acts as a gatekeeper — it validates the input before storing it,
    # so invalid values like an empty string are rejected before they can cause problems.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")

    # Q1: How does PortScanner reuse code from NetworkTool?
    # PortScanner inherits from NetworkTool using class PortScanner(NetworkTool),
    # which means it automatically gets the target property, its getter, setter, and 
    # the private self.__target storage without rewriting any of that code.
    # For example, when scan_port calls self.target to get the IP address, it is
    # using the @property getter that was defined in NetworkTool, not in PortScanner.
class PortScanner(NetworkTool):

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Q4: What would happen without try-except here?
        # Without try-except, any network error such as a timeout or unreachable
        # host would raise an unhandled exception and crash the entire program.
        # Since scan_port runs inside threads, one bad port could take down all
        # threads and stop the scan completely before it finishes.
        try:
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))

            status = "Open" if result == 0 else "Closed"
            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            sock.close()

    def get_open_ports(self):
        return [r for r in self.scan_results if r[1] == "Open"]
    
    # Q2: Why do we use threading instead of scanning one port at a time?
    # Each port scan waits up to 1 second for a response, so scanning 1024 ports
    # one at a time could take over 17 minutes in the worst case.
    # Threading lets all port scans run at the same time so the total wait time
    # is roughly 1 second instead of 1024 seconds, which is a massive improvement.
    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            target  TEXT,
            port    INTEGER,
            status  TEXT,
            service TEXT,
            scan_date TEXT
        )""")

        for result in results:
            port, status, service = result
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )

        conn.commit()
        conn.close()
        print("Results saved to database.")

    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                # row = (id, target, port, status, service, scan_date)
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")

        conn.close()

    except sqlite3.Error:
        print("No past scans found.")


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":

    # Get target IP
    target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
    if target == "":
        target = "127.0.0.1"

    # Get start port
    while True:
        try:
            start_port = int(input("Enter start port (1-1024): "))
            if start_port < 1 or start_port > 1024:
                print("Port must be between 1 and 1024.")
            else:
                break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Get end port
    while True:
        try:
            end_port = int(input("Enter end port (1-1024): "))
            if end_port < 1 or end_port > 1024:
                print("Port must be between 1 and 1024.")
            elif end_port < start_port:
                print("End port must be greater than or equal to start port.")
            else:
                break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # Scan
    scanner = PortScanner(target)
    print(f"\nScanning {target} from port {start_port} to {end_port}...")
    scanner.scan_range(start_port, end_port)

    # Print results
    open_ports = scanner.get_open_ports()
    print(f"\n--- Scan Results for {target} ---")
    if open_ports:
        for result in open_ports:
            port, status, service = result
            print(f"Port {port}: {status} ({service})")
    else:
        print("No open ports found.")
    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    # Save to database
    save_results(target, scanner.scan_results)

    # Load past scans
    see_history = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
    if see_history == "yes":
        load_past_scans()

    # Q5: New Feature Proposal
    # A useful addition would be an export_report() method that saves the open port
    # results to a .txt file with a timestamp in the filename, for example
    # "report_127.0.0.1_2026-03-29.txt". It would use a list comprehension to
    # filter only open ports from scan_results, then use a nested if-statement
    # to check if the service is "Unknown" — if so, it labels it as
    # "Unregistered Service" in the report for better readability.
    # Diagram: See diagram_101565577.png in the repository root

