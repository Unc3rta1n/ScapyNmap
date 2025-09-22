import argparse

from app.scapy_nmap import ScapyNmap

parser = argparse.ArgumentParser(description="Scapy Nmap")
scan_group = parser.add_mutually_exclusive_group(required=True)
scan_group.add_argument("-sS", "--syn", action="store_true", help="Stealth Scan (SYN)")
scan_group.add_argument("-sF", "--fin", action="store_true", help="Fin Scan")
parser.add_argument("-port", "--p", type=str, default="1-1000", help="ports to be scanned")
parser.add_argument("-host", "--h", type=str, help="pool ip addresses to be scanned")
parser.add_argument("-T", help="Timing template (0-5)", default=3, type=int, choices=[0, 1, 2, 3, 4, 5])
parser.add_argument("--vuln", "-v", action="store_true", default=False, help="search wing ftp in 21 and 80 ports")
my_namespace = parser.parse_args()
print(my_namespace)

if __name__ == "__main__":
    try:
        scanner = ScapyNmap(args=my_namespace)
        scanner.run()
        scanner.pretty_print()
    except ValueError as e:
        print(f"Error: {e}")
