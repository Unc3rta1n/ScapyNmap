import argparse

from app.scapy_nmap import ScapyNmap

parser = argparse.ArgumentParser(description="Scapy Nmap")
parser.add_argument("-port", "--p", type=str, default="1-1000", help="ports to be scanned")
parser.add_argument("-host", "--h", type=str, help="pool ip addresses to be scanned")
parser.add_argument("-sS", "--syn", action="store_true", help="Stealth Scan (SYN)")
parser.add_argument("-sF", "--fin", action="store_true", help="Fin Scan")
parser.add_argument("-T", help="Timing template (0-5)", default=3, type=int, choices=[0, 1, 2, 3, 4, 5])
my_namespace = parser.parse_args()


if __name__ == "__main__":
    try:
        scanner = ScapyNmap(args=my_namespace)
        scanner.run()
    except ValueError as e:
        print(f"Error: {e}")
