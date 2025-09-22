import argparse

parser = argparse.ArgumentParser(description="Scapy Nmap")
parser.add_argument("-port", "--p", type=str, default="1-1000", help="ports to be scanned")
parser.add_argument("-host", "--h", type=str, help="ip address to be scanned")
parser.add_argument("-hostpool", "--hp", type=str, help="pool ip addresses to be scanned")
parser.add_argument("-sS", "--syn", action="store_true", help="Stealth Scan (SYN)")
parser.add_argument("-sF", "--fin", action="store_true", help="Fin Scan")

parser.add_argument("-T", help="Timing template (0-5)", type=int, choices=[0, 1, 2, 3, 4, 5])
my_namespace = parser.parse_args()
print(my_namespace.__dict__)
# TODO add validate ip addresses
