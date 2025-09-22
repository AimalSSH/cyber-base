#!/usr/bin/env python3
from scapy.all import IP, TCP, wrpcap, conf
conf.verb = 0

def make_syn(dst="127.0.0.1", dport=40001, sport=20001, mss=1460, wscale=0):
    print(50*'=')
    opts=[]
    opts.append(("MSS", mss))
    if wscale:
        opts.append(("WScale", wscale))
    return IP(dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=100, options=opts)

if __name__ == "__main__":
    pkts = []
    pkts.append(make_syn(dport=40001, sport=20001, mss=1460, wscale=0))
    print(pkts)
    pkts.append(make_syn(dport=40001, sport=20002, mss=1200, wscale=5))
    print(pkts)
    pkts.append(make_syn(dport=40001, sport=20003, mss=8960, wscale=14))
    print(pkts)
    wrpcap("window_options.pcap", pkts)
    print("Saved captures/window_options.pcap")
