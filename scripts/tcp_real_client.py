from scapy.all import IP, TCP, sr1, send, conf
import time
conf.verb = 0

DST="127.0.0.1"
DPORT=40001
SPORT=25000

def do_flow(delay_ack=False):
    syn = IP(dst=DST)/TCP(sport=SPORT, dport=DPORT, flags="S", seq=100)
    resp = sr1(syn, timeout=2)
    if not resp:
        print("no resp to SYN")
        return
    if resp.haslayer(TCP) and resp.getlayer(TCP).flags & 0x12:
        ack = IP(dst=DST)/TCP(sport=SPORT, dport=DPORT, flags="A", seq=101, ack=resp.seq+1)
        send(ack)
        for i in range(3):
            send(IP(dst=DST)/TCP(sport=SPORT, dport=DPORT, flags="PA", seq=101+i, ack=resp.seq+1)/f"msg{i}".encode())
            if delay_ack:
                time.sleep(0.35)
        send(IP(dst=DST)/TCP(sport=SPORT, dport=DPORT, flags="R", seq=110))
        print("flow done")
    else:
        print("unexpected response:", resp.summary())

if __name__ == "__main__":
    do_flow(delay_ack=True)
