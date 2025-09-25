import pyshark, time
from collections import defaultdict, deque

capture = pyshark.FileCapture("/home/aimal/cyber-base/captures/real_stack.pcap", display_filter='tcp')

pending = defaultdict(dict)
recent_seqs = defaultdict(lambda: deque(maxlen=5000))
rtts = []
retrans_events = []

for pkt in capture:
    t = pkt.sniff_time.timestamp()
    src = pkt.ip.src; dst = pkt.ip.dst; sport = int(pkt.tcp.srcport); dport = int(pkt.tcp.dstport)
    flow = (src, sport, dst, dport)
    rev_flow = (dst, dport, src, sport)
    seq = int(pkt.tcp.seq)
    payload = int(getattr(pkt.tcp, 'len', '0'))
    ack = int(getattr(pkt.tcp, 'ack', '0'))
    
    if payload > 0:
        if seq in recent_seqs[flow]:
            retrans_events.append((flow, seq, t))
        recent_seqs[flow].append(seq)
        pending[flow][seq] = (t, payload)
    
    pend = pending.get(rev_flow, {})
    to_del = []
    for pseq, (st, plen) in pend.items():
        if ack >= pseq + plen:
            rtts.append(t - st)
            to_del.append(pseq)
    for p in to_del:
        del pending[rev_flow][p]
