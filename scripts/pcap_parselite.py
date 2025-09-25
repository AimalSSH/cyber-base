import pyshark
import pandas as pd
from collections import Counter

def advanced_tcp_analysis(pcap_file, csv_filename='advanced_tcp_analysis.csv'):
    capture = pyshark.FileCapture(input_file=pcap_file, display_filter='tcp')
    
    data = []
    for i, packet in enumerate(capture):
        flags = int(packet.tcp.flags, 16)
        flags_str = ""
        flags_str += "F" if flags & 0x01 else "."
        flags_str += "S" if flags & 0x02 else "."
        flags_str += "R" if flags & 0x04 else "."
        flags_str += "P" if flags & 0x08 else "."
        flags_str += "A" if flags & 0x10 else "."
        flags_str += "U" if flags & 0x20 else "."
        flags_str += "E" if flags & 0x40 else "."
        flags_str += "C" if flags & 0x80 else "."
        
        pkt_data = {
            "frame_num": i + 1,
            "timestamp": packet.sniff_time,
            "src_ip": packet.ip.src,
            "src_port": int(packet.tcp.srcport),
            "dst_ip": packet.ip.dst,
            "dst_port": int(packet.tcp.dstport),
            "window_size": int(packet.tcp.window_size),
            "ack_number": getattr(packet.tcp, 'ack', '0'),
            "seq_number": packet.tcp.seq,
            "flags_hex": packet.tcp.flags,
            "flags_readable": flags_str,
            "has_wscale": "Yes" if hasattr(packet.tcp, 'options_wscale') else "No",
            "tsval": getattr(packet.tcp, 'options_timestamp_tsval', 'N/A'),
            "tsecr": getattr(packet.tcp, 'options_timestamp_tsecr', 'N/A'),
            "mss": getattr(packet.tcp, 'options_mss', 'N/A'),
            "packet_length": packet.length
        }
        data.append(pkt_data)
    
    capture.close()
    
    df = pd.DataFrame(data)
    
    df.to_csv(csv_filename, index=False)
    
    print(f"\n=== СТАТИСТИКА АНАЛИЗА ===")
    print(f"Всего TCP пакетов: {len(df)}")
    print(f"Уникальных соединений: {len(df.groupby(['src_ip', 'src_port', 'dst_ip', 'dst_port']))}")
    print(f"Источники: {df['src_ip'].nunique()} уникальных IP")
    print(f"Назначения: {df['dst_ip'].nunique()} уникальных IP")
    
    flag_counts = Counter(df['flags_readable'])
    print(f"\nРаспределение флагов:")
    for flags, count in flag_counts.most_common():
        print(f"  {flags}: {count} пакетов")
    
    print(f"\nДанные сохранены в: {csv_filename}")
    return df

df = advanced_tcp_analysis('/home/aimal/cyber-base/captures/real_stack.pcap')