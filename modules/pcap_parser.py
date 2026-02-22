import pandas as pd
from scapy.all import rdpcap, Scapy_Exception, TCP, UDP, ICMP, IP, ARP, DNS, DNSQR, PcapReader
import os

def parse_pcap(file_path, max_packets=50000):
    """
    Parses a PCAP file and returns a Pandas DataFrame.
    Gracefully handles large files by limiting packets or chunking.
    """
    packets_data = []
    
    try:
        # Using PcapReader for memory efficiency with large files
        with PcapReader(file_path) as pcap_reader:
            count = 0
            for packet in pcap_reader:
                if count >= max_packets:
                    break
                
                if not packet.haslayer(IP) and not packet.haslayer(ARP):
                    continue

                packet_info = {
                    'timestamp': float(packet.time),
                    'size': len(packet),
                    'protocol': 'Other',
                    'src_ip': None,
                    'dst_ip': None,
                    'src_port': None,
                    'dst_port': None,
                    'tcp_flags': None,
                    'payload_len': 0,
                    'dns_query': None
                }

                if packet.haslayer(IP):
                    packet_info['src_ip'] = packet[IP].src
                    packet_info['dst_ip'] = packet[IP].dst
                    
                    if packet.haslayer(TCP):
                        packet_info['protocol'] = 'TCP'
                        packet_info['src_port'] = packet[TCP].sport
                        packet_info['dst_port'] = packet[TCP].dport
                        packet_info['tcp_flags'] = packet[TCP].underlayer.sprintf("%TCP.flags%")
                    elif packet.haslayer(UDP):
                        packet_info['protocol'] = 'UDP'
                        packet_info['src_port'] = packet[UDP].sport
                        packet_info['dst_port'] = packet[UDP].dport
                    elif packet.haslayer(ICMP):
                        packet_info['protocol'] = 'ICMP'
                    
                    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                        packet_info['protocol'] = 'DNS'
                        packet_info['dns_query'] = packet[DNSQR].qname.decode('utf-8', errors='ignore')

                    if packet.haslayer('Raw'):
                        packet_info['payload_len'] = len(packet['Raw'].load)

                elif packet.haslayer(ARP):
                    packet_info['protocol'] = 'ARP'
                    packet_info['src_ip'] = packet[ARP].psrc
                    packet_info['dst_ip'] = packet[ARP].pdst
                    packet_info['src_mac'] = packet[ARP].hwsrc

                packets_data.append(packet_info)
                count += 1

        return pd.DataFrame(packets_data)
    
    except Exception as e:
        print(f"Error parsing PCAP: {e}")
        return pd.DataFrame()

def get_protocol_counts(df):
    if df.empty:
        return pd.Series()
    return df['protocol'].value_counts()
