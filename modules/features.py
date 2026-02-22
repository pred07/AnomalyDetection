import pandas as pd
import numpy as np

def extract_features(df):
    """
    Computes aggregated features per Source IP.
    """
    if df.empty:
        return pd.DataFrame()

    features = []
    
    # Group by source IP
    groups = df.groupby('src_ip')
    
    # Global time window for scaling stats
    total_time = df['timestamp'].max() - df['timestamp'].min()
    if total_time <= 0: total_time = 1

    for src_ip, group in groups:
        # 1. Packets per second per source IP
        pps = len(group) / total_time
        
        # 2. Unique destination ports contacted
        unique_ports = group['dst_port'].dropna().nunique()
        
        # 3. Ratio of SYN packets to ACK packets
        syn_count = 0
        ack_count = 0
        if 'tcp_flags' in group.columns:
            syn_count = group['tcp_flags'].apply(lambda x: 'S' in str(x) if x else False).sum()
            ack_count = group['tcp_flags'].apply(lambda x: 'A' in str(x) if x else False).sum()
        syn_ack_ratio = syn_count / (ack_count + 1) # Avoid division by zero
        
        # 4. DNS frequency and length
        dns_queries = group[group['protocol'] == 'DNS']['dns_query'].dropna()
        dns_frequency = len(dns_queries) / total_time
        avg_dns_len = dns_queries.apply(len).mean() if not dns_queries.empty else 0
        
        # 5. ARP request to reply ratio (Logic would need more packet detail, but we'll approximate)
        # Assuming we just count ARP packets for this IP
        arp_count = len(group[group['protocol'] == 'ARP'])
        
        # 6. Average packet size per flow (Simplified as per IP)
        avg_packet_size = group['size'].mean()
        
        # 7. Total bandwidth consumed
        total_bandwidth = group['size'].sum()

        features.append({
            'src_ip': src_ip,
            'pps': pps,
            'unique_ports': unique_ports,
            'syn_ack_ratio': syn_ack_ratio,
            'dns_frequency': dns_frequency,
            'avg_dns_len': avg_dns_len,
            'arp_count': arp_count,
            'avg_packet_size': avg_packet_size,
            'total_bandwidth': total_bandwidth,
            'packet_count': len(group)
        })

    return pd.DataFrame(features)
