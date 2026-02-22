import pandas as pd

def detect_signatures(df, features_df):
    """
    Rule-based detection for specific attack patterns.
    """
    alerts = []
    
    # 1. Port Scanning: > 20 unique ports in 5 seconds
    # (Simplified for the demonstration context)
    for _, row in features_df.iterrows():
        if row['unique_ports'] > 20:
             alerts.append({
                'timestamp': 'Analysis Period',
                'src_ip': row['src_ip'],
                'type': 'Attack: Port Scanning',
                'severity': 'High',
                'explanation': f"Source IP contacted {row['unique_ports']} unique ports. High-speed port enumeration is a precursor to an attack."
            })

    # 2. SYN Flood / DDoS
    # High SYN count, very few ACKs.
    for _, row in features_df.iterrows():
        if row['syn_ack_ratio'] > 10 and row['packet_count'] > 100:
             alerts.append({
                'timestamp': 'Analysis Period',
                'src_ip': row['src_ip'],
                'type': 'Attack: SYN Flood/DDoS',
                'severity': 'Critical',
                'explanation': f"Extremely high SYN/ACK ratio ({row['syn_ack_ratio']:.2f}). Indicates incomplete TCP handshakes to exhaust resources."
            })

    # 3. ARP Spoofing: Multiple MACs for one IP
    if 'src_mac' in df.columns:
        arp_groups = df[df['protocol'] == 'ARP'].groupby('src_ip')['src_mac'].nunique()
        for ip, mac_count in arp_groups.items():
            if mac_count > 1:
                alerts.append({
                    'timestamp': 'Analysis Period',
                    'src_ip': ip,
                    'type': 'Attack: ARP Spoofing',
                    'severity': 'High',
                    'explanation': f"The IP {ip} is associated with {mac_count} different MAC addresses. Likely Man-in-the-Middle (MITM) attempt."
                })

    # 4. DNS Tunneling
    for _, row in features_df.iterrows():
        if row['avg_dns_len'] > 50 or row['dns_frequency'] > 1.6: # > 100 queries per minute
            alerts.append({
                'timestamp': 'Analysis Period',
                'src_ip': row['src_ip'],
                'type': 'Attack: DNS Tunneling',
                'severity': 'High',
                'explanation': f"Unusual DNS behavior: Avg query length {row['avg_dns_len']:.1f} or freq {row['dns_frequency']:.2f} q/s. May indicate data exfiltration."
            })

    # 5. Brute Force
    # Repeated attempts (failed connections logic is complex with just raw PCAP, 
    # but we can look for high frequency small packets to specific ports like 22, 3389)
    if not df.empty:
        ssh_rdp_attempts = df[df['dst_port'].isin([22, 3389, 445, 3306])]
        if not ssh_rdp_attempts.empty:
            brute_counts = ssh_rdp_attempts.groupby(['src_ip', 'dst_port']).size()
            for (ip, port), count in brute_counts.items():
                if count > 20: # Over 20 attempts in the capture
                     alerts.append({
                        'timestamp': 'Analysis Period',
                        'src_ip': ip,
                        'type': 'Attack: Brute Force',
                        'severity': 'High',
                        'explanation': f"Detected {count} connection attempts to port {port}. Suggests automated login cracking."
                    })

    return alerts
