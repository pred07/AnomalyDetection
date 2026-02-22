import pandas as pd
import numpy as np

def detect_anomalies(features_df):
    """
    Detects statistical anomalies using Z-scores and thresholds.
    """
    alerts = []
    if features_df.empty:
        return alerts

    # Calculate Z-scores for PPS
    pps_mean = features_df['pps'].mean()
    pps_std = features_df['pps'].std()
    
    for _, row in features_df.iterrows():
        # PPS Anomaly (> 3 Std Dev)
        if pps_std > 0:
            z_score = abs(row['pps'] - pps_mean) / pps_std
            if z_score > 3:
                alerts.append({
                    'timestamp': 'Baseline Period',
                    'src_ip': row['src_ip'],
                    'type': 'Anomaly: High Traffic Volume',
                    'severity': 'High',
                    'explanation': f"Source IP packets per second ({row['pps']:.2f}) exceeds 3 standard deviations from mean ({pps_mean:.2f})."
                })

        # Unique Ports Anomaly
        if row['unique_ports'] > 50: # Threshold for unusual port variety
            alerts.append({
                'timestamp': 'Baseline Period',
                'src_ip': row['src_ip'],
                'type': 'Anomaly: Unusual Port Scanning',
                'severity': 'Medium',
                'explanation': f"Source IP contacted {row['unique_ports']} unique destination ports, suggesting discovery behavior."
            })

        # Irregular Packet Size Distribution
        # This is simplified: if avg packet size is extremely small or large compared to median
        median_size = features_df['avg_packet_size'].median()
        if row['avg_packet_size'] < (median_size * 0.1) or row['avg_packet_size'] > (median_size * 10):
             alerts.append({
                'timestamp': 'Baseline Period',
                'src_ip': row['src_ip'],
                'type': 'Anomaly: Irregular Packet Size',
                'severity': 'Low',
                'explanation': f"Average packet size ({row['avg_packet_size']:.2f}) is significantly different from network median ({median_size:.2f})."
            })

    return alerts
