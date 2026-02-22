import pandas as pd

def calculate_threat_scores(features_df, alerts):
    """
    Computes a 0-100 threat score for each IP based on detected alerts.
    Classification: Clean (< 20), Suspicious (20-60), Malicious (> 60).
    """
    scores = {}
    
    # Initialize scores
    for ip in features_df['src_ip'].unique():
        scores[ip] = {
            'score': 0,
            'alerts_count': 0,
            'violations': set()
        }
        
    # Weight alerts by severity
    severity_weights = {
        'Low': 10,
        'Medium': 25,
        'High': 50,
        'Critical': 80
    }
    
    for alert in alerts:
        ip = alert['src_ip']
        if ip in scores:
            weight = severity_weights.get(alert['severity'], 10)
            scores[ip]['score'] += weight
            scores[ip]['alerts_count'] += 1
            scores[ip]['violations'].add(alert['type'])
            
    # Normalize to 0-100 and classify
    results = []
    for ip, data in scores.items():
        capped_score = min(data['score'], 100)
        
        if capped_score < 20:
            classification = 'Clean'
        elif capped_score < 60:
            classification = 'Suspicious'
        else:
            classification = 'Malicious'
            
        results.append({
            'IP Address': ip,
            'Threat Score': capped_score,
            'Classification': classification,
            'Alerts': data['alerts_count'],
            'Violations': ", ".join(data['violations']) if data['violations'] else "None"
        })
        
    return pd.DataFrame(results).sort_values(by='Threat Score', ascending=False)
