from fpdf import FPDF
import datetime

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Network Anomaly Detection Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(traffic_summary, alerts, threat_scores):
    pdf = PDFReport()
    pdf.add_page()
    
    # Summary Section
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '1. Traffic Summary', 0, 1)
    pdf.set_font('Arial', '', 10)
    for key, value in traffic_summary.items():
        pdf.cell(0, 7, f'{key}: {value}', 0, 1)
    pdf.ln(5)
    
    # Threat Scores
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '2. Top IP Threat Scores', 0, 1)
    pdf.set_font('Arial', '', 9)
    # Header
    pdf.cell(40, 7, 'IP Address', 1)
    pdf.cell(30, 7, 'Score', 1)
    pdf.cell(40, 7, 'Status', 1)
    pdf.cell(80, 7, 'Detections', 1)
    pdf.ln()
    
    for _, row in threat_scores.head(10).iterrows():
        pdf.cell(40, 7, str(row['IP Address']), 1)
        pdf.cell(30, 7, str(row['Threat Score']), 1)
        pdf.cell(40, 7, str(row['Classification']), 1)
        pdf.cell(80, 7, str(row['Violations'])[:40] + '...', 1)
        pdf.ln()
    pdf.ln(5)

    # Alerts
    pdf.add_page()
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, '3. Detailed Alerts', 0, 1)
    pdf.set_font('Arial', '', 8)
    
    for alert in alerts[:20]: # Limit to top 20 for readability
        pdf.set_font('Arial', 'B', 8)
        pdf.cell(0, 5, f"{alert['type']} - {alert['severity']} Severity", 0, 1)
        pdf.set_font('Arial', '', 8)
        pdf.multi_cell(0, 5, f"Source: {alert['src_ip']} | Explanation: {alert['explanation']}")
        pdf.ln(2)

    return pdf.output(dest='S').encode('latin-1', errors='ignore')
