from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from typing import List, Dict
import datetime

class PDFReportGenerator:
    def __init__(self, findings: List[Dict], target: str):
        self.findings = findings
        self.target = target
        self.total_high = 0
        self.total_medium = 0
        self.total_low = 0
        self._calculate_stats()
        self.styles = getSampleStyleSheet()

    def _calculate_stats(self):
        for finding in self.findings:
            sev = finding.get('severity', '').lower()
            if sev == 'high' or sev == 'critical':
                self.total_high += 1
            elif sev == 'medium':
                self.total_medium += 1
            elif sev == 'low':
                self.total_low += 1

    def _get_health_status(self):
        if self.total_high > 0:
            return "CRITICAL / MERAH", colors.red, "Ditemukan kerentanan tingkat Tinggi. Jika dieksploitasi, hal ini dapat menyebabkan gangguan layanan aplikasi dan potensi kebocoran data klien. Disarankan untuk segera mengalokasikan sumber daya teknis untuk perbaikan."
        elif self.total_medium > 0:
            return "WARNING / KUNING", colors.orange, "Ditemukan kerentanan tingkat Menengah. Risiko gangguan cukup signifikan. Disarankan untuk menjadwalkan perbaikan dalam siklus pengembangan terdekat."
        elif self.total_low > 0:
            return "NOTICE / BIRU", colors.blue, "Ditemukan kerentanan tingkat Rendah. Secara umum sistem cukup aman, namun disarankan untuk melakukan pengerasan (hardening) lebih lanjut."
        else:
            return "SECURE / HIJAU", colors.green, "Tidak ditemukan kerentanan serius pada target saat ini. Konfigurasi keamanan sudah cukup baik."

    def _build_executive_summary(self) -> List:
        story = []
        
        # Header Laporan
        title_style = self.styles['Title']
        story.append(Paragraph("Omni-Web-Auditor: Security Audit Report", title_style))
        story.append(Spacer(1, 12))
        
        normal_style = self.styles['Normal']
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"<b>Tanggal Audit:</b> {date_str}", normal_style))
        story.append(Paragraph(f"<b>Target:</b> {self.target}", normal_style))
        story.append(Spacer(1, 20))
        
        # Indikator Skor Visual & Business Impact
        status_text, status_color, impact_stmt = self._get_health_status()
        
        status_style = ParagraphStyle(
            'StatusStyle', 
            parent=self.styles['Heading2'], 
            textColor=status_color
        )
        story.append(Paragraph(f"Status Keamanan Keseluruhan: {status_text}", status_style))
        story.append(Spacer(1, 10))
        
        # Tabel Ringkasan
        data = [
            ['Severity', 'Total Temuan'],
            ['High / Critical', str(self.total_high)],
            ['Medium', str(self.total_medium)],
            ['Low', str(self.total_low)],
            ['Total Keseluruhan', str(len(self.findings))]
        ]
        
        t = Table(data, colWidths=[200, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (0,1), colors.pink),
            ('BACKGROUND', (0,2), (0,2), colors.navajowhite),
            ('BACKGROUND', (0,3), (0,3), colors.lightcyan),
            ('GRID', (0,0), (-1,-1), 1, colors.black)
        ]))
        story.append(t)
        story.append(Spacer(1, 20))
        
        # Business Impact Statement
        story.append(Paragraph("<b>Business Impact Statement:</b>", self.styles['Heading3']))
        story.append(Paragraph(impact_stmt, normal_style))
        
        story.append(PageBreak())
        return story

    def _build_technical_details(self) -> List:
        story = []
        story.append(Paragraph("Technical Remediation Details", self.styles['Title']))
        story.append(Spacer(1, 12))
        
        if not self.findings:
            story.append(Paragraph("Tidak ada kerentanan teknis yang ditemukan.", self.styles['Normal']))
            return story
            
        for i, finding in enumerate(self.findings):
            vuln = finding.get('vulnerability', 'Unknown')
            sev = finding.get('severity', 'Unknown')
            loc = finding.get('location', 'Unknown')
            evid = finding.get('evidence', 'None')
            rem = finding.get('remediation', 'None')
            
            sev_lower = sev.lower()
            if sev_lower in ['high', 'critical']:
                vuln_color = colors.red
            elif sev_lower == 'medium':
                vuln_color = colors.orange
            else:
                vuln_color = colors.blue
                
            vuln_style = ParagraphStyle(
                f'VulnStyle_{i}', 
                parent=self.styles['Heading3'], 
                textColor=vuln_color
            )
            
            normal = self.styles['Normal']
            data = [
                ['Vulnerability:', Paragraph(f"<b>{vuln}</b> [{sev}]", vuln_style)],
                ['Location:', Paragraph(loc, normal)],
                ['Evidence:', Paragraph(evid, normal)],
                ['Remediation:', Paragraph(rem, normal)]
            ]
            
            t = Table(data, colWidths=[100, 350])
            t.setStyle(TableStyle([
                ('ALIGN', (0,0), (0,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('BACKGROUND', (0,0), (0,-1), colors.lightgrey),
                ('PADDING', (0,0), (-1,-1), 6)
            ]))
            
            story.append(t)
            story.append(Spacer(1, 20))
            
        return story

    def generate_report(self, filename: str):
        doc = SimpleDocTemplate(filename, pagesize=letter)
        story = []
        
        story.extend(self._build_executive_summary())
        story.extend(self._build_technical_details())
        
        doc.build(story)
