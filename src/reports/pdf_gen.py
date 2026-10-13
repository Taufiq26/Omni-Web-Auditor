from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from typing import List, Dict
import datetime
from src.reports.rationale import secure_reason, count_related_findings

class PDFReportGenerator:
    def __init__(self, findings: List[Dict], target: str, coverage: List[Dict] = None):
        self.findings = findings
        self.target = target
        self.coverage = coverage or []
        self.total_high = 0
        self.total_medium = 0
        self.total_low = 0
        self._calculate_stats()
        self.total_skipped = sum(1 for c in self.coverage if c.get('status') == 'SKIPPED')
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Title'],
            fontName='Helvetica-Bold',
            fontSize=26,
            textColor=colors.HexColor('#2C3E50'),
            spaceAfter=10,
            alignment=1
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubTitle',
            parent=self.styles['Title'],
            fontName='Helvetica',
            fontSize=16,
            textColor=colors.HexColor('#7F8C8D'),
            spaceAfter=20,
            alignment=1
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=16,
            textColor=colors.HexColor('#34495E'),
            spaceBefore=20,
            spaceAfter=15,
            borderPadding=5
        ))

        self.styles.add(ParagraphStyle(
            name='NormalText',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            textColor=colors.HexColor('#2C3E50'),
            spaceAfter=10,
            leading=16
        ))

        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Normal'],
            fontName='Courier',
            fontSize=10,
            textColor=colors.HexColor('#C0392B'),
            backColor=colors.HexColor('#FDFEFE'),
            borderPadding=8,
            borderWidth=1,
            borderColor=colors.HexColor('#E5E8E8'),
            borderRadius=4,
            spaceAfter=5,
            leading=14
        ))

    def _calculate_stats(self):
        for finding in self.findings:
            sev = finding.get('severity', '').lower()
            if sev in ['high', 'critical']:
                self.total_high += 1
            elif sev == 'medium':
                self.total_medium += 1
            elif sev == 'low':
                self.total_low += 1

    def _get_health_status(self):
        if self.total_high > 0:
            return "CRITICAL", colors.HexColor('#C0392B'), "Ditemukan kerentanan tingkat Tinggi. Jika dieksploitasi, hal ini dapat menyebabkan gangguan layanan aplikasi, manipulasi *database*, dan potensi kebocoran data klien secara masif. Disarankan untuk <font color='red'><b>segera</b></font> mengalokasikan sumber daya teknis untuk perbaikan."
        elif self.total_medium > 0:
            return "WARNING", colors.HexColor('#D35400'), "Ditemukan kerentanan tingkat Menengah. Risiko gangguan cukup signifikan. Disarankan untuk menjadwalkan perbaikan dalam siklus pengembangan terdekat."
        elif self.total_low > 0:
            return "NOTICE", colors.HexColor('#2980B9'), "Ditemukan kerentanan tingkat Rendah. Secara umum sistem cukup aman, namun disarankan untuk melakukan pengerasan (hardening) lebih lanjut."
        elif self.total_skipped > 0:
            # Tidak ada temuan TAPI ada pengujian yang dilewati -> jangan klaim "aman".
            return "INCONCLUSIVE", colors.HexColor('#D35400'), (
                f"Tidak ditemukan kerentanan, NAMUN {self.total_skipped} jenis pengujian "
                "<b>tidak dijalankan</b> (lihat bagian Scan Coverage). Status ini "
                "<b>belum</b> berarti target aman -- sebagian cakupan belum teruji. "
                "Lengkapi kredensial/endpoint uji lalu scan ulang untuk kesimpulan yang valid."
            )
        else:
            return "SECURE", colors.HexColor('#27AE60'), "Tidak ditemukan kerentanan serius pada target saat ini, dan seluruh pengujian yang relevan telah dijalankan."

    def _build_executive_summary(self) -> List:
        story = []
        
        # Header Laporan
        story.append(Paragraph("Omni-Web-Auditor", self.styles['ReportTitle']))
        story.append(Paragraph("Security Audit Report", self.styles['SubTitle']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#BDC3C7'), spaceBefore=10, spaceAfter=30))
        
        date_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Meta Info Table
        meta_data = [
            [Paragraph("<b>Target URL / IP</b>", self.styles['NormalText']), Paragraph(f"<a href='{self.target}' color='blue'>{self.target}</a>", self.styles['NormalText'])],
            [Paragraph("<b>Tanggal Audit</b>", self.styles['NormalText']), Paragraph(f"{date_str}", self.styles['NormalText'])],
            [Paragraph("<b>Engine Version</b>", self.styles['NormalText']), Paragraph("v1.0.0", self.styles['NormalText'])],
        ]
        t_meta = Table(meta_data, colWidths=[150, 330])
        t_meta.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor('#ECF0F1')),
            ('PADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(t_meta)
        story.append(Spacer(1, 25))
        
        # Indikator Skor Visual & Business Impact
        status_text, status_color, impact_stmt = self._get_health_status()
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        status_style = ParagraphStyle(
            'StatusStyle', 
            parent=self.styles['Heading2'], 
            textColor=status_color,
            fontSize=16,
            fontName='Helvetica-Bold'
        )
        
        story.append(Paragraph(f"Health Status: <font color='{status_color}'>{status_text}</font>", status_style))
        story.append(Spacer(1, 15))
        
        # Tabel Ringkasan (Modern Look)
        summary_data = [
            ['Severity Level', 'Total Temuan'],
            ['High / Critical', str(self.total_high)],
            ['Medium', str(self.total_medium)],
            ['Low', str(self.total_low)],
            ['Total Keseluruhan', str(len(self.findings))]
        ]
        
        t_summary = Table(summary_data, colWidths=[250, 150])
        t_summary.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2C3E50')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 12),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('TOPPADDING', (0,0), (-1,0), 12),
            
            # Colors for rows
            ('BACKGROUND', (1,0), (1,0), colors.HexColor('#2C3E50')), # Header
            ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#FADBD8')), # High bg
            ('BACKGROUND', (0,2), (-1,2), colors.HexColor('#FDEBD0')), # Medium bg
            ('BACKGROUND', (0,3), (-1,3), colors.HexColor('#E8F8F5')), # Low bg
            ('BACKGROUND', (0,4), (-1,4), colors.HexColor('#F2F3F4')), # Total bg
            
            ('TEXTCOLOR', (0,1), (0,1), colors.HexColor('#C0392B')), # High Text
            ('TEXTCOLOR', (0,2), (0,2), colors.HexColor('#D35400')), # Medium Text
            ('TEXTCOLOR', (0,3), (0,3), colors.HexColor('#16A085')), # Low Text
            ('FONTNAME', (0,1), (0,3), 'Helvetica-Bold'), # Severity Name Bold
            ('FONTNAME', (0,4), (-1,4), 'Helvetica-Bold'), # Total Bold
            
            ('GRID', (0,0), (-1,-1), 1, colors.white),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('PADDING', (0,0), (-1,-1), 10),
        ]))
        story.append(t_summary)
        story.append(Spacer(1, 25))
        
        # Business Impact Statement
        story.append(Paragraph("Business Impact", self.styles['SectionHeader']))
        story.append(Paragraph(impact_stmt, self.styles['NormalText']))
        
        story.append(PageBreak())
        return story

    def _coverage_result(self, entry: Dict):
        """Tentukan (label_hasil, warna, penjelasan) untuk satu baris coverage.

        Untuk pengujian TESTED, laporan menyertakan BUKTI: apakah aman (dengan
        alasan singkat) atau ada temuan terkait (rujuk detail teknis). Ini membuat
        laporan tetap informatif meski tidak ada kerentanan sama sekali.
        """
        status = entry.get('status', 'UNKNOWN')
        test_name = entry.get('test', '')
        detail = entry.get('detail', '-')

        if status == 'TESTED':
            related = count_related_findings(test_name, self.findings)
            if related > 0:
                return (
                    f"&#9888; Ditemukan {related} temuan",
                    colors.HexColor('#C0392B'),
                    "Ada kelemahan pada aspek ini -- lihat bagian Technical Remediation Details.",
                )
            return (
                "&#10004; Aman",
                colors.HexColor('#16A085'),
                secure_reason(test_name),
            )
        if status == 'SKIPPED':
            return ("Belum teruji", colors.HexColor('#D35400'), detail)
        if status == 'NOT_APPLICABLE':
            return ("Tidak berlaku", colors.HexColor('#7F8C8D'), detail)
        return (status, colors.HexColor('#2C3E50'), detail)

    def _build_coverage_section(self) -> List:
        """Seksi bukti & kejujuran: apa yang diuji, hasilnya, dan kenapa aman.

        - Tes yang lulus disertai alasan singkat kenapa aspek itu aman (bukti).
        - Tes yang dilewati ditandai 'Belum teruji' -> cegah 'false sense of
          security' (docs/07-perbaikan-cakupan-scan.md, prinsip #6).
        """
        story = []
        if not self.coverage:
            return story

        story.append(Paragraph("Scan Coverage & Evidence", self.styles['ReportTitle']))
        story.append(Paragraph(
            "Rincian setiap pengujian yang dijalankan beserta hasil dan alasannya. "
            "Status 'Aman' hanya berlaku untuk pengujian yang benar-benar dijalankan.",
            self.styles['SubTitle']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#BDC3C7'), spaceBefore=10, spaceAfter=20))

        data = [[
            Paragraph("<b>Pengujian</b>", self.styles['NormalText']),
            Paragraph("<b>Hasil</b>", self.styles['NormalText']),
            Paragraph("<b>Penjelasan</b>", self.styles['NormalText']),
        ]]
        for c in self.coverage:
            label, color, explanation = self._coverage_result(c)
            data.append([
                Paragraph(c.get('test', '-'), self.styles['NormalText']),
                Paragraph(f"<font color='{color}'><b>{label}</b></font>", self.styles['NormalText']),
                Paragraph(explanation, self.styles['NormalText']),
            ])

        t = Table(data, colWidths=[120, 95, 265])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2C3E50')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#BDC3C7')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#BDC3C7')),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(t)
        story.append(PageBreak())
        return story

    def _build_technical_details(self) -> List:
        story = []
        story.append(Paragraph("Technical Remediation Details", self.styles['ReportTitle']))
        story.append(Paragraph("Daftar temuan teknis yang harus diperbaiki oleh Developer/Tim IT.", self.styles['SubTitle']))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#BDC3C7'), spaceBefore=10, spaceAfter=30))
        
        if not self.findings:
            tested = sum(1 for c in self.coverage if c.get('status') == 'TESTED')
            msg = (
                f"Tidak ada kerentanan teknis yang ditemukan. Sebanyak {tested} jenis "
                "pengujian telah dijalankan dan lulus -- rincian bukti tiap pengujian "
                "beserta alasan keamanannya tercantum pada bagian "
                "<b>Scan Coverage &amp; Evidence</b> di atas."
            )
            if self.total_skipped > 0:
                msg += (
                    f" <b>Catatan:</b> {self.total_skipped} pengujian tidak dijalankan "
                    "(lihat status 'Belum teruji'), sehingga hasil ini belum mencakup "
                    "seluruh permukaan serangan."
                )
            story.append(Paragraph(msg, self.styles['NormalText']))
            return story
            
        for i, finding in enumerate(self.findings):
            vuln = finding.get('vulnerability', 'Unknown')
            sev = finding.get('severity', 'Unknown')
            loc = finding.get('location', 'Unknown')
            evid = finding.get('evidence', 'None')
            rem = finding.get('remediation', 'None')
            
            sev_lower = sev.lower()
            if sev_lower in ['high', 'critical']:
                vuln_color = colors.HexColor('#C0392B')
            elif sev_lower == 'medium':
                vuln_color = colors.HexColor('#D35400')
            else:
                vuln_color = colors.HexColor('#2980B9')
                
            vuln_style = ParagraphStyle(
                f'VulnStyle_{i}', 
                parent=self.styles['Heading3'], 
                textColor=vuln_color,
                fontName='Helvetica-Bold',
                fontSize=14,
                spaceAfter=10
            )
            
            # Tampilkan judul vulnerability
            story.append(Paragraph(f"{i+1}. {vuln} [{sev.upper()}]", vuln_style))
            
            # Buat tabel untuk detail
            data = [
                [Paragraph("<b>Location</b>", self.styles['NormalText']), Paragraph(f"<font color='#2980B9'>{loc}</font>", self.styles['NormalText'])],
                [Paragraph("<b>Evidence</b>", self.styles['NormalText']), Paragraph(evid, self.styles['CodeBlock'])],
                [Paragraph("<b>Remediation</b>", self.styles['NormalText']), Paragraph(rem, self.styles['NormalText'])]
            ]
            
            t = Table(data, colWidths=[100, 380])
            t.setStyle(TableStyle([
                ('ALIGN', (0,0), (0,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#F4F6F7')),
                ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#2C3E50')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#BDC3C7')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#BDC3C7')),
                ('PADDING', (0,0), (-1,-1), 12)
            ]))
            
            story.append(t)
            story.append(Spacer(1, 30))
            
        return story

    def generate_report(self, filename: str):
        # Tambahkan margin agar lebih elegan
        doc = SimpleDocTemplate(
            filename, 
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        story = []
        
        story.extend(self._build_executive_summary())
        story.extend(self._build_coverage_section())
        story.extend(self._build_technical_details())
        
        doc.build(story)
