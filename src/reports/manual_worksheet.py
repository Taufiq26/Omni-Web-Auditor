"""Lembar Kerja Manual (Manual Testing Worksheet) dalam PDF.

Berisi HANYA item checklist WSTG yang MURNI MANUAL (type != auto/hybrid) — yakni
pengujian yang TIDAK dapat dinilai otomatis oleh tool dan harus dikerjakan pen-tester
(mis. session fixation, business logic, SSRF, stored XSS, authz vertical bypass).

Tujuan pemisahan: laporan tool otomatis fokus pada "apa yang tool periksa & hasilnya",
sedangkan dokumen ini menjadi daftar kerja manual yang jujur & actionable — bukan
sekumpulan TODO yang mengaburkan laporan otomatis.
"""

from typing import List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)

from src.core.engagement import Engagement
from src.checklist.loader import ChecklistItem

TOOL_VERSION = "v2.0.0 (WSTG-based)"

_STATUS_COLORS = {
    "pass": colors.HexColor("#16A085"),
    "fail": colors.HexColor("#C0392B"),
    "na": colors.HexColor("#7F8C8D"),
    "todo": colors.HexColor("#D35400"),
    "skipped": colors.HexColor("#D35400"),
}


class ManualWorksheet:
    def __init__(self, engagement: Engagement, items: List[ChecklistItem]):
        self.eng = engagement
        # Hanya item murni manual (tidak dapat diperiksa tool).
        self.items = [it for it in items if not it.is_auto]
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        add = self.styles.add
        add(ParagraphStyle(name="MW_Title", parent=self.styles["Title"], fontSize=22,
                           textColor=colors.HexColor("#2C3E50"), spaceAfter=6))
        add(ParagraphStyle(name="MW_Sub", parent=self.styles["Title"], fontSize=13,
                           textColor=colors.HexColor("#7F8C8D"), spaceAfter=14))
        add(ParagraphStyle(name="MW_H", parent=self.styles["Heading2"], fontSize=14,
                           textColor=colors.HexColor("#34495E"), spaceBefore=14, spaceAfter=8))
        add(ParagraphStyle(name="MW_Body", parent=self.styles["Normal"], fontSize=10,
                           textColor=colors.HexColor("#2C3E50"), leading=14, spaceAfter=6))
        add(ParagraphStyle(name="MW_Small", parent=self.styles["Normal"], fontSize=8.5,
                           textColor=colors.HexColor("#2C3E50"), leading=12))

    def _header(self):
        s = []
        s.append(Paragraph("Manual Testing Worksheet", self.styles["MW_Title"]))
        s.append(Paragraph("WSTG — Pengujian Manual (di luar cakupan otomatis tool)", self.styles["MW_Sub"]))
        s.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#BDC3C7"), spaceAfter=14))
        eng = self.eng
        meta = [
            ["Target", eng.target],
            ["Engagement", eng.name],
            ["Environment", eng.environment],
            ["Penguji", f"{eng.tester_name or '-'} ({eng.tester_role})"],
            ["Tool", TOOL_VERSION],
        ]
        t = Table([[Paragraph(f"<b>{k}</b>", self.styles["MW_Body"]), Paragraph(str(v), self.styles["MW_Body"])]
                   for k, v in meta], colWidths=[120, 360])
        t.setStyle(TableStyle([
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#ECF0F1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("PADDING", (0, 0), (-1, -1), 7),
        ]))
        s.append(t)
        s.append(Spacer(1, 10))
        s.append(Paragraph(
            "Dokumen ini berisi pengujian WSTG yang <b>tidak dapat dinilai otomatis</b> dan "
            "<b>wajib dikerjakan manual</b> oleh pen-tester menggunakan akun uji sendiri "
            "secara non-destruktif. Kolom Status/Catatan diisi saat pengujian. Hasilnya "
            "melengkapi laporan tool otomatis (file terpisah).",
            self.styles["MW_Body"]))
        return s

    def _items_table(self):
        s = [Paragraph(f"Daftar Pengujian Manual ({len(self.items)} item)", self.styles["MW_H"])]
        if not self.items:
            s.append(Paragraph("Tidak ada item manual pada checklist.", self.styles["MW_Body"]))
            return s
        head = ["ID", "Kategori / Pengujian", "Objective & Langkah", "Status", "Catatan"]
        data = [[Paragraph(f"<b>{h}</b>", self.styles["MW_Small"]) for h in head]]
        for it in self.items:
            st = self.eng.item_states.get(it.id, {"status": "todo", "note": ""})
            status = st.get("status", "todo")
            color = _STATUS_COLORS.get(status, colors.black)
            obj = f"<b>Objective:</b> {it.objective or '-'}<br/><b>Langkah:</b> {it.steps or '-'}"
            data.append([
                Paragraph(it.id, self.styles["MW_Small"]),
                Paragraph(f"<b>{it.category}</b><br/>{it.title}", self.styles["MW_Small"]),
                Paragraph(obj, self.styles["MW_Small"]),
                Paragraph(f"<font color='{color}'><b>{status.upper()}</b></font>", self.styles["MW_Small"]),
                Paragraph(st.get("note", "") or "", self.styles["MW_Small"]),
            ])
        t = Table(data, colWidths=[62, 120, 190, 48, 60], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C3E50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BDC3C7")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F9FA")]),
        ]))
        s.append(t)
        return s

    def build(self, output_path: str):
        doc = SimpleDocTemplate(output_path, pagesize=letter,
                                rightMargin=40, leftMargin=40, topMargin=54, bottomMargin=54)
        story = []
        story += self._header()
        story += self._items_table()
        doc.build(story)


def generate_manual_worksheet(engagement, items, output_path: str):
    ManualWorksheet(engagement, items).build(output_path)
