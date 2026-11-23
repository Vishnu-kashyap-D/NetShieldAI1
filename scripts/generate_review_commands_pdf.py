import os
import shutil
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.pdfgen import canvas

class SinglePageCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(SinglePageCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_footer(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_footer(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#718096"))
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(40, 36, 572, 36)
        
        self.drawString(40, 24, "NetShield AI · Project Review Quick Run Sheet")
        self.drawRightString(572, 24, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()

def create_code_block(title, code_lines, note=None):
    code_text = "<br/>".join([f"<code>{line}</code>" for line in code_lines])
    cell_content = [
        Paragraph(f"<b>{title}</b>", ParagraphStyle('CodeTitle', fontName='Helvetica-Bold', fontSize=10, leading=14, textColor=colors.HexColor("#1A365D"))),
        Spacer(1, 4),
        Paragraph(code_text, ParagraphStyle('CodeText', fontName='Courier', fontSize=8.5, leading=12, textColor=colors.HexColor("#1A202C"))),
    ]
    if note:
        cell_content.extend([
            Spacer(1, 4),
            Paragraph(f"<i>{note}</i>", ParagraphStyle('CodeNote', fontName='Helvetica-Oblique', fontSize=8, leading=11, textColor=colors.HexColor("#4A5568")))
        ])
    
    t = Table([[cell_content]], colWidths=[532])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E0")),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
    ]))
    return t

def generate_review_pdf(output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=36,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1A365D"),
        spaceAfter=2
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#2C7A7B"),
        spaceAfter=8
    )

    h2_style = ParagraphStyle(
        'StepHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#2B6CB0"),
        spaceBefore=8,
        spaceAfter=4
    )

    body_style = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#2D3748")
    )

    story = []

    # Title & Subtitle
    story.append(Paragraph("NetShield AI — Project Review & Demo Run Sheet", title_style))
    story.append(Paragraph("Exact copy-paste commands to launch and present the system live during evaluation", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2B6CB0"), spaceAfter=8))

    # STEP 1: BACKEND
    story.append(Paragraph("STEP 1: Terminal 1 — Start Backend & Load AI Models", h2_style))
    backend_code = [
        "conda activate netshield",
        'cd "v:\\vishnu\\notes pdf\\7th SEM\\Major-project(P2)\\prototype\\me\\backend"',
        '$env:PYTHONPATH="..;."',
        "python -m uvicorn app.main:app --port 8000"
    ]
    story.append(create_code_block(
        "PowerShell Terminal 1",
        backend_code,
        "Look for: 'Model loaded' and 'Uvicorn running on http://127.0.0.1:8000'. The Autoencoder and BiLSTM are now active."
    ))
    story.append(Spacer(1, 8))

    # STEP 2: FRONTEND
    story.append(Paragraph("STEP 2: Terminal 2 — Start SOC Dashboard (Frontend)", h2_style))
    frontend_code = [
        'cd "v:\\vishnu\\notes pdf\\7th SEM\\Major-project(P2)\\prototype\\me\\frontend\\dashboard-app"',
        "npm run dev"
    ]
    story.append(create_code_block(
        "PowerShell Terminal 2",
        frontend_code,
        "Ready at: http://localhost:5173 | Login: admin@netshield.ai | Password: NetShield@123"
    ))
    story.append(Spacer(1, 8))

    # STEP 3: DEMO TRAFFIC
    story.append(Paragraph("STEP 3: Terminal 3 — Trigger Live Attack Stream (Show to Reviewers)", h2_style))
    demo_code = [
        "conda activate netshield",
        'cd "v:\\vishnu\\notes pdf\\7th SEM\\Major-project(P2)\\prototype\\me"',
        "python backend/scripts/stream_simulator.py"
    ]
    story.append(create_code_block(
        "PowerShell Terminal 3",
        demo_code,
        "Narrative: Streams real CICIDS traffic: Benign -> DDoS (~99% conf) -> Port Scan (partial) -> Botnet (~75% conf). Alerts appear live."
    ))
    story.append(Spacer(1, 8))

    # QUICK CREDENTIALS & LINKS TABLE
    story.append(Paragraph("Reviewer Quick Reference & Demo Credentials", h2_style))
    creds_data = [
        [
            Paragraph("<b>URL / Service</b>", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, leading=11, textColor=colors.white)),
            Paragraph("<b>Address</b>", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, leading=11, textColor=colors.white)),
            Paragraph("<b>Credentials / Details</b>", ParagraphStyle('TH', fontName='Helvetica-Bold', fontSize=8, leading=11, textColor=colors.white))
        ],
        [
            Paragraph("<b>Dashboard (Vite)</b>", body_style),
            Paragraph("<code>http://localhost:5173</code>", body_style),
            Paragraph("admin@netshield.ai / NetShield@123 (Administrator)", body_style)
        ],
        [
            Paragraph("<b>Analyst Account</b>", body_style),
            Paragraph("<code>http://localhost:5173</code>", body_style),
            Paragraph("analyst@netshield.ai / NetShield@123 (Can submit feedback)", body_style)
        ],
        [
            Paragraph("<b>API Docs (Swagger)</b>", body_style),
            Paragraph("<code>http://localhost:8000/docs</code>", body_style),
            Paragraph("Interactive API testing & endpoint documentation", body_style)
        ],
        [
            Paragraph("<b>API Health Check</b>", body_style),
            Paragraph("<code>http://localhost:8000/api/health</code>", body_style),
            Paragraph('{"status":"ok", "model_loaded":true, "feature_count":76}', body_style)
        ]
    ]
    creds_table = Table(creds_data, colWidths=[120, 150, 262])
    creds_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1A365D")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFC")]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(creds_table)
    story.append(Spacer(1, 8))

    # CHECKS BEFORE REVIEW
    story.append(Paragraph("30-Second Pre-Review Health Checklist", h2_style))
    checklist_text = (
        "1. <b>MySQL Service:</b> Ensure MySQL80 service is running.<br/>"
        "2. <b>Port Availability:</b> Ports 8000 and 5173 must be free before starting.<br/>"
        "3. <b>Model Files Present:</b> <code>artifacts/models/autoencoder.keras</code> & <code>bilstm_classifier.keras</code>.<br/>"
        "4. <b>Offline / Demo Mode:</b> If backend is ever stopped, the frontend has a 'Mock Mode' toggle on top to still demonstrate the UI."
    )
    story.append(Paragraph(checklist_text, body_style))

    doc.build(story, canvasmaker=SinglePageCanvas)
    print(f"Review PDF generated: {output_path}")

if __name__ == "__main__":
    out = r"v:\vishnu\notes pdf\7th SEM\Major-project(P2)\prototype\me\docs\NetShieldAI_Review_Commands.pdf"
    generate_review_pdf(out)
    
    # Also copy to extra planning and stuff folder
    extra_dir = r"V:\vishnu\notes pdf\7th SEM\Major-project(P2)\extra planning and stuff\detailes about VM testing"
    if os.path.exists(extra_dir):
        dst = os.path.join(extra_dir, "NetShieldAI_Review_Commands.pdf")
        shutil.copy2(out, dst)
        print(f"Copied to: {dst}")
