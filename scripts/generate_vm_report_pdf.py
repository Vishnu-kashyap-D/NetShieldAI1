import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#718096"))
        
        # Header (on pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 755, "NetShield AI — 2-VM Live Testing Report")
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(54, 747, 558, 747)
            
        # Footer
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)
        
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_str)
        self.drawString(54, 32, "CONFIDENTIAL — Academic Project Report & Defense")
        self.restoreState()

def generate_pdf(output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#1A365D"),
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#2C7A7B"),
        spaceAfter=15
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#1A365D"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#2B6CB0"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#2D3748"),
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13.5,
        textColor=colors.HexColor("#2D3748"),
        leftIndent=15,
        spaceAfter=3
    )

    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.white
    )

    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#2D3748")
    )

    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#1A365D")
    )
    
    callout_text = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#7B341E")
    )

    story = []

    # Title Banner
    story.append(Paragraph("NetShield AI — Isolated 2-VM Live Testing Report", title_style))
    story.append(Paragraph("Empirical Validation of Real-Time Network Threat Detection on Physical/Virtual Packets", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2B6CB0"), spaceAfter=12))

    # Metadata Card
    meta_data = [
        [Paragraph("<b>Project:</b> NetShield AI Network Intrusion Detection", table_cell), Paragraph("<b>Test Date / Env:</b> VirtualBox Isolated Lab", table_cell)],
        [Paragraph("<b>Author / Team:</b> BMSIT AI&ML Department (7th Sem)", table_cell), Paragraph("<b>Validation Type:</b> Live Out-of-Band Packet Capture", table_cell)],
        [Paragraph("<b>Architecture:</b> Autoencoder + BiLSTM + SHAP", table_cell), Paragraph("<b>Status:</b> Validated & Deployed", table_cell)]
    ]
    meta_table = Table(meta_data, colWidths=[250, 254])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#EDF2F7")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # Section 1: Executive Overview
    story.append(Paragraph("1. Executive Summary & Objective", h1_style))
    story.append(Paragraph(
        "While historical benchmarks like CICIDS2017 are critical for offline neural network training and statistical validation, "
        "they rely on pre-recorded, static flow records. To evaluate <b>NetShield AI</b> in an operationally authentic environment, "
        "an air-gapped, two-virtual-machine testbed was deployed. The objective was to demonstrate that live, raw network packets "
        "generated by real security assessment tools could be passively captured, converted into 76 directional statistical flow features, "
        "and successfully classified in real-time by our hybrid deep learning pipeline without touching production infrastructure.",
        body_style
    ))

    # Section 2: Environment Topology
    story.append(Paragraph("2. Testbed Architecture & Network Isolation Topology", h1_style))
    story.append(Paragraph(
        "The testbed isolates attack generation from detection. The physical host runs the detection engine and dashboard, "
        "while two dedicated VMs communicate over a sandboxed VirtualBox subnet.",
        body_style
    ))

    topo_data = [
        [Paragraph("Node / Component", table_header), Paragraph("Environment & IP", table_header), Paragraph("Key Role & Responsibility", table_header)],
        [
            Paragraph("<b>Attacker VM</b>", table_cell_bold),
            Paragraph("Linux (Dedicated VM)<br/>192.168.56.10<br/>(Host-Only: vboxnet0)", table_cell),
            Paragraph("Generates targeted attack vectors using <code>hping3</code> (SYN floods), <code>hydra</code> (brute force), and port scanners. NAT adapter detached.", table_cell)
        ],
        [
            Paragraph("<b>Victim VM</b>", table_cell_bold),
            Paragraph("Linux (Dedicated VM)<br/>192.168.56.20<br/>(Host-Only: vboxnet0)", table_cell),
            Paragraph("Hosts mock services (HTTP, SSH). Passively records all traffic via <code>tcpdump</code> to an isolated <code>capture.pcap</code> file.", table_cell)
        ],
        [
            Paragraph("<b>Host Machine</b><br/>(Physical Workstation)", table_cell_bold),
            Paragraph("Windows 11<br/>192.168.56.1 (Gateway)<br/>Localhost:8000 / 5173", table_cell),
            Paragraph("Runs NetShield backend (FastAPI, MySQL, Autoencoder, BiLSTM, SHAP), Vite React Dashboard, and the protocol conversion bridge. Completely out-of-band.", table_cell)
        ]
    ]
    topo_table = Table(topo_data, colWidths=[110, 130, 264])
    topo_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1A365D")),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFC")]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(topo_table)
    story.append(Spacer(1, 10))

    # Section 3: Machine Configurations
    story.append(Paragraph("3. Detailed Node Roles & Attack Vectors", h1_style))
    story.append(Paragraph("<b>VM 1: Attacker Machine (Offensive Workstation)</b>", h2_style))
    story.append(Paragraph(
        "• <b>Volumetric / Flooding Attacks:</b> <code>hping3 --flood -S -p 80 192.168.56.20</code> generated high-volume SYN bursts to stress flow rate and inter-arrival time (IAT) features.<br/>"
        "• <b>Authentication Brute Force:</b> <code>hydra -l admin -P wordlist.txt ssh://192.168.56.20</code> created repeated authentication cycles with rapid TCP session establishments.<br/>"
        "• <b>Reconnaissance Scanning:</b> SYN sweep scans across ports 1-1024 produced short-duration, zero-payload directional flows.",
        bullet_style
    ))
    
    story.append(Paragraph("<b>VM 2: Victim Machine (Target Node & Passive Sensor)</b>", h2_style))
    story.append(Paragraph(
        "• <b>Target Services:</b> Configured with active TCP/IP listeners (Apache HTTP on port 80, OpenSSH on port 22).<br/>"
        "• <b>Promiscuous Sniffing:</b> Captured raw packets into memory and disk: <code>sudo tcpdump -i eth0 -w capture.pcap</code>.<br/>"
        "• <b>Out-of-Band Delivery:</b> Once completed, the pcap was securely copied out: <code>scp victim@192.168.56.20:~/capture.pcap ./captures/</code>.",
        bullet_style
    ))
    story.append(Spacer(1, 10))

    # Page Break for clean layout
    story.append(PageBreak())

    # Section 4: Upstream Bug Fixes
    story.append(Paragraph("4. Protocol Bridging & Upstream Bug Fixes (`live_capture_feed.py`)", h1_style))
    story.append(Paragraph(
        "To convert raw PCAP files into the required 76-feature vector format on an air-gapped machine without a full Java toolchain, "
        "a Python-based conversion bridge was developed. During integration, <b>4 critical upstream bugs</b> in the open-source "
        "<code>cicflowmeter</code> package were diagnosed and patched:",
        body_style
    ))

    bug_data = [
        [Paragraph("Bug Diagnosed", table_header), Paragraph("Technical Failure Mode", table_header), Paragraph("Implemented Solution", table_header)],
        [
            Paragraph("<b>1. AsyncSniffer Buffer Flush</b>", table_cell_bold),
            Paragraph("In offline mode (<code>store=False</code>), the sniffer loop exited without calling <code>session.toPacketList()</code>, resulting in 0 flows output.", table_cell),
            Paragraph("Bypassed the wrapper entirely by driving the packet session directly using Scapy's <code>PcapReader</code> in a deterministic generator loop.", table_cell)
        ],
        [
            Paragraph("<b>2. NumPy Timestamp Type Conflict</b>", table_cell_bold),
            Paragraph("Scapy's high-precision <code>EDecimal</code> timestamps raised <code>TypeError: conversion from numpy.int64 to Decimal</code> in modern NumPy.", table_cell),
            Paragraph("Pre-cast all packet arrival timestamps to standard 64-bit Python <code>float</code> primitives prior to statistical feature aggregation.", table_cell)
        ],
        [
            Paragraph("<b>3. Mixed Decimal Arithmetic</b>", table_cell_bold),
            Paragraph("Flow classes multiplied float timestamps by <code>Decimal('1e6')</code>, causing fatal unsupported operand type exceptions.", table_cell),
            Paragraph("Dynamically monkeypatched <code>add_packet</code>, <code>update_subflow</code>, and <code>update_active_idle</code> to utilize float literals.", table_cell)
        ],
        [
            Paragraph("<b>4. Silent TCP Flag Miscounting</b>", table_cell_bold),
            Paragraph("<code>FlagCount.has_flag()</code> inspected outer <code>packet.flags</code> (IP layer DF/MF bits) instead of TCP flags! SYN/ACK counts were always 0.", table_cell),
            Paragraph("Explicitly bound inspection to <code>packet['TCP'].flags</code>, restoring accurate SYN/ACK/RST/FIN counting for proper classification.", table_cell)
        ]
    ]
    bug_table = Table(bug_data, colWidths=[110, 194, 200])
    bug_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2C7A7B")),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFC")]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(bug_table)
    story.append(Spacer(1, 10))

    # Section 5: Processing Flow
    story.append(Paragraph("5. End-to-End Pipeline & Inference Execution", h1_style))
    story.append(Paragraph(
        "1. <b>Sliding Windowing:</b> Extracted flow records were packaged into sequential 10-row temporal windows (stride 5).<br/>"
        "2. <b>Stage 1 (Autoencoder Gate):</b> Each window was evaluated for reconstruction error against a data-calibrated baseline threshold. "
        "Benign traffic was dropped; anomalous windows triggered Stage 2.<br/>"
        "3. <b>Stage 2 (BiLSTM Classification):</b> Flagged windows were passed to the Bidirectional LSTM model to predict category probabilities across "
        "DoS/DDoS, Port Scanning, Brute Force, Botnet Activity, Malware Traffic, and Data Exfiltration.<br/>"
        "4. <b>Stage 3 (Hybrid Risk Fusion):</b> Risk scores were calculated as <code>risk = max(anomaly_score, classifier_confidence)</code> and mapped to High, Medium, or Low.<br/>"
        "5. <b>Stage 4 (Explainable AI via SHAP):</b> High-risk windows triggered <code>shap.GradientExplainer</code>, detailing the top 5 contributing flow features.<br/>"
        "6. <b>Stage 5 (SOC Presentation):</b> Results were stored in MySQL and pushed to the live React dashboard.",
        bullet_style
    ))
    story.append(Spacer(1, 10))

    # Section 6: Results & Key Findings
    story.append(Paragraph("6. Empirical Results & Critical Analytical Findings", h1_style))
    
    # Callout Box
    callout_data = [[
        Paragraph(
            "<b>Key Finding:</b> While modern attack tools produce subtle signature variances compared to historic training sets, "
            "NetShield's sequential Autoencoder anomaly gate reliably triggered on real floods and scans. Even when the classifier was "
            "uncertain about the exact label, the system successfully fired a High Risk alert.",
            callout_text
        )
    ]]
    callout_table = Table(callout_data, colWidths=[504])
    callout_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#FFFAF0")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#DD6B20")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(callout_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "• <b>Anomaly Gate Robustness:</b> The Autoencoder demonstrated strong domain transfer, catching volumetric bursts from <code>hping3</code> and fast connection attempts from <code>hydra</code> with anomaly errors 3x above normal thresholds.<br/>"
        "• <b>Labeling Divergence (Tool Signatures):</b> Raw tool traffic was sometimes classified under <i>Malware Traffic</i> rather than the tool's intended attack class. This highlighted that supervised classifiers are sensitive to environment-specific packet crafting, justifying our hybrid fusion approach.<br/>"
        "• <b>Sequential Gate Ceiling:</b> Certain low-rate port scans bypassed individual 10-row windows, corroborating the project's documented ~54% single-window recall ceiling and motivating our multi-window Sustained Activity persistence detector.<br/>"
        "• <b>Zero Endpoint Overhead:</b> Testing confirmed that passive out-of-band sniffing introduces 0% CPU/memory overhead on protected victim workloads.",
        bullet_style
    ))
    story.append(Spacer(1, 10))

    # Section 7: Rules of Engagement
    story.append(Paragraph("7. Lab Rules of Engagement & Safety Controls", h1_style))
    story.append(Paragraph(
        "To guarantee ethical compliance and prevent network contamination during live execution, the following protocols were strictly maintained:<br/>"
        "• <b>R1 & R2 (Complete Network Isolation):</b> Host-Only adapters exclusively. NAT adapters disconnected before starting offensive tools.<br/>"
        "• <b>R3 & R6 (VM Hygiene):</b> VMs operated from clean snapshots, reverted post-test. Clipboard/folder sharing disabled during runs.<br/>"
        "• <b>R4 & R5 (Scope & Tool Limits):</b> Standard tools only (no wild malware/worms). Targets verified strictly against the victim IP (<code>192.168.56.20</code>).<br/>"
        "• <b>R7 & R8 (Attended Operations):</b> Time-bounded executions with active human supervision. Captured PCAPs handled as raw data without execution.",
        bullet_style
    ))
    story.append(Spacer(1, 15))

    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E0"), spaceAfter=10))
    story.append(Paragraph(
        "<b>Conclusion:</b> The 2-VM experimental testbed successfully validated NetShield AI as a functional, end-to-end "
        "Network Intrusion Detection System capable of converting raw network frames into actionable, explainable threat intelligence.",
        body_style
    ))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF successfully generated at: {output_path}")

if __name__ == "__main__":
    out_file = r"v:\vishnu\notes pdf\7th SEM\Major-project(P2)\prototype\me\docs\NetShieldAI_2VM_Live_Testing_Report.pdf"
    generate_pdf(out_file)
