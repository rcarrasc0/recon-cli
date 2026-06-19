#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  recon-cli · report/pdf_gen.py
#  Genera el informe PDF de seguridad con ReportLab.
#  Secciones: portada, resumen ejecutivo, hallazgos por fase,
#  tabla CVSS, análisis SSL, CVEs, propuestas de mitigación.
# ─────────────────────────────────────────────────────────────

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor

RECON_CLI_VERSION = "v1.2.0"

# ── Paleta de colores ─────────────────────────────────────────
C_PRIMARY    = HexColor("#0D1117")   # Negro profundo
C_ACCENT     = HexColor("#00D4AA")   # Verde ciberseguridad
C_ACCENT2    = HexColor("#1F6FEB")   # Azul
C_BG_LIGHT   = HexColor("#F6F8FA")   # Gris muy claro
C_BORDER     = HexColor("#30363D")   # Gris oscuro
C_TEXT       = HexColor("#24292F")   # Texto principal
C_MUTED      = HexColor("#57606A")   # Texto secundario

SEV_COLORS = {
    "CRITICAL": HexColor("#DA3633"),
    "HIGH":     HexColor("#E36209"),
    "MEDIUM":   HexColor("#D29922"),
    "LOW":      HexColor("#1F6FEB"),
    "INFO":     HexColor("#57606A"),
    "NONE":     HexColor("#57606A"),
}

SEV_BG = {
    "CRITICAL": HexColor("#FFF0F0"),
    "HIGH":     HexColor("#FFF8F0"),
    "MEDIUM":   HexColor("#FFFBEA"),
    "LOW":      HexColor("#F0F6FF"),
    "INFO":     HexColor("#F6F8FA"),
    "NONE":     HexColor("#F6F8FA"),
}

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm


# ── Numeración de páginas ─────────────────────────────────────
class PageNumCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def _draw_page_number(self, page_count):
        page = self._pageNumber
        if page <= 1:
            return
        self.setFont("Helvetica", 8)
        self.setFillColor(C_MUTED)
        self.drawRightString(
            PAGE_W - MARGIN,
            1.2 * cm,
            f"Página {page} de {page_count}"
        )
        self.setStrokeColor(C_BORDER)
        self.setLineWidth(0.5)
        self.line(MARGIN, 1.5 * cm, PAGE_W - MARGIN, 1.5 * cm)


# ── Línea horizontal decorativa ──────────────────────────────
class ColorLine(Flowable):
    def __init__(self, width, color, thickness=1):
        Flowable.__init__(self)
        self.width     = width
        self.color     = color
        self.thickness = thickness
        self.height    = thickness + 2

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, 0, self.width, 0)


# ── Estilos ───────────────────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()
    styles = {}

    styles["cover_title"] = ParagraphStyle(
        "cover_title",
        fontName="Helvetica-Bold", fontSize=28,
        textColor=colors.white, alignment=TA_CENTER,
        spaceAfter=8,
    )
    styles["cover_subtitle"] = ParagraphStyle(
        "cover_subtitle",
        fontName="Helvetica", fontSize=14,
        textColor=C_ACCENT, alignment=TA_CENTER,
        spaceAfter=4,
    )
    styles["cover_meta"] = ParagraphStyle(
        "cover_meta",
        fontName="Helvetica", fontSize=10,
        textColor=HexColor("#8B949E"), alignment=TA_CENTER,
        spaceAfter=2,
    )
    styles["h1"] = ParagraphStyle(
        "h1",
        fontName="Helvetica-Bold", fontSize=16,
        textColor=C_PRIMARY, spaceBefore=16, spaceAfter=8,
        borderPad=4,
    )
    styles["h2"] = ParagraphStyle(
        "h2",
        fontName="Helvetica-Bold", fontSize=12,
        textColor=C_ACCENT2, spaceBefore=12, spaceAfter=6,
    )
    styles["h3"] = ParagraphStyle(
        "h3",
        fontName="Helvetica-Bold", fontSize=10,
        textColor=C_TEXT, spaceBefore=8, spaceAfter=4,
    )
    styles["body"] = ParagraphStyle(
        "body",
        fontName="Helvetica", fontSize=9,
        textColor=C_TEXT, spaceAfter=4,
        leading=14, alignment=TA_JUSTIFY,
    )
    styles["body_small"] = ParagraphStyle(
        "body_small",
        fontName="Helvetica", fontSize=8,
        textColor=C_MUTED, spaceAfter=2, leading=12,
    )
    styles["code"] = ParagraphStyle(
        "code",
        fontName="Courier", fontSize=8,
        textColor=C_TEXT, backColor=C_BG_LIGHT,
        spaceAfter=4, leading=12,
        leftIndent=8, rightIndent=8,
        borderWidth=1, borderColor=C_BORDER,
        borderPad=4,
    )
    styles["tag_critical"] = ParagraphStyle(
        "tag_critical",
        fontName="Helvetica-Bold", fontSize=8,
        textColor=colors.white, alignment=TA_CENTER,
    )
    styles["finding_title"] = ParagraphStyle(
        "finding_title",
        fontName="Helvetica-Bold", fontSize=10,
        textColor=C_TEXT, spaceAfter=2,
    )
    styles["finding_body"] = ParagraphStyle(
        "finding_body",
        fontName="Helvetica", fontSize=9,
        textColor=C_TEXT, leading=13, spaceAfter=3,
    )
    styles["remediation"] = ParagraphStyle(
        "remediation",
        fontName="Helvetica-Oblique", fontSize=9,
        textColor=HexColor("#0D6634"), leading=13,
        leftIndent=8,
    )
    styles["toc_entry"] = ParagraphStyle(
        "toc_entry",
        fontName="Helvetica", fontSize=10,
        textColor=C_TEXT, spaceAfter=4,
    )

    return styles


# ── Función principal ─────────────────────────────────────────
def generate_report(results: dict, output_path: str, config: dict):
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=2 * cm,
        title=f"Informe de Seguridad — {results['target']}",
        author=config.get("REPORT_AUTHOR", "recon-cli"),
        subject="Informe de análisis de seguridad",
    )

    styles  = _build_styles()
    story   = []
    content_width = PAGE_W - 2 * MARGIN

    # ── PORTADA ───────────────────────────────────────────────
    story += _build_cover(results, config, styles, content_width)

    # ── RESUMEN EJECUTIVO ─────────────────────────────────────
    story.append(PageBreak())
    story += _build_executive_summary(results, styles, content_width)

    # ── ALCANCE Y METODOLOGÍA ─────────────────────────────────
    story.append(PageBreak())
    story += _build_scope_section(results, styles, content_width)

    # ── HALLAZGOS POR SEVERIDAD ───────────────────────────────
    story.append(PageBreak())
    story += _build_findings_section(results, styles, content_width)

    # ── ANÁLISIS SSL/TLS ──────────────────────────────────────
    story.append(PageBreak())
    story += _build_ssl_section(results, styles, content_width)

    # ── ANÁLISIS DE CABECERAS ─────────────────────────────────
    story += _build_headers_section(results, styles, content_width)

    # ── WAF / CDN ─────────────────────────────────────────────
    if results.get("waf_cdn"):
        story.append(PageBreak())
        story += _build_waf_section(results, styles, content_width)

    # ── OSINT & RECONOCIMIENTO ────────────────────────────────
    story.append(PageBreak())
    story += _build_osint_section(results, styles, content_width)

    # ── CVEs ──────────────────────────────────────────────────
    if results.get("cves"):
        story.append(PageBreak())
        story += _build_cves_section(results, styles, content_width)

    # ── TABLA CVSS CONSOLIDADA ────────────────────────────────
    story.append(PageBreak())
    story += _build_cvss_table(results, styles, content_width)

    # ── PROPUESTAS DE MITIGACIÓN ──────────────────────────────
    story.append(PageBreak())
    story += _build_mitigations_section(results, styles, content_width)

    # Construir PDF
    doc.build(story, canvasmaker=PageNumCanvas)


# ── PORTADA ───────────────────────────────────────────────────
def _build_cover(results, config, styles, w):
    story = []
    target     = results["target"]
    start_time = results["start_time"]
    scope      = results.get("scope", "blackbox").upper()
    author     = config.get("REPORT_AUTHOR", "recon-cli")

    # Fondo negro (tabla con background)
    cover_data = [[""]]
    cover_table = Table(cover_data, colWidths=[w], rowHeights=[PAGE_H - 5 * cm])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_PRIMARY),
        ("TOPPADDING",    (0, 0), (-1, -1), 60),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    # Construir contenido de portada como story independiente
    story.append(Spacer(1, 3 * cm))

    # Línea decorativa superior
    story.append(ColorLine(w, C_ACCENT, 3))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("INFORME DE SEGURIDAD", styles["cover_title"]))
    story.append(Paragraph("Análisis de Reconocimiento & Vulnerabilidades", styles["cover_subtitle"]))

    story.append(Spacer(1, 1 * cm))

    # Target box
    target_data = [[Paragraph(f"<b>TARGET</b>: {target}", ParagraphStyle(
        "target_box", fontName="Courier-Bold", fontSize=18,
        textColor=C_ACCENT, alignment=TA_CENTER,
    ))]]
    target_table = Table(target_data, colWidths=[w * 0.7])
    target_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#161B22")),
        ("LINEABOVE",     (0, 0), (-1, 0),  2, C_ACCENT),
        ("LINEBELOW",     (0, -1), (-1, -1), 2, C_ACCENT),
        ("TOPPADDING",    (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))

    # Centrar la tabla de target
    container = Table([[target_table]], colWidths=[w])
    container.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story.append(container)

    story.append(Spacer(1, 1.5 * cm))

    # Metadata grid
    meta_rows = [
        ["Tipo de análisis", scope],
        ["Fecha de análisis", start_time.strftime("%d/%m/%Y %H:%M:%S UTC")],
        ["Autor del informe", author],
        ["Clasificación", "CONFIDENCIAL"],
        ["Versión herramienta", RECON_CLI_VERSION],
    ]
    meta_style = ParagraphStyle("meta_k", fontName="Helvetica", fontSize=10, textColor=HexColor("#8B949E"))
    meta_val_s = ParagraphStyle("meta_v", fontName="Helvetica-Bold", fontSize=10, textColor=colors.white)

    meta_data = [[
        Paragraph(k, meta_style),
        Paragraph(v, meta_val_s),
    ] for k, v in meta_rows]

    meta_table = Table(meta_data, colWidths=[w * 0.35, w * 0.55])
    meta_table.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (0, -1), "RIGHT"),
        ("ALIGN",         (1, 0), (1, -1), "LEFT"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.5, C_BORDER),
    ]))

    container2 = Table([[meta_table]], colWidths=[w])
    container2.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story.append(container2)

    story.append(Spacer(1, 1 * cm))
    story.append(ColorLine(w, C_ACCENT, 3))

    # Findings quick stats
    findings = results.get("findings", [])
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    story.append(Spacer(1, 0.8 * cm))

    stat_data = [[
        Paragraph(
            f"<b><font size='20' color='#{c.hexval()[2:]}'>{counts[sev]}</font></b><br/>"
            f"<font size='8' color='#8B949E'>{sev}</font>",
            ParagraphStyle("stat", fontName="Helvetica", alignment=TA_CENTER)
        )
        for sev, c in [("CRITICAL", SEV_COLORS["CRITICAL"]),
                       ("HIGH",     SEV_COLORS["HIGH"]),
                       ("MEDIUM",   SEV_COLORS["MEDIUM"]),
                       ("LOW",      SEV_COLORS["LOW"]),
                       ("INFO",     SEV_COLORS["INFO"])]
    ]]
    stat_table = Table(stat_data, colWidths=[w / 5] * 5)
    stat_table.setStyle(TableStyle([
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#161B22")),
    ]))
    story.append(stat_table)

    return story


# ── RESUMEN EJECUTIVO ─────────────────────────────────────────
def _build_executive_summary(results, styles, w):
    story = []
    findings = results.get("findings", [])
    counts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1

    story.append(Paragraph("1. Resumen Ejecutivo", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    # Texto resumen
    total = len(findings)
    critical_high = counts["CRITICAL"] + counts["HIGH"]

    risk_level = "CRÍTICO" if counts["CRITICAL"] > 0 else \
                 "ALTO"     if counts["HIGH"] > 2    else \
                 "MEDIO"    if counts["MEDIUM"] > 5   else "BAJO"

    story.append(Paragraph(
        f"El análisis de seguridad realizado sobre el objetivo <b>{results['target']}</b> "
        f"con metodología <b>{results.get('scope','blackbox').upper()}</b> ha identificado un total de "
        f"<b>{total} hallazgos de seguridad</b>, de los cuales <b>{critical_high}</b> son de severidad "
        f"alta o crítica. El nivel de riesgo global estimado es <b>{risk_level}</b>.",
        styles["body"]
    ))

    story.append(Spacer(1, 0.3 * cm))

    duration = results.get("duration")
    if duration:
        story.append(Paragraph(
            f"El análisis fue realizado el <b>{results['start_time'].strftime('%d/%m/%Y a las %H:%M:%S')}</b> "
            f"y tuvo una duración de <b>{duration.seconds} segundos</b>.",
            styles["body"]
        ))

    story.append(Spacer(1, 0.5 * cm))

    # Tabla de resumen por severidad
    story.append(Paragraph("Distribución de hallazgos por severidad:", styles["h2"]))

    header = [
        Paragraph("<b>Severidad</b>", styles["body"]),
        Paragraph("<b>Cantidad</b>", styles["body"]),
        Paragraph("<b>Impacto</b>", styles["body"]),
        Paragraph("<b>Acción recomendada</b>", styles["body"]),
    ]

    impact_map = {
        "CRITICAL": ("Compromiso total del sistema", "Remediar de inmediato (< 24h)"),
        "HIGH":     ("Compromiso parcial o escalación", "Remediar urgentemente (< 7 días)"),
        "MEDIUM":   ("Exposición de datos o degradación", "Planificar corrección (< 30 días)"),
        "LOW":      ("Riesgo limitado o teórico", "Corregir en próximo ciclo"),
        "INFO":     ("Sin impacto directo", "Revisar y documentar"),
    }

    rows = [header]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts[sev] == 0:
            continue
        impact, action = impact_map[sev]
        rows.append([
            Paragraph(sev, ParagraphStyle("sv", fontName="Helvetica-Bold", fontSize=9,
                                          textColor=SEV_COLORS[sev])),
            Paragraph(str(counts[sev]), styles["body"]),
            Paragraph(impact, styles["body_small"]),
            Paragraph(action, styles["body_small"]),
        ])

    t = Table(rows, colWidths=[w * 0.15, w * 0.1, w * 0.37, w * 0.38])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_PRIMARY),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0),  9),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t)

    # ── Warning NVD si hubo errores ───────────────────────────
    nvd_status = results.get("config_snapshot", {}).get("nvd_status") or ""
    # Buscamos en config pasado a través de results
    if not nvd_status:
        # fallback: mirar si hay 0 CVEs pero sí había productos
        if not results.get("cves") and results.get("enumeration", {}).get("technologies"):
            nvd_status = "possible_failure"

    if nvd_status in ("partial", "possible_failure"):
        story.append(Spacer(1, 0.4 * cm))
        warning_data = [[Paragraph(
            "⚠ <b>AVISO:</b> La correlación de CVEs no pudo completarse correctamente debido a "
            "errores o timeouts en la API de NVD/NIST. Los resultados de vulnerabilidades pueden "
            "estar <b>INCOMPLETOS</b>. Se recomienda repetir el análisis o consultar NVD manualmente "
            "para los productos detectados.",
            ParagraphStyle("nvd_warn", fontName="Helvetica", fontSize=9,
                           textColor=SEV_COLORS["HIGH"], leading=14)
        )]]
        warn_table = Table(warning_data, colWidths=[w])
        warn_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), HexColor("#FFF8F0")),
            ("LINEABOVE",     (0,0),(-1,0),  2, SEV_COLORS["HIGH"]),
            ("LINEBELOW",     (0,-1),(-1,-1),2, SEV_COLORS["HIGH"]),
            ("TOPPADDING",    (0,0),(-1,-1), 10),
            ("BOTTOMPADDING", (0,0),(-1,-1), 10),
            ("LEFTPADDING",   (0,0),(-1,-1), 12),
        ]))
        story.append(warn_table)

    return story


# ── ALCANCE Y METODOLOGÍA ─────────────────────────────────────
def _build_scope_section(results, styles, w):
    story = []
    story.append(Paragraph("2. Alcance y Metodología", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    ti = results.get("target_info", {})
    ips_str = ", ".join(ti.get("ips", [])) or "N/A"

    story.append(Paragraph("2.1 Definición del alcance", styles["h2"]))
    scope_data = [
        ["Target",          results["target"]],
        ["Tipo",            ti.get("type", "N/A").upper()],
        ["IPs resueltas",   ips_str],
        ["Modalidad",       results.get("scope", "blackbox").upper()],
        ["Fecha inicio",    results["start_time"].strftime("%Y-%m-%d %H:%M:%S")],
        ["Fecha fin",       results.get("end_time", results["start_time"]).strftime("%Y-%m-%d %H:%M:%S")],
        ["Duración",        f"{results.get('duration', 'N/A')}"],
    ]

    t = Table(scope_data, colWidths=[w * 0.3, w * 0.7])
    t.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_BG_LIGHT, colors.white]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(t)

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("2.2 Metodología", styles["h2"]))
    story.append(Paragraph(
        "El análisis se ha realizado siguiendo un enfoque estructurado por fases, "
        "partiendo de reconocimiento pasivo (OSINT) hasta análisis activo de protocolos "
        "y búsqueda de vulnerabilidades. Las fases ejecutadas son:",
        styles["body"]
    ))

    phases = [
        ["Fase 1 — OSINT",             "WHOIS, DNS, AXFR, certificados (crt.sh), ASN/BGP"],
        ["Fase 2 — Shodan",            "Servicios expuestos, puertos, banners, CVEs indexados"],
        ["Fase 3 — Leak-Lookup",       "Credenciales y emails filtrados en brechas conocidas"],
        ["Fase 4 — Enumeración",       "Subdominios, hosts activos, detección de tecnologías"],
        ["Fase 5 — SSL/TLS",           "Protocolos, cifrados, certificado, HSTS, vulnerabilidades"],
        ["Fase 6 — Cabeceras HTTP",    "Security headers, CSP, cookies, fugas de información"],
        ["Fase 7 — WAF/CDN",           "Detección de Cloudflare, AWS WAF/CloudFront y otros proveedores"],
        ["Fase 8 — CVEs",              "Búsqueda en NVD/NIST por productos y versiones detectadas"],
    ]

    t2 = Table(phases, colWidths=[w * 0.3, w * 0.7])
    t2.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_BG_LIGHT, colors.white]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(t2)

    return story


# ── HALLAZGOS ─────────────────────────────────────────────────
def _build_findings_section(results, styles, w):
    story = []
    story.append(Paragraph("3. Hallazgos de Seguridad", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    findings = results.get("findings", [])
    if not findings:
        story.append(Paragraph("No se encontraron hallazgos significativos.", styles["body"]))
        return story

    # Agrupar por severidad
    by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        by_sev.setdefault(sev, []).append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_findings = by_sev.get(sev, [])
        if not sev_findings:
            continue

        story.append(Paragraph(
            f"{sev} — {len(sev_findings)} hallazgo(s)",
            ParagraphStyle(f"sev_{sev}", fontName="Helvetica-Bold", fontSize=11,
                           textColor=SEV_COLORS[sev], spaceBefore=12, spaceAfter=4)
        ))
        story.append(ColorLine(w, SEV_COLORS[sev], 1))
        story.append(Spacer(1, 0.2 * cm))

        for idx, finding in enumerate(sev_findings, 1):
            block = _build_finding_card(finding, idx, sev, styles, w)
            story.append(KeepTogether(block))
            story.append(Spacer(1, 0.2 * cm))

    return story


def _build_finding_card(finding, idx, sev, styles, w):
    elements = []

    title_style = ParagraphStyle(
        "fc_title", fontName="Helvetica-Bold", fontSize=10,
        textColor=SEV_COLORS.get(sev, C_TEXT), spaceAfter=4,
    )

    phase = finding.get("phase", "")
    title = finding.get("title", "")
    desc  = finding.get("description", "")
    rem   = finding.get("remediation", "")
    cvss  = finding.get("cvss", 0.0)

    # Card con borde lateral de color
    content_rows = []
    content_rows.append([
        Paragraph(f"[{phase}] {title}", title_style)
    ])
    if desc:
        content_rows.append([
            Paragraph(f"<b>Descripción:</b> {desc}", styles["finding_body"])
        ])
    if cvss:
        content_rows.append([
            Paragraph(f"<b>CVSS Score:</b> {cvss}", styles["body_small"])
        ])
    if rem:
        content_rows.append([
            Paragraph(f"<b>Mitigación:</b> {rem}", styles["remediation"])
        ])

    inner = Table(content_rows, colWidths=[w - 1.2 * cm])
    inner.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), SEV_BG.get(sev, C_BG_LIGHT)),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (0, 0),   8),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
        ("TOPPADDING",    (0, 1), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -2), 2),
    ]))

    # Borde lateral de color
    badge_col = Table(
        [[""]],
        colWidths=[0.4 * cm],
        rowHeights=[None]
    )
    badge_col.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEV_COLORS.get(sev, C_MUTED)),
    ]))

    outer = Table([[badge_col, inner]], colWidths=[0.4 * cm, w - 0.4 * cm])
    outer.setStyle(TableStyle([
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))

    elements.append(outer)
    return elements


# ── SSL/TLS ───────────────────────────────────────────────────
def _build_ssl_section(results, styles, w):
    story = []
    ssl   = results.get("ssl_tls", {})

    story.append(Paragraph("4. Análisis SSL/TLS", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    if not ssl:
        story.append(Paragraph("Análisis SSL/TLS no ejecutado.", styles["body"]))
        return story

    # Certificado
    cert = ssl.get("certificate", {})
    if cert:
        story.append(Paragraph("4.1 Certificado X.509", styles["h2"]))
        cert_rows = [
            ["CN (Subject)",    cert.get("subject_cn", "N/A")],
            ["Emisor (CA)",     cert.get("issuer_cn", "N/A")],
            ["Válido desde",    cert.get("not_before", "N/A")],
            ["Válido hasta",    cert.get("not_after", "N/A")],
            ["Días restantes",  str(cert.get("days_remaining", "N/A"))],
            ["Algoritmo firma", cert.get("signature_algo", "N/A")],
            ["Tamaño de clave", f"{cert.get('key_size', 'N/A')} bits"],
            ["Autofirmado",     "Sí" if cert.get("self_signed") else "No"],
            ["SHA-256",         cert.get("fingerprint_sha256", "N/A")[:48] + "..."],
        ]

        t = Table(cert_rows, colWidths=[w * 0.3, w * 0.7])
        t.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_BG_LIGHT, colors.white]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

    # Protocolos
    protocols = ssl.get("protocols", {})
    if protocols:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("4.2 Protocolos", styles["h2"]))

        proto_data = [[
            Paragraph("<b>Protocolo</b>", styles["body"]),
            Paragraph("<b>Estado</b>", styles["body"]),
            Paragraph("<b>Seguridad</b>", styles["body"]),
        ]]

        proto_sec = {
            "SSLv2": ("INSEGURO", SEV_COLORS["CRITICAL"]),
            "SSLv3": ("INSEGURO", SEV_COLORS["CRITICAL"]),
            "TLSv1": ("OBSOLETO", SEV_COLORS["HIGH"]),
            "TLSv1.1": ("OBSOLETO", SEV_COLORS["HIGH"]),
            "TLSv1.2": ("ACEPTABLE", SEV_COLORS["LOW"]),
            "TLSv1.3": ("RECOMENDADO", HexColor("#1A7F37")),
        }

        for proto, enabled in protocols.items():
            label, color = proto_sec.get(proto, ("DESCONOCIDO", C_MUTED))
            status = "✓ Habilitado" if enabled else "✗ Deshabilitado"
            status_color = SEV_COLORS["CRITICAL"] if enabled and proto in ("SSLv2","SSLv3","TLSv1","TLSv1.1") else (HexColor("#1A7F37") if enabled else C_MUTED)
            proto_data.append([
                Paragraph(proto, styles["body"]),
                Paragraph(f"<font color='#{status_color.hexval()[2:]}'>{status}</font>", styles["body"]),
                Paragraph(f"<font color='#{color.hexval()[2:]}'>{label}</font>", styles["body"]),
            ])

        t2 = Table(proto_data, colWidths=[w * 0.25, w * 0.35, w * 0.4])
        t2.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(t2)

    # HSTS
    hsts = ssl.get("hsts_details", {})
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph("4.3 HSTS (HTTP Strict Transport Security)", styles["h2"]))

    hsts_rows = [
        ["Habilitado",         "Sí" if ssl.get("hsts") else "No"],
        ["max-age",            str(ssl.get("hsts_max_age", 0)) + " segundos"],
        ["includeSubDomains",  "Sí" if hsts.get("include_subdomains") else "No"],
        ["preload",            "Sí" if hsts.get("preload") else "No"],
        ["Cabecera completa",  hsts.get("raw", "N/A") or "N/A"],
    ]
    t3 = Table(hsts_rows, colWidths=[w * 0.3, w * 0.7])
    t3.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1,-1), 8),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_BG_LIGHT, colors.white]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    story.append(t3)

    return story


# ── CABECERAS HTTP ────────────────────────────────────────────
def _build_headers_section(results, styles, w):
    story = []
    headers_data = results.get("headers", {})

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("5. Cabeceras HTTP de Seguridad", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    if not headers_data:
        story.append(Paragraph("Análisis de cabeceras no ejecutado.", styles["body"]))
        return story

    present  = headers_data.get("headers_present", {})
    missing  = headers_data.get("headers_missing", [])
    leaks    = headers_data.get("info_leaks", {})
    cookies  = headers_data.get("cookies", [])

    # Tabla de cabeceras
    rows = [[
        Paragraph("<b>Cabecera</b>", styles["body"]),
        Paragraph("<b>Estado</b>",   styles["body"]),
        Paragraph("<b>Valor / Nota</b>", styles["body"]),
    ]]

    all_headers = list(present.keys()) + missing
    for h in all_headers:
        if h in present:
            val = present[h][:70] + "..." if len(present[h]) > 70 else present[h]
            rows.append([
                Paragraph(h, styles["body_small"]),
                Paragraph("<font color='#1A7F37'>✓ Presente</font>", styles["body_small"]),
                Paragraph(val, styles["body_small"]),
            ])
        else:
            rows.append([
                Paragraph(h, styles["body_small"]),
                Paragraph("<font color='#DA3633'>✗ Ausente</font>", styles["body_small"]),
                Paragraph("—", styles["body_small"]),
            ])

    t = Table(rows, colWidths=[w * 0.38, w * 0.17, w * 0.45])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # Fugas de info
    if leaks:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("5.1 Fugas de información en cabeceras", styles["h2"]))
        leak_rows = [[Paragraph("<b>Cabecera</b>", styles["body"]), Paragraph("<b>Valor expuesto</b>", styles["body"])]]
        for h, v in leaks.items():
            leak_rows.append([Paragraph(h, styles["body_small"]), Paragraph(v[:80], styles["body_small"])])
        t2 = Table(leak_rows, colWidths=[w * 0.3, w * 0.7])
        t2.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(t2)

    return story


# ── OSINT ─────────────────────────────────────────────────────
def _build_waf_section(results, styles, w):
    story = []
    waf   = results.get("waf_cdn", {})

    story.append(Paragraph("6. Detección WAF/CDN", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    detected = waf.get("detected", [])

    if not detected:
        story.append(Paragraph(
            "No se detectó ningún WAF o CDN conocido delante del servidor de origen.",
            styles["body"]
        ))
    else:
        providers_str = ", ".join(d["provider"] for d in detected)
        story.append(Paragraph(
            f"Se ha identificado la presencia de <b>{providers_str}</b> "
            f"intermediando el tráfico hacia el servidor de origen.",
            styles["body"]
        ))
        story.append(Spacer(1, 0.3 * cm))

        # Tabla de proveedores detectados
        rows = [[
            Paragraph("<b>Proveedor</b>",    styles["body"]),
            Paragraph("<b>Tipo</b>",         styles["body"]),
            Paragraph("<b>Confianza</b>",    styles["body"]),
            Paragraph("<b>Detectado por</b>",styles["body"]),
        ]]
        for d in detected:
            rows.append([
                Paragraph(d.get("provider",""),  styles["body_small"]),
                Paragraph(d.get("type",""),      styles["body_small"]),
                Paragraph(d.get("confidence",""),styles["body_small"]),
                Paragraph(", ".join(d.get("matched_by",[]))[:80], styles["body_small"]),
            ])

        t = Table(rows, colWidths=[w*0.25, w*0.15, w*0.15, w*0.45])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0),  C_PRIMARY),
            ("TEXTCOLOR",     (0,0),(-1,0),  colors.white),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, C_BG_LIGHT]),
            ("GRID",          (0,0),(-1,-1), 0.5, C_BORDER),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ]))
        story.append(t)

    # IP provider
    ip_prov = waf.get("ip_provider", {})
    if ip_prov.get("provider"):
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("6.1 Rango IP", styles["h2"]))
        ip_rows = [
            ["Proveedor",    ip_prov.get("provider","N/A")],
            ["IP detectada", ip_prov.get("matched_ip","N/A")],
            ["Rango CIDR",   ip_prov.get("matched_range","N/A")],
        ]
        t2 = Table(ip_rows, colWidths=[w*0.3, w*0.7])
        t2.setStyle(TableStyle([
            ("FONTNAME",      (0,0),(0,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1),8),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_BG_LIGHT, colors.white]),
            ("GRID",          (0,0),(-1,-1),0.5, C_BORDER),
            ("TOPPADDING",    (0,0),(-1,-1),5),
            ("BOTTOMPADDING", (0,0),(-1,-1),5),
            ("LEFTPADDING",   (0,0),(-1,-1),8),
        ]))
        story.append(t2)

    # DNS hints
    dns = waf.get("dns_hints", {})
    if dns.get("cname_provider"):
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("6.2 CNAME hacia CDN", styles["h2"]))
        story.append(Paragraph(
            f"El registro CNAME apunta a <b>{dns.get('cname_value','N/A')}</b> "
            f"({dns.get('cname_provider','N/A')}).",
            styles["body"]
        ))

    # Block test
    block = waf.get("block_test", {})
    if block.get("waf_detected"):
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("6.3 Comportamiento de bloqueo WAF", styles["h2"]))
        story.append(Paragraph(
            f"El servidor respondió con comportamiento de WAF ante rutas de prueba. "
            f"Proveedor identificado: <b>{block.get('provider','WAF genérico')}</b> "
            f"(HTTP {block.get('status_code','N/A')}).",
            styles["body"]
        ))

    return story


def _build_osint_section(results, styles, w):
    story = []
    osint = results.get("osint", {})
    enum  = results.get("enumeration", {})

    story.append(Paragraph("7. OSINT & Reconocimiento", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    # WHOIS
    whois_data = osint.get("whois", {})
    if whois_data:
        story.append(Paragraph("7.1 WHOIS", styles["h2"]))
        whois_rows = [
            ["Registrador",     whois_data.get("registrar", "N/A")],
            ["Organización",    whois_data.get("org", "N/A")],
            ["País",            whois_data.get("country", "N/A")],
            ["Creación",        str(whois_data.get("creation_date", "N/A"))[:30]],
            ["Expiración",      str(whois_data.get("expiration_date", "N/A"))[:30]],
            ["Name Servers",    ", ".join(whois_data.get("name_servers", []))[:80]],
            ["Emails WHOIS",    ", ".join(whois_data.get("emails", []))[:80] or "N/A"],
        ]
        t = Table(whois_rows, colWidths=[w * 0.25, w * 0.75])
        t.setStyle(TableStyle([
            ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_BG_LIGHT, colors.white]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

    # DNS Records
    dns_records = osint.get("dns_records", {})
    if dns_records:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("7.2 Registros DNS", styles["h2"]))
        dns_rows = [[Paragraph("<b>Tipo</b>", styles["body"]), Paragraph("<b>Valor</b>", styles["body"])]]
        for rtype, values in dns_records.items():
            for i, v in enumerate(values):
                dns_rows.append([
                    Paragraph(rtype if i == 0 else "", styles["body_small"]),
                    Paragraph(v[:100], styles["body_small"]),
                ])
        t2 = Table(dns_rows, colWidths=[w * 0.1, w * 0.9])
        t2.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        story.append(t2)

    # Subdominios
    subdomains = enum.get("subdomains", [])
    if subdomains:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(f"7.3 Subdominios ({len(subdomains)} encontrados)", styles["h2"]))
        sub_rows = [[
            Paragraph("<b>FQDN</b>",  styles["body"]),
            Paragraph("<b>IPs</b>",   styles["body"]),
        ]]
        for sub in subdomains[:30]:
            sub_rows.append([
                Paragraph(sub.get("fqdn", ""), styles["body_small"]),
                Paragraph(", ".join(sub.get("ips", [])), styles["body_small"]),
            ])
        if len(subdomains) > 30:
            sub_rows.append([Paragraph(f"... y {len(subdomains)-30} más", styles["body_small"]), Paragraph("", styles["body_small"])])

        t3 = Table(sub_rows, colWidths=[w * 0.6, w * 0.4])
        t3.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
            ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        story.append(t3)

    return story


# ── CVEs ──────────────────────────────────────────────────────
def _build_cves_section(results, styles, w):
    story = []
    cves  = results.get("cves", [])

    story.append(Paragraph("8. CVEs Identificados", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        f"Se han identificado {len(cves)} CVE(s) asociados a los productos y versiones detectados "
        f"durante el análisis, consultados contra la base de datos NVD/NIST.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.3 * cm))

    rows = [[
        Paragraph("<b>CVE ID</b>",    styles["body"]),
        Paragraph("<b>Producto</b>",  styles["body"]),
        Paragraph("<b>CVSS</b>",      styles["body"]),
        Paragraph("<b>Severidad</b>", styles["body"]),
        Paragraph("<b>Publicado</b>", styles["body"]),
    ]]

    for cve in cves[:50]:
        sev   = cve.get("severity", "NONE")
        score = cve.get("cvss_score", 0.0)
        c     = SEV_COLORS.get(sev, C_MUTED)
        rows.append([
            Paragraph(cve.get("id", ""), styles["body_small"]),
            Paragraph(cve.get("product", "")[:20], styles["body_small"]),
            Paragraph(str(score), styles["body_small"]),
            Paragraph(f"<font color='#{c.hexval()[2:]}'>{sev}</font>", styles["body_small"]),
            Paragraph(cve.get("published", ""), styles["body_small"]),
        ])

    t = Table(rows, colWidths=[w*0.22, w*0.22, w*0.1, w*0.18, w*0.18])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    # Detalle de CVEs críticos/altos
    critical_cves = [c for c in cves if c.get("severity") in ("CRITICAL", "HIGH")]
    if critical_cves:
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph("Detalle de CVEs Críticos/Altos:", styles["h2"]))
        for cve in critical_cves[:10]:
            sev = cve.get("severity", "HIGH")
            story.append(KeepTogether([
                Paragraph(
                    f"<b>{cve.get('id')}</b> — CVSS {cve.get('cvss_score')} "
                    f"(<font color='#{SEV_COLORS[sev].hexval()[2:]}'>{sev}</font>)",
                    styles["h3"]
                ),
                Paragraph(cve.get("description", "")[:400], styles["body_small"]),
                Paragraph(f"<i>Mitigación: {cve.get('remediation','')}</i>", styles["remediation"]),
                Spacer(1, 0.2 * cm),
            ]))

    return story


# ── TABLA CVSS CONSOLIDADA ────────────────────────────────────
def _build_cvss_table(results, styles, w):
    story = []
    story.append(Paragraph("9. Tabla CVSS Consolidada", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        "La siguiente tabla consolida todos los hallazgos con una puntuación CVSS asignada, "
        "ordenados por severidad descendente.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.3 * cm))

    findings = [f for f in results.get("findings", []) if f.get("cvss", 0) > 0]
    findings.sort(key=lambda x: x.get("cvss", 0), reverse=True)

    rows = [[
        Paragraph("<b>#</b>",          styles["body"]),
        Paragraph("<b>Hallazgo</b>",   styles["body"]),
        Paragraph("<b>Fase</b>",       styles["body"]),
        Paragraph("<b>CVSS</b>",       styles["body"]),
        Paragraph("<b>Severidad</b>",  styles["body"]),
    ]]

    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "INFO")
        c   = SEV_COLORS.get(sev, C_MUTED)
        rows.append([
            Paragraph(str(i), styles["body_small"]),
            Paragraph(f.get("title", "")[:60], styles["body_small"]),
            Paragraph(f.get("phase", ""), styles["body_small"]),
            Paragraph(str(f.get("cvss", 0.0)), styles["body_small"]),
            Paragraph(f"<font color='#{c.hexval()[2:]}'>{sev}</font>", styles["body_small"]),
        ])

    t = Table(rows, colWidths=[w*0.05, w*0.47, w*0.16, w*0.1, w*0.17])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    return story


# ── MITIGACIONES ──────────────────────────────────────────────
def _build_mitigations_section(results, styles, w):
    story = []
    story.append(Paragraph("10. Propuestas de Mitigación", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        "A continuación se detallan las acciones de mitigación recomendadas, "
        "priorizadas por severidad e impacto potencial.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.3 * cm))

    findings = results.get("findings", [])
    findings_sorted = sorted(findings, key=lambda x: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
            x.get("severity", "INFO"), 5)
    ))

    # Deduplicar por título de remediación
    seen_rems = set()
    priority_map = {
        "CRITICAL": ("Inmediata", "< 24 horas",   SEV_COLORS["CRITICAL"]),
        "HIGH":     ("Urgente",   "< 7 días",      SEV_COLORS["HIGH"]),
        "MEDIUM":   ("Planificada","< 30 días",    SEV_COLORS["MEDIUM"]),
        "LOW":      ("Normal",    "Próximo sprint", SEV_COLORS["LOW"]),
        "INFO":     ("Opcional",  "Sin urgencia",   SEV_COLORS["INFO"]),
    }

    rows = [[
        Paragraph("<b>Prioridad</b>",   styles["body"]),
        Paragraph("<b>Hallazgo</b>",    styles["body"]),
        Paragraph("<b>Acción</b>",      styles["body"]),
        Paragraph("<b>Plazo</b>",       styles["body"]),
    ]]

    for f in findings_sorted:
        rem = f.get("remediation", "")
        if not rem or rem in seen_rems:
            continue
        seen_rems.add(rem)

        sev = f.get("severity", "INFO")
        prio_label, plazo, color = priority_map.get(sev, ("Normal", "—", C_MUTED))

        rows.append([
            Paragraph(
                f"<font color='#{color.hexval()[2:]}'><b>{prio_label}</b></font>",
                styles["body_small"]
            ),
            Paragraph(f.get("title", "")[:50], styles["body_small"]),
            Paragraph(rem[:120], styles["body_small"]),
            Paragraph(plazo, styles["body_small"]),
        ])

    t = Table(rows, colWidths=[w*0.13, w*0.3, w*0.42, w*0.15])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_PRIMARY),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)

    # Nota final
    story.append(Spacer(1, 1 * cm))
    story.append(ColorLine(w, C_BORDER, 0.5))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        f"<i>Informe generado por recon-cli {RECON_CLI_VERSION} el "
        f"{results['start_time'].strftime('%d/%m/%Y a las %H:%M:%S')}. "
        f"Este documento es confidencial y está destinado exclusivamente al equipo de seguridad autorizado.</i>",
        styles["body_small"]
    ))

    return story
