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
    PageBreak, HRFlowable, KeepTogether, CondPageBreak
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor

from version import __version__ as RECON_CLI_VERSION

# ── Paleta de colores ─────────────────────────────────────────
C_PRIMARY    = HexColor("#0D1117")   # Negro profundo
C_ACCENT     = HexColor("#00D4AA")   # Verde ciberseguridad
C_ACCENT2    = HexColor("#1F6FEB")   # Azul
C_BG_LIGHT   = HexColor("#F6F8FA")   # Gris muy claro
C_BORDER     = HexColor("#30363D")   # Gris oscuro
C_TEXT       = HexColor("#24292F")   # Texto principal
C_MUTED      = HexColor("#57606A")   # Texto secundario
C_TABLE_HEAD = HexColor("#E1E4E8")   # Gris suave para cabeceras de tabla
C_TABLE_TEXT = HexColor("#1B1F23")   # Texto oscuro sobre cabecera gris

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

    # ── ÍNDICE ────────────────────────────────────────────────
    story.append(PageBreak())
    story += _build_index(results, styles, content_width)

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
    story.append(PageBreak())
    story += _build_headers_section(results, styles, content_width)

    # ── WAF/CDN ───────────────────────────────────────────────
    story.append(PageBreak())
    story += _build_waf_section(results, styles, content_width)

    # ── OSINT & RECONOCIMIENTO ────────────────────────────────
    story.append(PageBreak())
    story += _build_osint_section(results, styles, content_width)

    # ── CVEs ────────────────────────────────────────────────────
    story.append(PageBreak())
    story += _build_cves_section(results, styles, content_width)

    # Contador dinámico de secciones — las 8 fijas ya ocupan 1-8
    sec_num = 9  # próxima sección condicional

    # ── TABLA CVSS CONSOLIDADA ────────────────────────────────
    cvss_findings = [f for f in results.get("findings", []) if f.get("cvss", 0) > 0]
    if cvss_findings:
        story.append(PageBreak())
        story += _build_cvss_table(results, styles, content_width, sec_num)
        sec_num += 1

    # ── OPORTUNIDADES DE MEJORA (dominio raíz) ───────────────
    if results.get("root_domain_findings"):
        story.append(PageBreak())
        story += _build_improvement_section(results, styles, content_width, sec_num)
        sec_num += 1

    # ── GREYBOX ───────────────────────────────────────────────
    if results.get("scope") == "greybox" and results.get("greybox"):
        story.append(PageBreak())
        story += _build_greybox_section(results, styles, content_width, sec_num)
        sec_num += 1

    # ── MITRE ATT&amp;CK ──────────────────────────────────────────
    if results.get("mitre_techniques"):
        story.append(PageBreak())
        story += _build_mitre_section(results, styles, content_width, sec_num)
        sec_num += 1

    # ── PROPUESTAS DE MITIGACIÓN ──────────────────────────────
    story.append(PageBreak())
    story += _build_mitigations_section(results, styles, content_width, sec_num)
    sec_num += 1

    # ── METADATOS DE EJECUCIÓN ────────────────────────────────
    story.append(CondPageBreak(8 * cm))
    story += _build_execution_metadata(results, styles, content_width, sec_num)

    # Construir PDF
    doc.build(story, canvasmaker=PageNumCanvas)


# ── ÍNDICE ────────────────────────────────────────────────────
def _build_index(results, styles, w):
    story = []
    scope    = results.get("scope", "blackbox")
    is_grey  = scope == "greybox"
    findings = results.get("findings", [])
    has_cvss = any(f.get("cvss", 0) > 0 for f in findings)
    has_root = bool(results.get("root_domain_findings"))
    has_mitre= bool(results.get("mitre_techniques"))
    has_cves = bool(results.get("cves"))
    has_grey = is_grey and bool(results.get("greybox"))

    story.append(Paragraph("Índice", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.4 * cm))

    # Estilos de celda
    num_st  = ParagraphStyle("idx_num",  fontName="Helvetica-Bold", fontSize=9,
                              textColor=C_ACCENT, alignment=TA_CENTER)
    tit_st  = ParagraphStyle("idx_tit",  fontName="Helvetica-Bold", fontSize=9,
                              textColor=C_TEXT)
    desc_st = ParagraphStyle("idx_desc", fontName="Helvetica",      fontSize=8,
                              textColor=C_MUTED, leading=12)
    cond_st = ParagraphStyle("idx_cond", fontName="Helvetica-Oblique", fontSize=7,
                              textColor=C_MUTED)

    def row(num, title, description, condition="", color=C_TEXT, bg=colors.white):
        num_style = ParagraphStyle("iN", fontName="Helvetica-Bold", fontSize=9,
                                   textColor=color, alignment=TA_CENTER)
        tit_style = ParagraphStyle("iT", fontName="Helvetica-Bold", fontSize=9,
                                   textColor=color)
        return [
            Paragraph(str(num), num_style),
            Paragraph(title, tit_style),
            Paragraph(description, desc_st) if description else Paragraph("", desc_st),
            Paragraph(f"▸ {condition}" if condition else "", cond_st),
        ]

    # Cabecera
    hdr_st = ParagraphStyle("idx_hdr", fontName="Helvetica-Bold", fontSize=8,
                             textColor=C_TABLE_TEXT)
    header = [
        Paragraph("#",           hdr_st),
        Paragraph("Sección",     hdr_st),
        Paragraph("Descripción", hdr_st),
        Paragraph("Condición",   hdr_st),
    ]

    # Definir secciones dinámicamente
    n = [0]
    def next_n(): n[0] += 1; return n[0]

    sections = []
    sections.append(row(next_n(), "Resumen Ejecutivo",
        "KPIs de severidad, riesgo global, técnicas MITRE y artefactos generados"))
    sections.append(row(next_n(), "Alcance y Metodología",
        "Target, IPs, modalidad, fases ejecutadas y duración"))
    sections.append(row(next_n(), "Hallazgos de Seguridad",
        "Hallazgos clasificados por severidad con CVSS y correlación MITRE"))
    sections.append(row(next_n(), "Análisis SSL/TLS",
        "Certificado X.509, protocolos, cifrados, HSTS — RSA / ECDSA / DSA"))
    sections.append(row(next_n(), "Cabeceras HTTP",
        "Security headers, CSP, cookies y fugas de información"))
    sections.append(row(next_n(), "Detección WAF/CDN",
        "Cloudflare, AWS, Azure, Akamai — posible bypass de origen"))
    sections.append(row(next_n(), "OSINT & Reconocimiento",
        "DNS, AXFR, crt.sh, ASN/BGP — scope endpoint vs dominio raíz"))
    sections.append(row(next_n(), "CVEs Identificados",
        "Correlación CVE/CVSS con NVD/NIST. Fallback CIRCL. Solo versión confirmada"))

    if has_cvss:
        sections.append(row(next_n(), "Tabla CVSS Consolidada",
            "Todos los hallazgos con CVSS > 0 ordenados por severidad",
            "Solo si hay hallazgos con CVSS"))
    if has_root:
        sections.append(row(next_n(), "Análisis del Dominio Raíz",
            "SPF, DMARC, WHOIS/ASN — fuera del scoring del endpoint analizado",
            "Solo si hay hallazgos de dominio raíz"))
    if has_grey:
        sections.append(row(next_n(), "Análisis Greybox",
            "Discovery de endpoints, auditoría de autenticación, IDORs, SSO/OAuth2",
            "Solo con --scope greybox", color=HexColor("#8250DF")))
    if has_mitre:
        sections.append(row(next_n(), "Correlación MITRE ATT&amp;CK",
            "Táctica + técnica + sub-técnica por cada hallazgo"))
    sections.append(row(next_n(), "Propuestas de Mitigación",
        "Acciones priorizadas por severidad con plazos recomendados"))
    sections.append(row(next_n(), "Metadatos de Ejecución",
        "Run ID, comando, target, inicio/fin, duración, versión y artefactos"))

    # Anchos de columna
    cw = [w*0.06, w*0.26, w*0.44, w*0.24]

    table_data = [header] + sections
    col_styles = [
        ("BACKGROUND",    (0, 0), (-1, 0),  C_TABLE_HEAD),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_TABLE_TEXT),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0),  8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 7),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 7),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("ALIGN",         (0, 0), (0, -1),  "CENTER"),
    ]

    # Destacar fila greybox si existe
    if has_grey:
        grey_idx = next(
            i+1 for i, s in enumerate(sections) if "Greybox" in s[1].text
        )
        col_styles.append(("BACKGROUND", (0, grey_idx), (-1, grey_idx), HexColor("#F5F0FF")))
        col_styles.append(("LINEABOVE",  (0, grey_idx), (-1, grey_idx), 1, HexColor("#8250DF")))

    t = Table(table_data, colWidths=cw)
    t.setStyle(TableStyle(col_styles))
    story.append(t)
    story.append(Spacer(1, 0.4 * cm))

    # Leyenda de artefactos
    art_title = Paragraph("Artefactos generados", styles["h2"])

    art_st_k = ParagraphStyle("art_k", fontName="Courier",      fontSize=8, textColor=C_ACCENT2)
    art_st_v = ParagraphStyle("art_v", fontName="Helvetica",    fontSize=8, textColor=C_MUTED, leading=12)

    artefacts = [
        ("[target]_[run_id].pdf",                 "Informe técnico completo"),
        ("[target]_[run_id].log",                 "Salida completa de consola — todas las fases"),
    ]
    if is_grey:
        artefacts += [
            ("[target]_[run_id]_api_discovery.json", "Endpoints descubiertos con fuentes y metadatos"),
            ("[target]_[run_id]_api_audit.json",     "Hallazgos de auditoría con evidencias"),
        ]

    art_data = [
        [Paragraph(k, art_st_k), Paragraph(v, art_st_v)]
        for k, v in artefacts
    ]
    at = Table(art_data, colWidths=[w*0.52, w*0.48])
    at.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_BG_LIGHT, colors.white]),
        ("GRID",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 8),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(KeepTogether([art_title, Spacer(1, 0.2 * cm), at]))

    return story


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

    # Target box: etiqueta "TARGET" arriba, endpoint completo debajo
    # Tamaño de fuente dinámico según longitud para evitar truncado/wrap forzado
    target_len = len(target)
    if target_len <= 30:
        target_fontsize = 18
    elif target_len <= 45:
        target_fontsize = 15
    elif target_len <= 60:
        target_fontsize = 12
    else:
        target_fontsize = 10

    label_style = ParagraphStyle(
        "target_label", fontName="Helvetica-Bold", fontSize=11,
        textColor=HexColor("#8B949E"), alignment=TA_CENTER,
        spaceAfter=4, tracking=2,
    )
    value_style = ParagraphStyle(
        "target_value", fontName="Courier-Bold", fontSize=target_fontsize,
        textColor=C_ACCENT, alignment=TA_CENTER, leading=target_fontsize + 4,
        wordWrap="CJK",  # permite partir el dominio si no cabe, sin desbordar
    )

    target_data = [
        [Paragraph("TARGET", label_style)],
        [Paragraph(target, value_style)],
    ]
    target_table = Table(target_data, colWidths=[w * 0.85])
    target_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), HexColor("#161B22")),
        ("LINEABOVE",     (0, 0), (-1, 0),  2, C_ACCENT),
        ("LINEBELOW",     (0, -1), (-1, -1), 2, C_ACCENT),
        ("TOPPADDING",    (0, 0), (0, 0),   14),
        ("BOTTOMPADDING", (0, 0), (0, 0),   2),
        ("TOPPADDING",    (0, 1), (0, 1),   2),
        ("BOTTOMPADDING", (0, 1), (0, 1),   14),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))

    # Centrar la tabla de target
    container = Table([[target_table]], colWidths=[w])
    container.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story.append(container)

    story.append(Spacer(1, 0.5 * cm))

    # Metadata grid
    meta_rows = [
        ["Tipo de análisis", scope],
        ["Fecha de análisis", start_time.strftime("%d/%m/%Y %H:%M:%S UTC")],
        ["Autor del informe", author],
        ["Clasificación", "CONFIDENCIAL"],
        ["Versión herramienta", RECON_CLI_VERSION],
    ]
    meta_style = ParagraphStyle("meta_k", fontName="Helvetica", fontSize=10, textColor=HexColor("#8B949E"))
    meta_val_s = ParagraphStyle("meta_v", fontName="Helvetica-Bold", fontSize=10, textColor=C_TEXT)

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

    story.append(Spacer(1, 1.5 * cm))
    story.append(ColorLine(w, C_ACCENT, 3))

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

    # ── KPIs visuales (movidos desde portada) ─────────────────
    stat_data = [[
        Paragraph(
            f"<b><font size=\'20\' color=\'#{c.hexval()[2:]}\'>{counts[sev]}</font></b><br/>"
            f"<font size=\'8\' color=\'#57606A\'>{sev}</font>",
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
        ("TOPPADDING",    (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
        ("BACKGROUND",    (0, 0), (-1, -1), C_BG_LIGHT),
        ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LINEAFTER",     (0, 0), (-2, -1), 0.5, C_BORDER),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 0.5 * cm))

    # Texto resumen
    total = len(findings)
    critical_high = counts["CRITICAL"] + counts["HIGH"]

    # Riesgo global = severidad más alta encontrada (sin ponderaciones)
    if counts["CRITICAL"] > 0:
        risk_level = "CRÍTICO"
    elif counts["HIGH"] > 0:
        risk_level = "ALTO"
    elif counts["MEDIUM"] > 0:
        risk_level = "MEDIO"
    elif counts["LOW"] > 0:
        risk_level = "BAJO"
    else:
        risk_level = "INFORMATIVO"

    story.append(Paragraph(
        f"El análisis de seguridad realizado sobre el objetivo <b>{results['target']}</b> "
        f"con metodología <b>{results.get('scope','blackbox').upper()}</b> ha identificado un total de "
        f"<b>{total} hallazgos de seguridad</b>, de los cuales <b>{critical_high}</b> son de severidad "
        f"alta o crítica. El nivel de riesgo global estimado es <b>{risk_level}</b>.",
        styles["body"]
    ))

    # Nota greybox si aplica
    if results.get("scope") == "greybox" and results.get("greybox"):
        greybox   = results["greybox"]
        discovery = greybox.get("discovery", {})
        n_ep      = len(discovery.get("endpoints", []))
        n_auth    = sum(1 for e in discovery.get("endpoints", []) if not e.get("intentionally_public") and e.get("auth_needed"))
        gb_finds  = len(greybox.get("findings", []))
        submode   = {1: "API audit", 2: "SSO audit", 3: "API audit + SSO audit"}.get(greybox.get("submode", 1), "API audit")
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph(
            f"El análisis greybox (<b>{submode}</b>) descubrió <b>{n_ep} endpoint(s)</b> "
            f"de los cuales <b>{n_auth}</b> requieren autenticación, "
            f"generando <b>{gb_finds} hallazgo(s) adicionales</b> incluidos en el total anterior.",
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

    # Nota de confianza — solo si algún hallazgo lleva el campo (checks
    # heurísticos de Greybox API/SSO). No es una escala de severidad:
    # indica cuánta verificación manual adicional requiere el hallazgo
    # antes de planificar su remediación. Deliberadamente no se mezcla
    # con el CVSS — son dimensiones distintas.
    low_confidence = sum(1 for f in findings if f.get("confidence") == "LOW")
    if low_confidence:
        verbo = "presenta" if low_confidence == 1 else "presentan"
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph(
            f"De los {total} hallazgos, <b>{low_confidence}</b> {verbo} un nivel de "
            f"confianza <b>bajo</b> — la evidencia recogida automáticamente es "
            f"indicativa pero no concluyente, y se recomienda verificación manual "
            f"antes de priorizar su remediación.",
            styles["body_small"]
        ))

    story.append(Spacer(1, 0.5 * cm))

    # Tabla de resumen por severidad
    sev_table_title = Paragraph("Distribución de hallazgos por severidad:", styles["h2"])

    header = [
        Paragraph("<b>Severidad</b>", styles["body"]),
        Paragraph("<b>#</b>", styles["body"]),
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

    t = Table(rows, colWidths=[w * 0.15, w * 0.07, w * 0.39, w * 0.39])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_TABLE_HEAD),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_TABLE_TEXT),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0),  9),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(KeepTogether([sev_table_title, t]))
    mitre_techniques = results.get("mitre_techniques", [])
    if mitre_techniques:
        story.append(Spacer(1, 0.5 * cm))
        mitre_table_title = Paragraph("Resumen de técnicas ATT&amp;CK identificadas:", styles["h2"])

        tactic_colors = {
            "TA0043": HexColor("#0D6634"),
            "TA0001": HexColor("#DA3633"),
            "TA0002": HexColor("#E36209"),
            "TA0006": HexColor("#8250DF"),
            "TA0007": HexColor("#1F6FEB"),
            "TA0008": HexColor("#E36209"),
            "TA0009": HexColor("#D29922"),
        }

        mitre_rows = [[
            Paragraph("<b>Táctica</b>",    styles["body"]),
            Paragraph("<b>Técnica</b>",    styles["body"]),
            Paragraph("<b>Sub-técnica</b>",styles["body"]),
        ]]
        for tech in mitre_techniques:
            tc = tactic_colors.get(tech["tactic_id"], C_MUTED)
            mitre_rows.append([
                Paragraph(
                    f"<font color='#{tc.hexval()[2:]}'><b>{tech['tactic_id']}</b></font> "
                    f"<font size='8'>{tech['tactic']}</font>",
                    styles["body_small"]
                ),
                Paragraph(
                    f"<b>{tech['technique_id']}</b> "
                    f"<font size='8'>{tech['technique']}</font>",
                    styles["body_small"]
                ),
                Paragraph(
                    f"<b>{tech['subtechnique_id']}</b> <font size='8'>{tech['subtechnique']}</font>"
                    if tech.get("subtechnique_id")
                    else "<font size='8' color='#57606A'>—</font>",
                    styles["body_small"]
                ),
            ])

        mt = Table(mitre_rows, colWidths=[w*0.3, w*0.35, w*0.35])
        mt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0),  C_TABLE_HEAD),
            ("TEXTCOLOR",     (0,0),(-1,0),  C_TABLE_TEXT),
            ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, C_BG_LIGHT]),
            ("GRID",          (0,0),(-1,-1), 0.5, C_BORDER),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("LEFTPADDING",   (0,0),(-1,-1), 8),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]))
        story.append(KeepTogether([mitre_table_title, mt]))
        story.append(Paragraph(
            f"<i>Detalle completo en sección 10. Correlación MITRE ATT&amp;CK.</i>",
            styles["body_small"]
        ))

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

    scope_title = Paragraph("2.1 Definición del alcance", styles["h2"])
    k_st = ParagraphStyle("scope_k", fontName="Helvetica-Bold", fontSize=9, textColor=C_TEXT)
    v_st = ParagraphStyle("scope_v", fontName="Helvetica",      fontSize=9, textColor=C_TEXT, leading=13)

    scope_data = [
        [Paragraph("Target",        k_st), Paragraph(results["target"],                                                              v_st)],
        [Paragraph("Tipo",          k_st), Paragraph(ti.get("type", "N/A").upper(),                                                  v_st)],
        [Paragraph("IPs resueltas", k_st), Paragraph(ips_str,                                                                        v_st)],
        [Paragraph("Modalidad",     k_st), Paragraph(results.get("scope", "blackbox").upper(),                                       v_st)],
        [Paragraph("Fecha inicio",  k_st), Paragraph(results["start_time"].strftime("%Y-%m-%d %H:%M:%S"),                            v_st)],
        [Paragraph("Fecha fin",     k_st), Paragraph(results.get("end_time", results["start_time"]).strftime("%Y-%m-%d %H:%M:%S"),   v_st)],
        [Paragraph("Duración",      k_st), Paragraph(str(results.get("duration", "N/A")),                                            v_st)],
    ]

    t = Table(scope_data, colWidths=[w * 0.3, w * 0.7])
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_BG_LIGHT, colors.white]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(KeepTogether([scope_title, t]))

    story.append(Spacer(1, 0.5 * cm))
    story.append(KeepTogether([
        Paragraph("2.2 Metodología", styles["h2"]),
        Paragraph(
            "El análisis se ha realizado siguiendo un enfoque estructurado por fases, "
            "partiendo de reconocimiento pasivo (OSINT) hasta análisis activo de protocolos "
            "y búsqueda de vulnerabilidades. Las fases ejecutadas son:",
            styles["body"]
        ),
    ]))

    fk_st = ParagraphStyle("fase_k", fontName="Helvetica-Bold", fontSize=9, textColor=C_TEXT)
    fv_st = ParagraphStyle("fase_v", fontName="Helvetica",      fontSize=9, textColor=C_TEXT, leading=13)

    phases_list = [
        ("Fase 1 — OSINT",          "WHOIS, DNS, AXFR, crt.sh, ASN/BGP. Separación automática endpoint vs. dominio raíz."),
        ("Fase 2 — Shodan",         "Servicios expuestos, puertos y banners indexados."),
        ("Fase 3 — Leak-Lookup",    "Credenciales y emails filtrados en brechas conocidas."),
        ("Fase 4 — Enumeración",    "Subdominios, hosts activos, fingerprinting de tecnologías y detección de versiones (nmap -sV)."),
        ("Fase 5 — SSL/TLS",        "Protocolos, cifrados, certificado X.509, HSTS y vulnerabilidades."),
        ("Fase 6 — Cabeceras HTTP", "Security headers, Content Security Policy, cookies y fugas de información."),
        ("Fase 7 — WAF/CDN",        "Detección pasiva de Cloudflare, AWS, Azure, Akamai y otros. Rangos IP estáticos y dinámicos."),
        ("Fase 8 — CVEs",           "Correlación CVE/CVSS con NVD/NIST (solo versión confirmada). Fallback automático a CIRCL Vulnerability-Lookup si NVD no está disponible."),
        ("Fase 9 — MITRE ATT&amp;CK",   "Correlación táctica + técnica + sub-técnica de MITRE ATT&amp;CK Enterprise. Sin API externa. Mappings conservadores."),
        ("Fase 10 — Dom. Raíz",     "Análisis WHOIS, ASN/BGP, SPF y DMARC del dominio raíz. Separado del scoring del endpoint analizado."),
    ]

    # Añadir fase greybox si el scope es greybox
    if results.get("scope") == "greybox":
        greybox      = results.get("greybox", {})
        submode      = greybox.get("submode", 1)
        submode_name = {1: "API audit", 2: "SSO audit", 3: "API audit + SSO audit"}.get(submode, "API audit")
        phases_list.append((
            "Fase 11 — Greybox",
            f"Análisis autenticado con credenciales — {submode_name}. "
            f"Discovery de endpoints (Postman / OpenAPI / Spider), verificación de autenticación, "
            f"detección de IDORs, exposición de información y auditoría OAuth2."
        ))

    phases_data = [
        [Paragraph(k, fk_st), Paragraph(v, fv_st)]
        for k, v in phases_list
    ]

    t2 = Table(phases_data, colWidths=[w * 0.3, w * 0.7])
    t2.setStyle(TableStyle([
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C_BG_LIGHT, colors.white]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
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

        sev_header = [
            Paragraph(
                f"{sev} — {len(sev_findings)} hallazgo(s)",
                ParagraphStyle(f"sev_{sev}", fontName="Helvetica-Bold", fontSize=11,
                               textColor=SEV_COLORS[sev], spaceBefore=12, spaceAfter=4)
            ),
            ColorLine(w, SEV_COLORS[sev], 1),
            Spacer(1, 0.2 * cm),
        ]

        first_block = _build_finding_card(sev_findings[0], 1, sev, styles, w)
        story.append(KeepTogether(sev_header + first_block))
        story.append(Spacer(1, 0.2 * cm))

        for idx, finding in enumerate(sev_findings[1:], 2):
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

    phase      = finding.get("phase", "")
    title      = finding.get("title", "")
    desc       = finding.get("description", "")
    rem        = finding.get("remediation", "")
    cvss       = finding.get("cvss", 0.0)
    confidence = finding.get("confidence")

    # Confianza: solo se muestra si el check la informa (checks heurísticos/
    # de comportamiento en Greybox API y SSO). Checks deterministas (cabecera
    # presente o no, certificado expirado, etc.) no la llevan — no aporta
    # nada distinguir "confianza" en un hecho binario.
    CONFIDENCE_LABEL = {"HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}
    CONFIDENCE_COLOR = {"HIGH": "#0D6634", "MEDIUM": "#9A6700", "LOW": "#57606A"}

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
        cvss_line = f"<b>CVSS Score:</b> {cvss}"
        if confidence in CONFIDENCE_LABEL:
            cvss_line += (
                f"&nbsp;&nbsp;·&nbsp;&nbsp;<b>Confianza:</b> "
                f"<font color='{CONFIDENCE_COLOR[confidence]}'>{CONFIDENCE_LABEL[confidence]}</font>"
            )
        content_rows.append([Paragraph(cvss_line, styles["body_small"])])
    elif confidence in CONFIDENCE_LABEL:
        # Findings sin CVSS (p.ej. INFO) que sí llevan confidence
        content_rows.append([
            Paragraph(
                f"<b>Confianza:</b> "
                f"<font color='{CONFIDENCE_COLOR[confidence]}'>{CONFIDENCE_LABEL[confidence]}</font>",
                styles["body_small"]
            )
        ])
    if rem:
        content_rows.append([
            Paragraph(f"<b>Mitigación:</b> {rem}", styles["remediation"])
        ])

    # Badge MITRE si existe
    mitre = finding.get("mitre")
    if mitre:
        sub = mitre.get("subtechnique_id")
        tech_ref = f"{sub} · {mitre['subtechnique']}" if sub else f"{mitre['technique_id']} · {mitre['technique']}"
        content_rows.append([
            Paragraph(
                f"<font color='#0D6634'>⚑ MITRE ATT&amp;CK</font> "
                f"<font color='#57606A'>{mitre['tactic']} ({mitre['tactic_id']}) → "
                f"{tech_ref}</font>",
                ParagraphStyle("mitre_badge", fontName="Helvetica", fontSize=8,
                               textColor=HexColor("#24292F"), leading=12)
            )
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
def _build_improvement_section(results, styles, w, sec_num=10):
    """
    Sección separada para hallazgos de dominio raíz (SPF, DMARC, WHOIS emails).
    No afectan al scoring CVSS del endpoint analizado.
    """
    story        = []
    findings     = results.get("root_domain_findings", [])
    target_info  = results.get("target_info", {})
    root_domain  = target_info.get("root_domain", "dominio raíz")

    story.append(Paragraph(f"{sec_num}. Análisis del Dominio Raíz", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        f"Los siguientes aspectos corresponden a la configuración del dominio raíz "
        f"<b>{root_domain}</b> y no al endpoint analizado directamente. "
        f"Se documentan como oportunidades de mejora dado que afectan a todos los "
        f"subdominios y servicios bajo ese dominio, pero <b>no forman parte del "
        f"scoring de seguridad del endpoint evaluado</b>.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.4 * cm))

    for finding in findings:
        title = finding.get("title", "")
        desc  = finding.get("description", "")
        rem   = finding.get("remediation", "")

        block = [
            Paragraph(f"<b>{title}</b>",
                ParagraphStyle("imp_title", fontName="Helvetica-Bold", fontSize=10,
                               textColor=C_ACCENT2, spaceAfter=3)),
        ]
        if desc:
            block.append(Paragraph(desc, styles["finding_body"]))
        if rem:
            block.append(Paragraph(f"<b>Recomendación:</b> {rem}", styles["remediation"]))
        block.append(Spacer(1, 0.15 * cm))

        inner = Table([[p] for p in block], colWidths=[w - 0.8 * cm])
        inner.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_BG_LIGHT),
            ("LEFTPADDING",   (0, 0), (-1, -1), 12),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 12),
            ("TOPPADDING",    (0, 0), (0, 0),   10),
            ("BOTTOMPADDING", (0, -1),(-1,-1),  10),
            ("TOPPADDING",    (0, 1), (-1, -1),  3),
            ("BOTTOMPADDING", (0, 0), (-1, -2),  2),
        ]))

        outer = Table([[inner]], colWidths=[w])
        outer.setStyle(TableStyle([
            ("LEFTPADDING",  (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING",   (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 0),
            ("LINEABOVE",    (0, 0), (-1, 0),  2, C_ACCENT2),
            ("BOX",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ]))
        story.append(outer)
        story.append(Spacer(1, 0.2 * cm))

    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        f"<i>Nota: estas observaciones se basan en el análisis DNS del dominio "
        f"{root_domain} durante el reconocimiento OSINT. Para una evaluación "
        f"completa de la seguridad del correo electrónico se recomienda un análisis "
        f"específico del dominio corporativo.</i>",
        styles["body_small"]
    ))

    return story



def _build_mitre_section(results, styles, w, sec_num=11):
    story      = []
    techniques = results.get("mitre_techniques", [])

    story.append(Paragraph(f"{sec_num}. Correlación MITRE ATT&amp;CK", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        "Los hallazgos identificados se correlacionan con las técnicas del framework "
        "<b>MITRE ATT&amp;CK Enterprise</b>, permitiendo contextualizar el riesgo desde "
        "la perspectiva del adversario y alinearlo con marcos de defensa.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.4 * cm))

    if not techniques:
        story.append(Paragraph("No se identificaron correlaciones MITRE para este análisis.", styles["body"]))
        return story

    # ── Tabla de técnicas únicas ──────────────────────────────
    rows = [[
        Paragraph("<b>Táctica</b>",       styles["body"]),
        Paragraph("<b>Técnica</b>",        styles["body"]),
        Paragraph("<b>Sub-técnica</b>",    styles["body"]),
        Paragraph("<b>Hallazgos</b>",      styles["body"]),
    ]]

    tactic_colors = {
        "TA0043": HexColor("#0D6634"),  # Reconnaissance   → verde oscuro
        "TA0001": HexColor("#DA3633"),  # Initial Access    → rojo
        "TA0002": HexColor("#E36209"),  # Execution         → naranja
        "TA0006": HexColor("#8250DF"),  # Credential Access → morado
        "TA0007": HexColor("#1F6FEB"),  # Discovery         → azul
        "TA0008": HexColor("#E36209"),  # Lateral Movement  → naranja
        "TA0009": HexColor("#D29922"),  # Collection        → amarillo
    }

    for tech in techniques:
        tcolor = tactic_colors.get(tech["tactic_id"], C_MUTED)

        tactic_str = (
            f"<font color='#{tcolor.hexval()[2:]}'><b>{tech['tactic_id']}</b></font><br/>"
            f"<font size='8'>{tech['tactic']}</font>"
        )
        technique_str = (
            f"<b>{tech['technique_id']}</b><br/>"
            f"<font size='8'>{tech['technique']}</font>"
        )
        if tech.get("subtechnique_id"):
            sub_str = (
                f"<b>{tech['subtechnique_id']}</b><br/>"
                f"<font size='8'>{tech['subtechnique']}</font>"
            )
        else:
            sub_str = "<font size='8' color='#57606A'>—</font>"

        findings_list = tech.get("findings", [])
        findings_str  = "<br/>".join(
            f"<font size='7'>· {f[:55]}{'…' if len(f) > 55 else ''}</font>"
            for f in findings_list[:4]
        )
        if len(findings_list) > 4:
            findings_str += f"<br/><font size='7' color='#57606A'>(+{len(findings_list)-4} más)</font>"

        rows.append([
            Paragraph(tactic_str,    styles["body_small"]),
            Paragraph(technique_str, styles["body_small"]),
            Paragraph(sub_str,       styles["body_small"]),
            Paragraph(findings_str,  styles["body_small"]),
        ])

    t = Table(rows, colWidths=[w*0.18, w*0.22, w*0.22, w*0.38])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_TABLE_HEAD),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_TABLE_TEXT),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)

    # ── Nota de enlace ────────────────────────────────────────
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
        "<i>Referencia: https://attack.mitre.org/ — MITRE ATT&amp;CK® es una marca registrada de The MITRE Corporation.</i>",
        styles["body_small"]
    ))

    return story



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
        cert_title = Paragraph("4.1 Certificado X.509", styles["h2"])
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
        story.append(KeepTogether([cert_title, t]))
    protocols = ssl.get("protocols", {})
    if protocols:
        story.append(Spacer(1, 0.3 * cm))
        proto_title = Paragraph("4.2 Protocolos", styles["h2"])

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
            ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HEAD),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_TABLE_TEXT),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(KeepTogether([proto_title, t2]))

    # HSTS
    hsts = ssl.get("hsts_details", {})
    story.append(Spacer(1, 0.3 * cm))
    hsts_title = Paragraph("4.3 HSTS (HTTP Strict Transport Security)", styles["h2"])

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
    story.append(KeepTogether([hsts_title, t3]))

    return story


# ── CABECERAS HTTP ────────────────────────────────────────────
def _build_headers_section(results, styles, w):
    story = []
    headers_data = results.get("headers", {})

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
        ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HEAD),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_TABLE_TEXT),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
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
        leaks_title = Paragraph("5.1 Fugas de información en cabeceras", styles["h2"])
        leak_rows = [[Paragraph("<b>Cabecera</b>", styles["body"]), Paragraph("<b>Valor expuesto</b>", styles["body"])]]
        for h, v in leaks.items():
            leak_rows.append([Paragraph(h, styles["body_small"]), Paragraph(v[:80], styles["body_small"])])
        t2 = Table(leak_rows, colWidths=[w * 0.3, w * 0.7])
        t2.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HEAD),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_TABLE_TEXT),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ]))
        story.append(KeepTogether([leaks_title, t2]))

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
            ("BACKGROUND",    (0,0),(-1,0),  C_TABLE_HEAD),
            ("TEXTCOLOR",     (0,0),(-1,0),  C_TABLE_TEXT),
            ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
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
        ip_title = Paragraph("6.1 Rango IP", styles["h2"])
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
        story.append(KeepTogether([ip_title, t2]))

    # DNS hints
    dns = waf.get("dns_hints", {})
    if dns.get("cname_provider"):
        story.append(Spacer(1, 0.3 * cm))
        story.append(KeepTogether([
            Paragraph("6.2 CNAME hacia CDN", styles["h2"]),
            Paragraph(
                f"El registro CNAME apunta a <b>{dns.get('cname_value','N/A')}</b> "
                f"({dns.get('cname_provider','N/A')}).",
                styles["body"]
            ),
        ]))

    # Block test
    block = waf.get("block_test", {})
    if block.get("waf_detected"):
        story.append(Spacer(1, 0.3 * cm))
        story.append(KeepTogether([
            Paragraph("6.3 Comportamiento de bloqueo WAF", styles["h2"]),
            Paragraph(
                f"El servidor respondió con comportamiento de WAF ante rutas de prueba. "
                f"Proveedor identificado: <b>{block.get('provider','WAF genérico')}</b> "
                f"(HTTP {block.get('status_code','N/A')}).",
                styles["body"]
            ),
        ]))

    return story


def _build_osint_section(results, styles, w):
    story = []
    osint = results.get("osint", {})
    enum  = results.get("enumeration", {})

    story.append(Paragraph("7. OSINT & Reconocimiento", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))

    is_sub = results.get("target_info", {}).get("is_subdomain", False)
    root   = results.get("target_info", {}).get("root_domain", "")
    if is_sub:
        story.append(Paragraph(
            f"Esta sección recoge los datos de reconocimiento directamente asociados al endpoint "
            f"<b>{results.get('target','')}</b>. "
            f"Los datos del dominio raíz <b>{root}</b> (WHOIS, ASN, SPF/DMARC) "
            f"se encuentran en la sección 10.",
            styles["body_small"]
        ))
        story.append(Spacer(1, 0.2 * cm))

    # DNS Records
    dns_records = osint.get("dns_records", {})
    if dns_records:
        story.append(Spacer(1, 0.3 * cm))
        dns_title = Paragraph("7.2 Registros DNS", styles["h2"])
        dns_rows = [[Paragraph("<b>Tipo</b>", styles["body"]), Paragraph("<b>Valor</b>", styles["body"])]]
        for rtype, values in dns_records.items():
            for i, v in enumerate(values):
                dns_rows.append([
                    Paragraph(rtype if i == 0 else "", styles["body_small"]),
                    Paragraph(v[:100], styles["body_small"]),
                ])
        t2 = Table(dns_rows, colWidths=[w * 0.1, w * 0.9])
        t2.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HEAD),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_TABLE_TEXT),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether([dns_title, t2]))

    # Subdominios
    subdomains = enum.get("subdomains", [])
    if subdomains:
        story.append(Spacer(1, 0.3 * cm))
        sub_title = Paragraph(f"7.3 Subdominios ({len(subdomains)} encontrados)", styles["h2"])
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
            ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HEAD),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_TABLE_TEXT),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
            ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        story.append(KeepTogether([sub_title, t3]))

    return story


# ── CVEs ──────────────────────────────────────────────────────
def _build_cves_section(results, styles, w):
    story = []
    cves  = results.get("cves", [])

    snap       = results.get("config_snapshot", {})
    cve_source = snap.get("cve_source", "NVD/NIST")
    cve_reason = snap.get("cve_reason", "")

    if not cves:
        if cve_source == "none":
            msg = "No se identificaron productos con versión confirmada para correlación CVE."
        else:
            base = f"No se encontraron CVEs para los productos detectados."
            src  = f" Fuente consultada: <b>{cve_source}</b>."
            rsn  = f" {cve_reason}" if cve_reason else ""
            msg  = base + src + rsn
        return [KeepTogether([
            Paragraph("8. CVEs Identificados", styles["h1"]),
            ColorLine(w, C_ACCENT, 2),
            Spacer(1, 0.3 * cm),
            Paragraph(msg, styles["body"]),
        ])]

    story.append(Paragraph("8. CVEs Identificados", styles["h1"]))
    story.append(ColorLine(w, C_ACCENT, 2))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(
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
        ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HEAD),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_TABLE_TEXT),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
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
        cve_detail_title = Paragraph("Detalle de CVEs Críticos/Altos:", styles["h2"])
        for i, cve in enumerate(critical_cves[:10]):
            sev = cve.get("severity", "HIGH")
            cve_block = [
                Paragraph(
                    f"<b>{cve.get('id')}</b> — CVSS {cve.get('cvss_score')} "
                    f"(<font color='#{SEV_COLORS[sev].hexval()[2:]}'>{sev}</font>)",
                    styles["h3"]
                ),
                Paragraph(cve.get("description", "")[:400], styles["body_small"]),
                Paragraph(f"<i>Mitigación: {cve.get('remediation','')}</i>", styles["remediation"]),
                Spacer(1, 0.2 * cm),
            ]
            if i == 0:
                story.append(KeepTogether([cve_detail_title] + cve_block))
            else:
                story.append(KeepTogether(cve_block))

    return story


# ── TABLA CVSS CONSOLIDADA ────────────────────────────────────
def _build_cvss_table(results, styles, w, sec_num=9):
    story = []
    story.append(Paragraph(f"{sec_num}. Tabla CVSS Consolidada", styles["h1"]))
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
        ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HEAD),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_TABLE_TEXT),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    return story


# ── GREYBOX ───────────────────────────────────────────────────
def _build_greybox_section(results, styles, w, sec_num=11):
    story = []
    greybox   = results.get("greybox", {})
    discovery = greybox.get("discovery", {})
    audit     = greybox.get("audit", {})
    sso_audit = greybox.get("sso_audit", {})
    submode   = greybox.get("submode", 1)
    submode_name = {1: "API audit", 2: "SSO audit", 3: "API + SSO"}.get(submode, "Greybox")

    story.append(Paragraph(f"{sec_num}. Análisis Greybox — {submode_name}", styles["h1"]))
    story.append(ColorLine(w, HexColor("#8250DF"), 2))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph(
        "Análisis con credenciales que complementa el reconocimiento externo. "
        "Incluye discovery de endpoints, verificación de autenticación, "
        "detección de endpoints no documentados y auditoría de flujos OAuth2.",
        styles["body"]
    ))
    story.append(Spacer(1, 0.4 * cm))

    sub_idx = 0  # contador dinámico — evita renumerar a mano cada subsección condicional

    # ── 10.1 Resumen de discovery ─────────────────────────────
    if submode in (1, 3) and discovery:
        sub_idx += 1
        discovery_title = Paragraph(f"{sec_num}.{sub_idx} Resumen del Discovery", styles["h2"])

        endpoints   = discovery.get("endpoints", [])
        sources     = discovery.get("sources", {})
        n_postman   = sources.get("postman", 0)
        n_openapi   = sources.get("openapi", 0)
        n_spider    = sources.get("spider", 0)
        n_public    = sum(1 for e in endpoints if e.get("intentionally_public"))
        n_auth      = len(endpoints) - n_public
        n_undoc     = sum(
            1 for e in endpoints
            if all(s in ("spider", "spider_html")
                   for s in e.get("sources", [e.get("source", "spider")]))
            and (n_postman > 0 or n_openapi > 0)
        )
        n_multisrc  = sum(
            1 for e in endpoints
            if len(e.get("sources", [])) > 1
        )
        n_runtime   = discovery.get("runtime_generated_count", 0)

        k_st = ParagraphStyle("gb_k", fontName="Helvetica-Bold", fontSize=9, textColor=C_TEXT)
        v_st = ParagraphStyle("gb_v", fontName="Helvetica", fontSize=9, textColor=C_TEXT)

        summary_rows = [
            [Paragraph("Total endpoints descubiertos", k_st), Paragraph(str(len(endpoints)), v_st)],
            [Paragraph("Fuente — Postman", k_st),             Paragraph(str(n_postman), v_st)],
            [Paragraph("Fuente — OpenAPI", k_st),             Paragraph(str(n_openapi), v_st)],
            [Paragraph("Fuente — Spider",  k_st),             Paragraph(str(n_spider), v_st)],
            [Paragraph("Endpoints en múltiples fuentes", k_st), Paragraph(str(n_multisrc), v_st)],
            [Paragraph("Endpoints autenticados",    k_st),    Paragraph(str(n_auth), v_st)],
            [Paragraph("Endpoints públicos (noauth)", k_st),  Paragraph(str(n_public), v_st)],
            [Paragraph("Endpoints no documentados",  k_st),   Paragraph(str(n_undoc), v_st)],
        ]

        if n_runtime:
            summary_rows.append([
                Paragraph("Endpoints con variables runtime (no auditados)", k_st),
                Paragraph(
                    f"⚠ {n_runtime}",
                    ParagraphStyle("warn", fontName="Helvetica-Bold", fontSize=9,
                                   textColor=SEV_COLORS["MEDIUM"])
                )
            ])

        if discovery.get("swagger_found"):
            summary_rows.append([
                Paragraph("Swagger UI / OpenAPI expuesto", k_st),
                Paragraph("⚠ Detectado sin autenticación",
                          ParagraphStyle("warn", fontName="Helvetica-Bold", fontSize=9,
                                         textColor=SEV_COLORS["MEDIUM"]))
            ])
        if discovery.get("graphql_found"):
            summary_rows.append([
                Paragraph("GraphQL", k_st),
                Paragraph("⚠ Detectado",
                          ParagraphStyle("warn", fontName="Helvetica-Bold", fontSize=9,
                                         textColor=SEV_COLORS["MEDIUM"]))
            ])
        if discovery.get("wsdl_found"):
            ops = discovery.get("wsdl_operations", [])
            summary_rows.append([
                Paragraph("WSDL / SOAP", k_st),
                Paragraph(f"⚠ Detectado — {len(ops)} operación(es)",
                          ParagraphStyle("warn", fontName="Helvetica-Bold", fontSize=9,
                                         textColor=SEV_COLORS["MEDIUM"]))
            ])

        t = Table(summary_rows, colWidths=[w * 0.55, w * 0.45])
        t.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_BG_LIGHT, colors.white]),
            ("GRID",           (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",     (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
            ("LEFTPADDING",    (0, 0), (-1, -1), 8),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
            # Destacar endpoints no documentados si los hay
            ("BACKGROUND",     (0, 7), (-1, 7),  HexColor("#FFFBEA")) if n_undoc > 0 else
            ("BACKGROUND",     (0, 0), (-1, 0),  C_BG_LIGHT),
        ]))
        story.append(KeepTogether([discovery_title, t]))
        story.append(Spacer(1, 0.4 * cm))

        # ── Tabla de endpoints descubiertos ───────────────────
        if endpoints:
            sub_idx += 1
            endpoints_title = Paragraph(f"{sec_num}.{sub_idx} Endpoints descubiertos", styles["h2"])

            ep_header = [
                Paragraph("<b>Método</b>",  styles["body"]),
                Paragraph("<b>Path</b>",    styles["body"]),
                Paragraph("<b>Fuentes</b>", styles["body"]),
                Paragraph("<b>Auth</b>",    styles["body"]),
            ]
            ep_rows = [ep_header]
            for ep in endpoints[:50]:  # máximo 50 en PDF
                srcs  = ep.get("sources", [ep.get("source", "?")])
                pub   = ep.get("intentionally_public", False)
                meth  = ep.get("method", "GET")
                meth_color = {
                    "GET":    "#1F6FEB",
                    "POST":   "#0D6634",
                    "PUT":    "#D29922",
                    "PATCH":  "#D29922",
                    "DELETE": "#DA3633",
                }.get(meth, "#57606A")

                ep_rows.append([
                    Paragraph(
                        f"<font color='{meth_color}'><b>{meth}</b></font>",
                        styles["body_small"]
                    ),
                    Paragraph(ep.get("path", "")[:60], styles["body_small"]),
                    Paragraph(", ".join(srcs), styles["body_small"]),
                    Paragraph(
                        "<font color='#57606A'>público</font>" if pub
                        else "<font color='#0D6634'>requerida</font>",
                        styles["body_small"]
                    ),
                ])

            ep_table = Table(ep_rows, colWidths=[w*0.1, w*0.5, w*0.22, w*0.18])
            ep_table.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0),  C_TABLE_HEAD),
                ("TEXTCOLOR",     (0, 0), (-1, 0),  C_TABLE_TEXT),
                ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
                ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(KeepTogether([endpoints_title, ep_table]))

            if len(endpoints) > 50:
                story.append(Paragraph(
                    f"<i>Mostrando 50 de {len(endpoints)} endpoints. "
                    f"Ver api_discovery.json para el listado completo.</i>",
                    styles["body_small"]
                ))
            story.append(Spacer(1, 0.4 * cm))

    # ── 10.x Resumen de auditoría ─────────────────────────────
    if submode in (1, 3) and audit:
        sub_idx += 1
        sub_num = f"{sec_num}.{sub_idx}"

        gb_findings = audit.get("findings", [])
        n_idor      = sum(1 for f in gb_findings if "IDOR" in f.get("title", ""))
        n_noauth    = sum(1 for f in gb_findings if "sin autenticación" in f.get("title", "").lower())
        n_undoc_f   = sum(1 for f in gb_findings if "no documentado" in f.get("title", "").lower())
        n_methods   = sum(1 for f in gb_findings if "Método no documentado" in f.get("title", ""))
        n_exposure  = sum(1 for f in gb_findings if any(
            kw in f.get("title", "").lower()
            for kw in ["expuesto", "stack trace", "expuesta"]
        ))

        k_st = ParagraphStyle("gb_k2", fontName="Helvetica-Bold", fontSize=9, textColor=C_TEXT)
        v_st = ParagraphStyle("gb_v2", fontName="Helvetica", fontSize=9, textColor=C_TEXT)

        audit_rows = [
            [Paragraph("Endpoints auditados",             k_st), Paragraph(str(audit.get("endpoints_audited", 0)), v_st)],
            [Paragraph("Endpoints sin autenticación",     k_st), Paragraph(str(audit.get("endpoints_open", 0)),    v_st)],
            [Paragraph("Endpoints no documentados",       k_st), Paragraph(str(n_undoc_f),   v_st)],
            [Paragraph("Posibles IDOR",                   k_st), Paragraph(str(n_idor),       v_st)],
            [Paragraph("Métodos no documentados activos", k_st), Paragraph(str(n_methods),    v_st)],
            [Paragraph("Exposición de información",       k_st), Paragraph(str(n_exposure),   v_st)],
            [Paragraph("Total hallazgos API",             k_st), Paragraph(str(len(gb_findings)), v_st)],
        ]

        t2 = Table(audit_rows, colWidths=[w * 0.55, w * 0.45])
        t2.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_BG_LIGHT, colors.white]),
            ("GRID",           (0, 0), (-1, -1), 0.5, C_BORDER),
            ("TOPPADDING",     (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
            ("LEFTPADDING",    (0, 0), (-1, -1), 8),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ]))

        story.append(KeepTogether([
            Paragraph(f"{sub_num} Resumen de Auditoría API", styles["h2"]),
            Spacer(1, 0.2 * cm),
            t2,
            Spacer(1, 0.3 * cm),
            Paragraph(
                (
                    f"Se auditaron los {audit.get('endpoints_audited', 0)} endpoints descubiertos "
                    f"en {sec_num}.1 y {sec_num}.2 (mismo conjunto)"
                    + (
                        f", excluyendo {discovery.get('runtime_generated_count', 0)} endpoint(s) con "
                        f"variables runtime sin resolver, no auditables — ver {sec_num}.1."
                        if discovery.get("runtime_generated_count") else "."
                    )
                ),
                styles["body_small"]
            ),
        ]))

        # ── Detalle de hallazgos de la auditoría API ──────────────
        # Antes solo se daban recuentos ("Total hallazgos API: 3") sin decir
        # cuáles. Esta tabla identifica cada uno por título — el texto
        # completo (descripción, mitigación, evidencia) sigue en la sección
        # de Hallazgos de Seguridad; esto es un índice rápido para no tener
        # que localizarlos manualmente entre el resto de hallazgos del informe.
        if gb_findings:
            sub_idx += 1
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            gb_sorted = sorted(gb_findings, key=lambda f: sev_order.get(f.get("severity", "INFO"), 5))

            detail_rows = [[
                Paragraph("<b>#</b>",         styles["body"]),
                Paragraph("<b>Hallazgo</b>",  styles["body"]),
                Paragraph("<b>Severidad</b>", styles["body"]),
                Paragraph("<b>Confianza</b>", styles["body"]),
            ]]
            CONF_ES = {"HIGH": "Alta", "MEDIUM": "Media", "LOW": "Baja"}
            for i, f in enumerate(gb_sorted, 1):
                sev = f.get("severity", "INFO")
                detail_rows.append([
                    Paragraph(str(i), styles["body_small"]),
                    Paragraph(f.get("title", ""), styles["body_small"]),
                    Paragraph(
                        f"<font color='#{SEV_COLORS[sev].hexval()[2:]}'>{sev}</font>",
                        styles["body_small"]
                    ),
                    Paragraph(CONF_ES.get(f.get("confidence"), "—"), styles["body_small"]),
                ])

            t_detail = Table(detail_rows, colWidths=[w * 0.06, w * 0.62, w * 0.16, w * 0.16])
            t_detail.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HEAD),
                ("TEXTCOLOR",     (0, 0), (-1, 0), C_TABLE_TEXT),
                ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
                ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ]))
            legend_flowables = []
            if any(f.get("confidence") for f in gb_sorted):
                legend_flowables = [
                    Spacer(1, 0.15 * cm),
                    Paragraph(
                        "<b>Confianza</b> — no es severidad, es cuánta verificación manual adicional "
                        "requiere el hallazgo antes de priorizar su remediación: "
                        "<b>Alta</b> = hecho verificable sin ambigüedad (p.ej. estructura de la URL). "
                        "<b>Media</b> = patrón de comportamiento que conviene confirmar manualmente. "
                        "<b>Baja</b> = indicio parcial, con cobertura limitada del check.",
                        styles["body_small"]
                    ),
                ]

            story.append(KeepTogether([
                Paragraph(f"{sec_num}.{sub_idx} Detalle de hallazgos de la auditoría API", styles["h2"]),
                Spacer(1, 0.2 * cm),
                t_detail,
                Spacer(1, 0.2 * cm),
                Paragraph(
                    "<i>Descripción, evidencia y mitigación completas de cada hallazgo en la sección "
                    "3 (Hallazgos de Seguridad), buscando por el título exacto. Evidencia técnica "
                    "adicional (requests/responses) en api_audit.json.</i>",
                    styles["body_small"]
                ),
            ] + legend_flowables))

    # ── SSO audit summary ─────────────────────────────────────
    if submode in (2, 3) and sso_audit:
        sub_idx += 1
        sub_num = f"{sec_num}.{sub_idx}"
        sso_findings = sso_audit.get("findings", [])
        if sso_findings:
            sso_body = Paragraph(
                f"Se identificaron <b>{len(sso_findings)}</b> hallazgo(s) en el análisis "
                f"del flujo OAuth2/SSO. Consultar la sección de Hallazgos de Seguridad "
                f"para el detalle completo.",
                styles["body"]
            )
        else:
            sso_body = Paragraph(
                "No se identificaron problemas en el flujo OAuth2/SSO analizado.",
                styles["body"]
            )
        story.append(KeepTogether([
            Paragraph(f"{sub_num} Resumen de Auditoría SSO / OAuth2", styles["h2"]),
            sso_body,
        ]))

    return story


# ── METADATOS DE EJECUCIÓN ────────────────────────────────────
def _build_execution_metadata(results, styles, w, sec_num=13):
    block = []
    block.append(Paragraph(f"{sec_num}. Metadatos de Ejecución", styles["h1"]))
    block.append(ColorLine(w, C_ACCENT, 2))
    block.append(Spacer(1, 0.3 * cm))

    block.append(Paragraph(
        "Trazabilidad técnica de la ejecución que generó este informe.",
        styles["body"]
    ))
    block.append(Spacer(1, 0.3 * cm))

    start_time = results.get("start_time")
    end_time   = results.get("end_time")
    duration   = results.get("duration")

    k_st = ParagraphStyle("meta_k2", fontName="Helvetica-Bold", fontSize=9, textColor=C_MUTED)
    v_st = ParagraphStyle("meta_v2", fontName="Courier",        fontSize=9, textColor=C_TEXT, leading=13)

    rows_data = [
        ("Run ID",              results.get("run_id", "—")),
        ("Comando ejecutado",   results.get("command", "—")),
        ("Target",              results.get("target", "—")),
        ("Scope",               results.get("scope", "—").upper()),
        ("Inicio",              start_time.strftime("%Y-%m-%d %H:%M:%S") if start_time else "—"),
        ("Fin",                 end_time.strftime("%Y-%m-%d %H:%M:%S")   if end_time   else "—"),
        ("Duración (s)",        str(duration.seconds) if duration else "—"),
        ("Versión herramienta", RECON_CLI_VERSION),
    ]

    table_data = [[Paragraph(k, k_st), Paragraph(v, v_st)] for k, v in rows_data]

    t = Table(table_data, colWidths=[w * 0.28, w * 0.72])
    t.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",           (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",     (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 7),
        ("LEFTPADDING",    (0, 0), (-1, -1), 10),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND",     (0, 0), (-1, 0),  HexColor("#F0FFF8")),
        ("LINEABOVE",      (0, 0), (-1, 0),  1.5, C_ACCENT),
    ]))
    block.append(t)

    # Nota de cierre del informe — va junto a los metadatos, al final del documento.
    block.append(Spacer(1, 1 * cm))
    block.append(ColorLine(w, C_BORDER, 0.5))
    block.append(Spacer(1, 0.3 * cm))
    block.append(Paragraph(
        f"<i>Informe generado por recon-cli {RECON_CLI_VERSION} el "
        f"{results['start_time'].strftime('%d/%m/%Y a las %H:%M:%S')}. "
        f"Este documento es confidencial y está destinado exclusivamente al equipo de seguridad autorizado.</i>",
        styles["body_small"]
    ))

    # KeepTogether evita que el título quede solo al final de una página
    # mientras la tabla salta a la siguiente.
    return [KeepTogether(block)]


# ── MITIGACIONES ──────────────────────────────────────────────
def _build_mitigations_section(results, styles, w, sec_num=12):
    story = []
    story.append(Paragraph(f"{sec_num}. Propuestas de Mitigación", styles["h1"]))
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
        ("BACKGROUND",    (0, 0), (-1, 0), C_TABLE_HEAD),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_TABLE_TEXT),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.white, C_BG_LIGHT]),
        ("GRID",          (0, 0), (-1, -1), 0.5, C_BORDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)

    return story
