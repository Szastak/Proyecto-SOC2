"""Nordic Shadow Hunter - Executive and Technical PDF Report Generator.

This module generates professional incident investigation reports using fpdf2,
structured into an Executive Summary (business impact, NIS2/RGPD compliance,
recommended actions) and a Technical Summary (MITRE matrix, incident timelines,
IoCs, attribution, and containment playbooks).
"""

from datetime import datetime
import os
from pathlib import Path
import re
from fpdf import FPDF
from fpdf.fonts import FontFace

from report_content import (
    METADATA,
    EXECUTIVE_SUMMARY,
    TECHNICAL_SUMMARY,
    ANNEX_A,
    ANNEX_B,
)


def _detect_and_setup_font(pdf: FPDF):
    """Detect and register Unicode TrueType fonts or fallback to Helvetica."""
    dejavu_candidates = [
        (
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-BoldOblique.ttf",
        ),
        (
            "C:/Windows/Fonts/DejaVuSans.ttf",
            "C:/Windows/Fonts/DejaVuSans-Bold.ttf",
            "C:/Windows/Fonts/DejaVuSans-Oblique.ttf",
            "C:/Windows/Fonts/DejaVuSans-BoldOblique.ttf",
        ),
    ]
    for reg, bold, italic, b_italic in dejavu_candidates:
        if os.path.isfile(reg) and os.path.isfile(bold):
            try:
                pdf.add_font("DejaVu", "", reg)
                pdf.add_font("DejaVu", "B", bold)
                if os.path.isfile(italic):
                    pdf.add_font("DejaVu", "I", italic)
                if os.path.isfile(b_italic):
                    pdf.add_font("DejaVu", "BI", b_italic)
                return "DejaVu", True
            except Exception:
                pass

    arial_candidates = [
        (
            "C:/Windows/Fonts/arial.ttf",
            "C:/Windows/Fonts/arialbd.ttf",
            "C:/Windows/Fonts/ariali.ttf",
            "C:/Windows/Fonts/arialbi.ttf",
        ),
        (
            "/usr/share/fonts/truetype/msttcorefonts/arial.ttf",
            "/usr/share/fonts/truetype/msttcorefonts/arialbd.ttf",
            "/usr/share/fonts/truetype/msttcorefonts/ariali.ttf",
            "/usr/share/fonts/truetype/msttcorefonts/arialbi.ttf",
        ),
    ]
    for reg, bold, italic, b_italic in arial_candidates:
        if os.path.isfile(reg) and os.path.isfile(bold):
            try:
                pdf.add_font("ArialUni", "", reg)
                pdf.add_font("ArialUni", "B", bold)
                if os.path.isfile(italic):
                    pdf.add_font("ArialUni", "I", italic)
                if os.path.isfile(b_italic):
                    pdf.add_font("ArialUni", "BI", b_italic)
                return "ArialUni", True
            except Exception:
                pass

    return "Helvetica", False


def sanitize_text(text, is_unicode=True) -> str:
    """Sanitize strings to ensure strict emoji elimination and proper character encoding."""
    if text is None:
        return ""
    text = str(text)
    # Strict elimination of emojis
    text = re.sub(r"[\U00010000-\U0010ffff]", "", text)
    if not is_unicode:
        replacements = {
            "\u2014": " - ",
            "\u2013": "-",
            "\u2018": "'",
            "\u2019": "'",
            "\u201c": '"',
            "\u201d": '"',
            "\u2022": "*",
            "\u2026": "...",
            "\u2248": "~",
            "\u2265": ">=",
            "\u2264": "<=",
            "\u2192": "->",
        }
        for orig, rep in replacements.items():
            text = text.replace(orig, rep)
        text = text.encode("latin-1", "replace").decode("latin-1")
    return text


class NordicPDFReport(FPDF):
    """Custom FPDF2 class with running headers, footers, and professional styling."""

    def __init__(self, font_family="Helvetica", is_unicode=False):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.custom_font = font_family
        self.is_unicode = is_unicode
        self.set_margins(15, 18, 15)
        self.set_auto_page_break(auto=True, margin=18)

    def header(self):
        if self.page_no() > 1:
            self.set_y(8)
            self.set_font(self.custom_font, "B", 7.5)
            self.set_text_color(100, 110, 125)
            hdr_text = sanitize_text(METADATA["HEADER_TEXT"], self.is_unicode)
            self.cell(0, 5, hdr_text, align="R")
            self.set_draw_color(200, 205, 215)
            self.set_line_width(0.3)
            self.line(15, 14, 195, 14)
            self.set_y(18)

    def footer(self):
        if self.page_no() > 1:
            self.set_y(-14)
            self.set_draw_color(200, 205, 215)
            self.set_line_width(0.3)
            self.line(15, 283, 195, 283)
            self.set_font(self.custom_font, "", 8)
            self.set_text_color(120, 130, 140)
            conf_text = sanitize_text(METADATA["FOOTER_TEXT"], self.is_unicode)
            page_text = sanitize_text(f"P\u00e1gina {self.page_no()} / {{nb}}", self.is_unicode)
            self.cell(90, 8, conf_text, align="L")
            self.cell(90, 8, page_text, align="R")


def build_pdf(df, incidents, iocs, sha256, analyst="Sebastian Szostak") -> bytes:
    """Build the final forensic report in PDF format.

    Args:
        df: Enriched events dataframe.
        incidents: List of clustered incident dictionaries.
        iocs: Extracted indicators of compromise dataframe.
        sha256: Hexadecimal SHA-256 digest of original telemetry data.
        analyst: Name of the reporting SOC analyst.

    Returns:
        bytes: Raw bytes of the generated PDF document.
    """
    pdf = FPDF()
    font_family, is_unicode = _detect_and_setup_font(pdf)
    del pdf

    report = NordicPDFReport(font_family=font_family, is_unicode=is_unicode)
    report.set_title(sanitize_text(METADATA["TITLE"], is_unicode))
    report.set_author(sanitize_text(analyst, is_unicode))

    # Re-register custom font on the active report instance if needed
    if font_family != "Helvetica":
        _detect_and_setup_font(report)

    def _s(txt):
        return sanitize_text(txt, is_unicode)

    # Estilos de encabezado de tabla estandar
    table_head_style = FontFace(
        family=font_family,
        emphasis="B",
        size_pt=7.5,
        fill_color=(27, 42, 74),
        color=(255, 255, 255),
    )

    def add_h1(title_text):
        report.ln(3)
        report.set_fill_color(27, 42, 74)
        report.set_text_color(255, 255, 255)
        report.set_font(font_family, "B", 11)
        report.cell(0, 7.5, f"  {_s(title_text)}", fill=True, new_x="LMARGIN", new_y="NEXT")
        report.set_text_color(40, 50, 60)
        report.ln(2)

    def add_h2(sub_text):
        report.ln(2)
        report.set_text_color(27, 42, 74)
        report.set_font(font_family, "B", 9.5)
        report.cell(0, 5.5, _s(sub_text), new_x="LMARGIN", new_y="NEXT")
        report.set_draw_color(46, 107, 158)
        report.set_line_width(0.3)
        report.line(15, report.get_y(), 195, report.get_y())
        report.set_text_color(40, 50, 60)
        report.ln(2)

    def add_h3(h3_text):
        report.ln(1)
        report.set_text_color(46, 107, 158)
        report.set_font(font_family, "B", 8.5)
        report.cell(0, 4.5, _s(h3_text), new_x="LMARGIN", new_y="NEXT")
        report.set_text_color(40, 50, 60)
        report.ln(1)

    def add_p(text):
        report.set_font(font_family, "", 8)
        report.set_text_color(45, 55, 65)
        report.multi_cell(0, 4.0, _s(text))
        report.ln(1.5)

    # Calculo de metricas y KPIs clave
    total_events = len(df)
    malicious_events = (
        len(df[df["Incidente"] != ""])
        if "Incidente" in df.columns
        else sum(len(inc.get("log_ids", [])) for inc in incidents)
    )
    incident_count = len(incidents)
    all_hosts = sorted(list({h for inc in incidents for h in inc.get("hosts", [])}))
    host_count = len(all_hosts)
    external_ips = sorted(
        list(set(iocs[iocs["tipo"] == "IP Externa"]["valor"].unique()))
    ) if "tipo" in iocs.columns else []
    ip_count = len(external_ips)
    total_bytes_out = df["bytes_out"].sum() if "bytes_out" in df.columns else 0
    total_mb_approx = total_bytes_out / (1000 * 1000)  # ~253 MB

    # ==========================================================================
    # PORTADA / COVER PAGE
    # ==========================================================================
    report.add_page()
    report.set_y(25)

    # Franja decorativa superior
    report.set_fill_color(27, 42, 74)
    report.rect(15, 20, 180, 5, "F")
    report.set_fill_color(46, 107, 158)
    report.rect(15, 25, 180, 2, "F")

    report.set_y(35)
    report.set_font(font_family, "B", 18)
    report.set_text_color(27, 42, 74)
    report.multi_cell(0, 8.5, _s(METADATA["TITLE"]), align="C")

    report.ln(2)
    report.set_font(font_family, "", 11)
    report.set_text_color(100, 110, 125)
    report.cell(0, 6, _s(METADATA["SUBTITLE"]), align="C", new_x="LMARGIN", new_y="NEXT")

    report.ln(5)
    # Badge TLP:AMBER
    report.set_fill_color(217, 119, 6)  # Amber
    report.set_text_color(255, 255, 255)
    report.set_font(font_family, "B", 10)
    tlp_text = _s(f"CLASIFICACION {METADATA['CLASSIFICATION']}")
    badge_w = report.get_string_width(tlp_text) + 10
    badge_x = (210 - badge_w) / 2
    report.set_x(badge_x)
    report.cell(badge_w, 7, tlp_text, fill=True, align="C", new_x="LMARGIN", new_y="NEXT")

    report.ln(12)
    # Tabla de metadatos de portada
    cover_meta = [
        ["Cliente / Entidad:", METADATA["CLIENT"]],
        ["Organismo Investigador:", METADATA["ORGANIZATION"]],
        ["Analista SOC L2 a Cargo:", analyst],
        ["Fecha de Emisión del Informe:", datetime.now().strftime("%d de noviembre de 2026")],
        ["Estado Operacional de la Amenaza:", EXECUTIVE_SUMMARY["SECTION_1_2_STATUS"]],
        ["Resumen SHA-256 de Telemetría:", sha256],
    ]
    report.set_font(font_family, "", 9)
    report.set_draw_color(210, 215, 225)
    for lbl, val in cover_meta:
        report.set_x(25)
        report.set_font(font_family, "B", 8.5)
        report.set_text_color(27, 42, 74)
        report.cell(55, 6, _s(lbl), border=0)
        report.set_font(font_family, "", 8.5)
        report.set_text_color(45, 55, 65)
        report.cell(105, 6, _s(val), border=0, new_x="LMARGIN", new_y="NEXT")

    report.ln(10)
    # Tarjetas de resumen de KPIs principales
    report.set_draw_color(180, 190, 205)
    report.set_fill_color(245, 248, 252)

    kpis = [
        ("Eventos Analizados", f"{total_events}"),
        ("Eventos Maliciosos", f"{malicious_events}"),
        ("Incidentes Detectados", f"{incident_count}"),
        ("Hosts Afectados", f"{host_count}"),
        ("IPs Atacantes Externas", f"{ip_count}"),
        ("Exfiltración Estimada", f"~{total_mb_approx:.0f} MB"),
    ]

    kw = 28
    kh = 14
    report.set_x(18)
    for i, (k_lbl, k_val) in enumerate(kpis):
        x_pos = 18 + i * (kw + 1.5)
        report.set_xy(x_pos, 160)
        report.rect(x_pos, 160, kw, kh, "DF")
        report.set_xy(x_pos, 161)
        report.set_font(font_family, "B", 10)
        report.set_text_color(27, 42, 74)
        report.cell(kw, 5, _s(k_val), align="C")
        report.set_xy(x_pos, 166.5)
        report.set_font(font_family, "", 6.5)
        report.set_text_color(100, 110, 125)
        report.multi_cell(kw, 3, _s(k_lbl), align="C")

    report.set_xy(15, 220)
    report.set_font(font_family, "I", 7.5)
    report.set_text_color(120, 130, 140)
    aviso_conf = (
        "AVISO DE CONFIDENCIALIDAD: Este documento contiene información forense clasificada como TLP:AMBER. "
        "Su distribución está estrictamente limitada a los miembros autorizados del equipo de ciberseguridad, "
        "dirección técnica y asesoría jurídica del operador energético. Queda prohibida su reproducción parcial o total."
    )
    report.multi_cell(180, 4, _s(aviso_conf), align="C")

    # ==========================================================================
    # PARTE 1 - RESUMEN EJECUTIVO (PAGINAS 2 Y 3)
    # ==========================================================================
    report.add_page()
    add_h1(EXECUTIVE_SUMMARY["SECTION_1_TITLE"])

    add_h2(EXECUTIVE_SUMMARY["SECTION_1_1_TITLE"])
    add_p(EXECUTIVE_SUMMARY["SECTION_1_1_TEXT"])

    add_h2(EXECUTIVE_SUMMARY["SECTION_1_2_TITLE"])
    report.set_font(font_family, "B", 8.5)
    report.set_text_color(192, 57, 43)
    report.cell(0, 5, _s(f"Estado Formal: {EXECUTIVE_SUMMARY['SECTION_1_2_STATUS']}"), new_x="LMARGIN", new_y="NEXT")
    report.set_text_color(45, 55, 65)
    add_p(EXECUTIVE_SUMMARY["SECTION_1_2_TEXT"])

    add_h2(EXECUTIVE_SUMMARY["SECTION_1_3_TITLE"])
    for impact_title, impact_desc in EXECUTIVE_SUMMARY["SECTION_1_3_ITEMS"]:
        report.set_font(font_family, "B", 8)
        report.set_text_color(27, 42, 74)
        report.cell(0, 4.5, _s(f"\u2022 {impact_title}"), new_x="LMARGIN", new_y="NEXT")
        report.set_font(font_family, "", 7.8)
        report.set_text_color(50, 60, 70)
        report.multi_cell(0, 3.8, _s(f"   {impact_desc}"))
        report.ln(1)

    add_h2(EXECUTIVE_SUMMARY["SECTION_1_4_TITLE"])
    add_p(EXECUTIVE_SUMMARY["SECTION_1_4_RGPD"])
    add_p(EXECUTIVE_SUMMARY["SECTION_1_4_NIS2"])

    add_h2(EXECUTIVE_SUMMARY["SECTION_1_5_TITLE"])
    report.set_font(font_family, "", 7.5)
    report.set_text_color(40, 50, 60)
    with report.table(
        col_widths=(24, 96, 35, 25),
        headings_style=table_head_style,
        repeat_headings=1,
        text_align=("CENTER", "LEFT", "LEFT", "CENTER"),
        padding=1.5,
        cell_fill_color=(255, 255, 255),
        cell_fill_mode="ALL",
    ) as t_prio:
        r_head = t_prio.row()
        for h in EXECUTIVE_SUMMARY["RECOMMENDED_PRIORITIES_HEADERS"]:
            r_head.cell(_s(h))
        for row_data in EXECUTIVE_SUMMARY["RECOMMENDED_PRIORITIES"]:
            r = t_prio.row()
            for val in row_data:
                r.cell(_s(val))

    report.ln(2)
    add_h2(EXECUTIVE_SUMMARY["SECTION_1_6_TITLE"])
    report.set_font(font_family, "", 7.5)
    report.set_text_color(40, 50, 60)
    with report.table(
        col_widths=(20, 65, 22, 73),
        headings_style=table_head_style,
        repeat_headings=1,
        text_align=("CENTER", "LEFT", "CENTER", "LEFT"),
        padding=1.5,
        cell_fill_color=(255, 255, 255),
        cell_fill_mode="ALL",
    ) as t_risk:
        r_head = t_risk.row()
        for h in EXECUTIVE_SUMMARY["RISK_MATRIX_HEADERS"]:
            r_head.cell(_s(h))
        for row_data in EXECUTIVE_SUMMARY["RISK_MATRIX"]:
            r = t_risk.row()
            for val in row_data:
                r.cell(_s(val))

    # ==========================================================================
    # PARTE 2 - RESUMEN TECNICO Y EVIDENCIA FORENSE
    # ==========================================================================
    report.add_page()
    add_h1(TECHNICAL_SUMMARY["SECTION_2_TITLE"])

    add_h2(TECHNICAL_SUMMARY["SECTION_2_1_TITLE"])
    add_p(TECHNICAL_SUMMARY["SECTION_2_1_TEXT"])

    add_h2(TECHNICAL_SUMMARY["SECTION_2_2_TITLE"])
    report.set_font(font_family, "", 7.5)
    report.set_text_color(40, 50, 60)
    with report.table(
        col_widths=(18, 50, 32, 28, 25, 27),
        headings_style=table_head_style,
        repeat_headings=1,
        text_align=("CENTER", "LEFT", "LEFT", "LEFT", "LEFT", "LEFT"),
        padding=1.5,
        cell_fill_color=(255, 255, 255),
        cell_fill_mode="ALL",
    ) as t_inc:
        r_head = t_inc.row()
        for h in TECHNICAL_SUMMARY["INCIDENTS_TABLE_HEADERS"]:
            r_head.cell(_s(h))
        for inc in incidents:
            t_start = (
                inc["inicio"].strftime("%H:%M:%S")
                if hasattr(inc["inicio"], "strftime")
                else str(inc["inicio"])
            )
            t_end = (
                inc["fin"].strftime("%H:%M:%S")
                if hasattr(inc["fin"], "strftime")
                else str(inc["fin"])
            )
            r = t_inc.row()
            r.cell(_s(inc["id"]))
            r.cell(_s(inc["titulo"]))
            r.cell(_s(f"{t_start} - {t_end}"))
            r.cell(_s(", ".join(inc.get("hosts", []))))
            r.cell(_s(", ".join([u.replace("CORP\\", "") for u in inc.get("usuarios", [])])))
            r.cell(_s(", ".join(inc.get("tecnicas", []))))

    report.ln(3)
    add_h2(TECHNICAL_SUMMARY["SECTION_2_3_TITLE"])
    add_p(
        "A continuación se desglosa la secuencia cronológica completa de eventos maliciosos agrupados "
        "por incidente, indicando el identificador único de registro (Log_ID), marca temporal, host afectado, "
        "cuenta utilizada, Event ID de telemetría, detalle de la línea de comando o solicitud, y severidad asignada."
    )

    for inc in incidents:
        add_h3(f"{inc['id']} \u2014 {inc['titulo']} ({len(inc.get('log_ids', []))} Eventos Correlacionados)")
        report.set_font(font_family, "", 7.2)
        report.set_text_color(40, 50, 60)
        with report.table(
            col_widths=(18, 28, 20, 22, 14, 64, 14),
            headings_style=table_head_style,
            repeat_headings=1,
            text_align=("CENTER", "LEFT", "LEFT", "LEFT", "CENTER", "LEFT", "CENTER"),
            padding=1.2,
            cell_fill_color=(255, 255, 255),
            cell_fill_mode="ALL",
        ) as t_tl:
            r_head = t_tl.row()
            for h in TECHNICAL_SUMMARY["TIMELINE_HEADERS"]:
                r_head.cell(_s(h))
            for evt in inc.get("timeline", []):
                t_str = (
                    evt["Timestamp"].strftime("%Y-%m-%d %H:%M:%S")
                    if hasattr(evt["Timestamp"], "strftime")
                    else str(evt["Timestamp"])
                )
                u_str = str(evt.get("User", "")).replace("CORP\\", "")
                cmd_raw = str(evt.get("Process_CommandLine", "")) or str(evt.get("Event_Description", ""))
                r = t_tl.row()
                r.cell(_s(evt.get("Log_ID", "")))
                r.cell(_s(t_str))
                r.cell(_s(evt.get("Hostname", "")))
                r.cell(_s(u_str))
                r.cell(_s(evt.get("Event_ID", "")))
                r.cell(_s(cmd_raw))
                r.cell(_s(evt.get("Severidad_SOC", "")))
        report.ln(2)

    # 2.4 Matriz MITRE ATT&CK
    report.add_page()
    add_h2(TECHNICAL_SUMMARY["SECTION_2_4_TITLE"])
    add_p(
        "Mapeo exhaustivo de las técnicas de ataque observadas en la investigación contra la matriz MITRE "
        "ATT&CK Enterprise v14, desglosando la táctica, identificador de técnica, nombre canónico, "
        "incidentes donde se manifestó y los identificadores Log_ID que constituyen la evidencia forense."
    )

    # Construccion dinamica de la matriz MITRE
    mitre_rows = []
    technique_incidents = {}
    technique_log_ids = {}

    for inc in incidents:
        inc_id = inc["id"]
        for evt in inc.get("timeline", []):
            t_str = evt.get("Tecnica_MITRE", "")
            l_id = evt.get("Log_ID", "")
            if t_str:
                for tech in t_str.split(", "):
                    tech = tech.strip()
                    technique_incidents.setdefault(tech, set()).add(inc_id)
                    technique_log_ids.setdefault(tech, []).append(l_id)

    dict_mitre = TECHNICAL_SUMMARY["MITRE_DICTIONARY"]
    for tech_id in sorted(technique_incidents.keys()):
        tactic, tech_name = dict_mitre.get(tech_id, ("Actividad Sospechosa", tech_id))
        inc_list = sorted(list(technique_incidents[tech_id]))
        evts = technique_log_ids.get(tech_id, [])
        if len(evts) > 6:
            evt_sample = f"{evts[0]}..{evts[-1]} ({len(evts)} evts)"
        else:
            evt_sample = ", ".join(evts)
        mitre_rows.append([tactic, tech_name, tech_id, ", ".join(inc_list), evt_sample])

    mitre_rows.sort(key=lambda x: (x[0], x[2]))

    report.set_font(font_family, "", 7.5)
    report.set_text_color(40, 50, 60)
    with report.table(
        col_widths=(32, 48, 20, 26, 54),
        headings_style=table_head_style,
        repeat_headings=1,
        text_align=("LEFT", "LEFT", "CENTER", "LEFT", "LEFT"),
        padding=1.5,
        cell_fill_color=(255, 255, 255),
        cell_fill_mode="ALL",
    ) as t_mitre:
        r_head = t_mitre.row()
        for h in TECHNICAL_SUMMARY["MITRE_HEADERS"]:
            r_head.cell(_s(h))
        for row in mitre_rows:
            r = t_mitre.row()
            for val in row:
                r.cell(_s(val))

    # 2.5 Indicadores de Compromiso (IoCs)
    report.ln(2)
    add_h2(TECHNICAL_SUMMARY["SECTION_2_5_TITLE"])
    add_p(
        "Consolidación de artefactos e indicadores de compromiso (IoCs) extraídos del análisis de eventos, "
        "clasificados por categoría operativa para su ingestión en sistemas SIEM, EDR y pasarelas perimetrales."
    )

    report.set_font(font_family, "", 7.2)
    report.set_text_color(40, 50, 60)
    with report.table(
        col_widths=(26, 42, 50, 18, 22, 22),
        headings_style=table_head_style,
        repeat_headings=1,
        text_align=("LEFT", "LEFT", "LEFT", "CENTER", "LEFT", "LEFT"),
        padding=1.2,
        cell_fill_color=(255, 255, 255),
        cell_fill_mode="ALL",
    ) as t_iocs:
        r_head = t_iocs.row()
        for h in TECHNICAL_SUMMARY["IOC_TABLE_HEADERS"]:
            r_head.cell(_s(h))
        for _, row in iocs.iterrows():
            t_first = (
                row["primer_visto"].strftime("%H:%M:%S")
                if hasattr(row["primer_visto"], "strftime")
                else str(row["primer_visto"])
            )
            t_last = (
                row["ultimo_visto"].strftime("%H:%M:%S")
                if hasattr(row["ultimo_visto"], "strftime")
                else str(row["ultimo_visto"])
            )
            r = t_iocs.row()
            r.cell(_s(row["tipo"]))
            r.cell(_s(row["valor"]))
            r.cell(_s(row["contexto"]))
            r.cell(_s(row["incidente"]))
            r.cell(_s(t_first))
            r.cell(_s(t_last))

    report.ln(2)
    add_p(TECHNICAL_SUMMARY["IOC_HASHES_NOTE"])

    # 2.6 Correlacion y Analisis de Atribucion (ACH)
    report.add_page()
    add_h2(TECHNICAL_SUMMARY["SECTION_2_6_TITLE"])
    add_p(TECHNICAL_SUMMARY["ACH_INTRO"])

    add_h3("Definición de Hipótesis Competitivas:")
    for h_code, h_desc in TECHNICAL_SUMMARY["ACH_HYPOTHESES"].items():
        report.set_font(font_family, "B", 8)
        report.cell(10, 4.5, _s(f"{h_code}:"), border=0)
        report.set_font(font_family, "", 8)
        report.multi_cell(0, 4.5, _s(h_desc))
        report.ln(0.5)

    report.ln(2)
    add_h3("Matriz de Evaluación de Evidencia vs Hipótesis (ACH):")
    report.set_font(font_family, "", 7.5)
    report.set_text_color(40, 50, 60)
    with report.table(
        col_widths=(75, 35, 35, 35),
        headings_style=table_head_style,
        repeat_headings=1,
        text_align=("LEFT", "CENTER", "CENTER", "CENTER"),
        padding=1.5,
        cell_fill_color=(255, 255, 255),
        cell_fill_mode="ALL",
    ) as t_ach:
        r_head = t_ach.row()
        for h in TECHNICAL_SUMMARY["ACH_EVIDENCE_HEADERS"]:
            r_head.cell(_s(h))
        for row in TECHNICAL_SUMMARY["ACH_EVIDENCE_TABLE"]:
            r = t_ach.row()
            for val in row:
                r.cell(_s(val))

    report.ln(2)
    add_p(TECHNICAL_SUMMARY["ACH_ANALYSIS_TEXT"])
    add_p(TECHNICAL_SUMMARY["ACH_CONCLUSION_TEXT"])

    # 2.7 Calidad de Datos y Brechas de Visibilidad
    report.ln(2)
    add_h2(TECHNICAL_SUMMARY["SECTION_2_7_TITLE"])
    add_p(
        "A continuación se documentan las brechas de visibilidad identificadas durante el análisis forense, "
        "acompañadas de precisiones analíticas críticas sobre asignación de privilegios y vectores de compromiso."
    )

    for gap_title, gap_desc in TECHNICAL_SUMMARY["VISIBILITY_GAPS"]:
        report.set_font(font_family, "B", 8)
        report.set_text_color(27, 42, 74)
        report.cell(0, 4.5, _s(f"\u2022 {gap_title}"), new_x="LMARGIN", new_y="NEXT")
        report.set_font(font_family, "", 7.8)
        report.set_text_color(50, 60, 70)
        report.multi_cell(0, 3.8, _s(f"   {gap_desc}"))
        report.ln(1)

    report.ln(1)
    add_p(TECHNICAL_SUMMARY["NOTE_EVENT_4672"])
    add_p(TECHNICAL_SUMMARY["BACKUPSVC_INITIAL_VECTOR"])
    add_p(TECHNICAL_SUMMARY["SVC_BACKUP_DC01_ANOMALY"])

    # 2.8 Playbook Operativo de Contencion, Erradicacion y Recuperacion
    report.add_page()
    add_h2(TECHNICAL_SUMMARY["SECTION_2_8_TITLE"])
    add_p(
        "Playbook operacional de ejecución inmediata para el equipo de respuesta a incidentes (IR / SecOps), "
        "con mandatos y comandos técnicos ejecutables precisos por vector e incidente identificado."
    )

    report.set_font(font_family, "", 7.5)
    report.set_text_color(40, 50, 60)
    with report.table(
        col_widths=(35, 45, 100),
        headings_style=table_head_style,
        repeat_headings=1,
        text_align=("LEFT", "LEFT", "LEFT"),
        padding=1.5,
        cell_fill_color=(255, 255, 255),
        cell_fill_mode="ALL",
    ) as t_pb:
        r_head = t_pb.row()
        for h in TECHNICAL_SUMMARY["PLAYBOOK_HEADERS"]:
            r_head.cell(_s(h))
        for row in TECHNICAL_SUMMARY["CONTAINMENT_PLAYBOOKS"]:
            r = t_pb.row()
            for val in row:
                r.cell(_s(val))

    # ==========================================================================
    # ANEXOS TECNICOS: REGLAS Y GLOSARIO
    # ==========================================================================
    report.add_page()
    add_h1(ANNEX_A["TITLE"])
    report.set_font(font_family, "", 7.5)
    report.set_text_color(40, 50, 60)
    with report.table(
        col_widths=(14, 38, 70, 18, 40),
        headings_style=table_head_style,
        repeat_headings=1,
        text_align=("CENTER", "LEFT", "LEFT", "CENTER", "LEFT"),
        padding=1.4,
        cell_fill_color=(255, 255, 255),
        cell_fill_mode="ALL",
    ) as t_r:
        r_head = t_r.row()
        for h in ANNEX_A["HEADERS"]:
            r_head.cell(_s(h))
        for row in ANNEX_A["RULES"]:
            r = t_r.row()
            for val in row:
                r.cell(_s(val))

    report.ln(4)
    add_h1(ANNEX_B["TITLE"])
    report.set_font(font_family, "", 7.5)
    report.set_text_color(40, 50, 60)
    with report.table(
        col_widths=(22, 28, 55, 75),
        headings_style=table_head_style,
        repeat_headings=1,
        text_align=("CENTER", "LEFT", "LEFT", "LEFT"),
        padding=1.4,
        cell_fill_color=(255, 255, 255),
        cell_fill_mode="ALL",
    ) as t_glo:
        r_head = t_glo.row()
        for h in ANNEX_B["HEADERS"]:
            r_head.cell(_s(h))
        for row in ANNEX_B["EVENTS"]:
            r = t_glo.row()
            for val in row:
                r.cell(_s(val))

    return bytes(report.output())
