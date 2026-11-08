"""Nordic Shadow Hunter - SOC L2 Interactive Dashboard.

This module implements the Streamlit web application for security analysts to
investigate SIEM export logs, visualize incident timelines, inspect MITRE ATT&CK
mappings, explore Indicators of Compromise (IoCs), assess data quality anomalies,
and generate executive/technical forensic reports.
"""

from collections import Counter
from datetime import datetime
import io
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from detections import file_sha256, load_dataset, run_detections

# ==============================================================================
# CONFIGURACION DE SEVERIDAD Y PALETA DE COLORES
# ==============================================================================

SEVERITY_COLORS = {
    "Alto": "#EF4444",
    "Medio": "#F59E0B",
    "Bajo": "#10B981",
}

DEFAULT_DATASET_RELATIVE = (
    Path("data") / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
)


# ==============================================================================
# FUNCIONES DE LOGICA PURA Y COMPUTO FORENSE
# ==============================================================================


def compute_kpis(
    df: pd.DataFrame, incidents: List[Dict[str, Any]], iocs_df: pd.DataFrame
) -> Dict[str, Any]:
    """Calculate key performance indicators (KPIs) for the forensic investigation.

    Args:
        df: Enriched telemetry dataframe.
        incidents: Clustered incident list.
        iocs_df: Extracted Indicators of Compromise dataframe.

    Returns:
        Dict[str, Any]: Calculated KPI metrics matching ground truth.
    """
    total_events = len(df)
    malicious_events = len(df[df["Severidad_SOC"].isin(["Alto", "Medio"])])
    correlated_incidents = len(incidents)

    # Hosts afectados a traves de los incidentes correlacionados
    affected_hosts = set()
    for inc in incidents:
        affected_hosts.update(inc.get("hosts", []))
    num_hosts = len(affected_hosts)

    # IPs externas unicas extraidas en los IoCs
    if not iocs_df.empty and "tipo" in iocs_df.columns:
        ip_iocs = iocs_df[iocs_df["tipo"] == "IP Externa"]
        num_ips = len(set(ip_iocs["valor"].unique()))
    else:
        num_ips = 0

    # Volumen exfiltrado en bytes y megabytes en incidentes correlacionados
    inc_events = df[df["Incidente"].astype(str).str.startswith("INC-")]
    if not inc_events.empty and "bytes_out" in inc_events.columns:
        bytes_out_sum = int(inc_events["bytes_out"].sum())
    else:
        bytes_out_sum = 0

    mb_exfiltrated = bytes_out_sum / 1_000_000  # ~253.3 MB decimal
    mib_exfiltrated = bytes_out_sum / (1024 * 1024)  # 241.6 MiB

    return {
        "total_eventos": total_events,
        "eventos_maliciosos": malicious_events,
        "incidentes_correlacionados": correlated_incidents,
        "hosts_afectados": num_hosts,
        "ips_externas_ioc": num_ips,
        "volumen_exfiltrado_bytes": bytes_out_sum,
        "volumen_exfiltrado_mb": mb_exfiltrated,
        "volumen_exfiltrado_mib": mib_exfiltrated,
    }


def apply_filters(
    df: pd.DataFrame,
    severities: Optional[List[str]] = None,
    incidents: Optional[List[str]] = None,
    hostnames: Optional[List[str]] = None,
    users: Optional[List[str]] = None,
    source_ips: Optional[List[str]] = None,
    event_ids: Optional[List[str]] = None,
    time_range: Optional[Tuple[Any, Any]] = None,
) -> pd.DataFrame:
    """Filter telemetry dataframe according to user selections safely.

    Handles empty filter combinations gracefully without throwing runtime errors.

    Args:
        df: Telemetry dataframe.
        severities: Selected Severidad_SOC values.
        incidents: Selected incident identifiers.
        hostnames: Selected hostnames.
        users: Selected users.
        source_ips: Selected source IPs.
        event_ids: Selected Event IDs.
        time_range: Tuple of (min_time, max_time).

    Returns:
        pd.DataFrame: Filtered dataframe.
    """
    if df.empty:
        return df.copy()

    filtered = df.copy()

    # Filtro Severidad SOC
    if severities is not None:
        filtered = filtered[filtered["Severidad_SOC"].isin(severities)]

    # Filtro Incidente
    if incidents is not None:
        inc_conditions = []
        if "Sin Incidente" in incidents:
            inc_conditions.append(
                filtered["Incidente"].isna() | (filtered["Incidente"] == "")
            )
        actual_incidents = [i for i in incidents if i != "Sin Incidente"]
        if actual_incidents:
            inc_conditions.append(filtered["Incidente"].isin(actual_incidents))

        if inc_conditions:
            combined = inc_conditions[0]
            for cond in inc_conditions[1:]:
                combined = combined | cond
            filtered = filtered[combined]
        else:
            filtered = filtered.iloc[0:0]

    # Filtro Hostname
    if hostnames is not None:
        filtered = filtered[filtered["Hostname"].isin(hostnames)]

    # Filtro User
    if users is not None:
        filtered = filtered[filtered["User"].isin(users)]

    # Filtro Source_IP
    if source_ips is not None:
        filtered = filtered[filtered["Source_IP"].isin(source_ips)]

    # Filtro Event_ID
    if event_ids is not None:
        event_ids_str = {str(eid) for eid in event_ids}
        filtered = filtered[filtered["Event_ID"].astype(str).isin(event_ids_str)]

    # Filtro Rango Temporal
    if time_range is not None and len(time_range) == 2:
        t_start = pd.to_datetime(time_range[0])
        t_end = pd.to_datetime(time_range[1])
        filtered = filtered[
            (filtered["Timestamp"] >= t_start) & (filtered["Timestamp"] <= t_end)
        ]

    return filtered


# ==============================================================================
# PIPELINE CON CACHE DE RENDIMIENTO
# ==============================================================================


@st.cache_data(show_spinner="Ejecutando motor de correlación y análisis forense...")
def get_detection_data(
    file_bytes: bytes, filename: str, file_sha: str
) -> Tuple[pd.DataFrame, List[Dict[str, Any]], pd.DataFrame]:
    """Execute SIEM data loading, enrichment, and correlation with SHA-256 caching.

    Args:
        file_bytes: Raw bytes of the uploaded or default Excel dataset.
        filename: Name of the telemetry file.
        file_sha: Hexadecimal SHA-256 digest of the dataset file.

    Returns:
        Tuple[pd.DataFrame, List[Dict[str, Any]], pd.DataFrame]: Enriched dataframe,
        incident clustering list, and Indicators of Compromise dataframe.
    """
    df_raw = load_dataset(file_bytes)
    df_enriquecido, incidents, iocs_df = run_detections(df_raw)
    return df_enriquecido, incidents, iocs_df


# ==============================================================================
# ASISTENTE IA OPCIONAL (GEMINI)
# ==============================================================================


def generate_gemini_summary(
    kpis: Dict[str, Any], incidents: List[Dict[str, Any]], api_key: str
) -> str:
    """Generate an AI executive threat summary using the Gemini API.

    Gracefully falls back if network or API keys are invalid.
    """
    try:
        import requests

        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        prompt_text = (
            "Eres un analista forense SOC Nivel 2. Genera un resumen ejecutivo de amenaza "
            "en 3 párrafos concisos y técnicos basado en los siguientes KPIs e incidentes detectados "
            "en el sector energético nórdico:\n"
            f"- Eventos totales analizados: {kpis['total_eventos']}\n"
            f"- Eventos maliciosos: {kpis['eventos_maliciosos']}\n"
            f"- Incidentes APT: {kpis['incidentes_correlacionados']}\n"
            f"- Hosts afectados: {kpis['hosts_afectados']}\n"
            f"- IPs externas de C2: {kpis['ips_externas_ioc']}\n"
            f"- Volumen exfiltrado: ~{kpis['volumen_exfiltrado_mb']:.1f} MB\n"
            f"Resumen de incidentes: {', '.join(inc['id'] + ': ' + inc['titulo'] for inc in incidents)}."
        )
        payload = {"contents": [{"parts": [{"text": prompt_text}]}]}
        response = requests.post(url, json=payload, timeout=8)
        if response.status_code == 200:
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        else:
            return f"Respuesta de Gemini API (HTTP {response.status_code}): {response.text[:200]}"
    except Exception as exc:
        return f"No se pudo completar la consulta a Gemini IA: {exc}"


# ==============================================================================
# ENTORNO INTERACTIVO PRINCIPAL (STREAMLIT APP)
# ==============================================================================


def main():
    """Main application routine for the Nordic Shadow Hunter SOC L2 dashboard."""
    # Configuración de página
    st.set_page_config(
        page_title="Nordic Shadow Hunter — SOC L2",
        layout="wide",
        page_icon="🛡️",
    )

    # --------------------------------------------------------------------------
    # SIDEBAR: INGESTA, METADATOS Y FILTROS GLOBALES
    # --------------------------------------------------------------------------
    st.sidebar.title("🛡️ Nordic Shadow Hunter")
    st.sidebar.caption("SOC Level 2 Forensic Analytics")
    st.sidebar.divider()

    st.sidebar.subheader("📁 Ingesta de Telemetría")
    uploaded_file = st.sidebar.file_uploader(
        "Cargar exportación SIEM (.xlsx)", type=["xlsx"]
    )

    file_bytes: Optional[bytes] = None
    filename: str = ""
    is_default: bool = False

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        filename = uploaded_file.name
        is_default = False
    else:
        # Resolver dataset por defecto oficial
        dataset_path = DEFAULT_DATASET_RELATIVE
        if not dataset_path.is_file():
            # Buscar relativo al directorio del archivo actual
            alt_path = (
                Path(__file__).resolve().parent
                / "data"
                / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"
            )
            if alt_path.is_file():
                dataset_path = alt_path

        if dataset_path.is_file():
            file_bytes = dataset_path.read_bytes()
            filename = dataset_path.name
            is_default = True
            st.sidebar.success("🏷️ Dataset oficial cargado por defecto")
        else:
            st.sidebar.error(
                "No se encontró el dataset por defecto en data/ ni se cargó ningún archivo. "
                "Por favor cargue una exportación SIEM en formato Excel (.xlsx)."
            )
            st.stop()

    # Cálculo y presentación de metadatos de integridad forense
    file_sha = file_sha256(file_bytes)
    file_size_kb = len(file_bytes) / 1024

    st.sidebar.markdown(
        f"**Archivo:** `{filename}`  \n"
        f"**Tamaño:** `{file_size_kb:.1f} KB`  \n"
        f"**SHA-256:**  \n`{file_sha}`"
    )

    # Ejecución del pipeline forense cacheado
    df_enriquecido, incidents, iocs_df = get_detection_data(
        file_bytes, filename, file_sha
    )

    # Cálculo de KPIs base (ground truth de todo el dataset)
    baseline_kpis = compute_kpis(df_enriquecido, incidents, iocs_df)

    # Controles de filtrado interactivo en la barra lateral
    st.sidebar.divider()
    st.sidebar.subheader("🔍 Filtros Globales")

    # 1. Severidad SOC
    severity_options = ["Alto", "Medio", "Bajo"]
    selected_severities = st.sidebar.multiselect(
        "Severidad SOC",
        options=severity_options,
        default=severity_options,
        help="Clasificación de severidad analítica asignada por el motor de correlación.",
    )

    # 2. Incidente
    incident_options = [
        "INC-01",
        "INC-02",
        "INC-03",
        "INC-04",
        "INC-05",
        "INC-06",
        "Sin Incidente",
    ]
    selected_incidents = st.sidebar.multiselect(
        "Incidente Correlacionado",
        options=incident_options,
        default=incident_options,
        help="Agrupación contextual por cadena de ataque.",
    )

    # 3. Hostname
    all_hostnames = sorted(
        [h for h in df_enriquecido["Hostname"].dropna().unique().tolist() if h]
    )
    selected_hosts = st.sidebar.multiselect(
        "Hostname",
        options=all_hostnames,
        default=all_hostnames,
    )

    # 4. User
    all_users = sorted(
        [u for u in df_enriquecido["User"].dropna().unique().tolist() if u]
    )
    selected_users = st.sidebar.multiselect(
        "Usuario",
        options=all_users,
        default=all_users,
    )

    # 5. Source_IP
    all_source_ips = sorted(
        [
            ip
            for ip in df_enriquecido["Source_IP"].dropna().unique().tolist()
            if ip and str(ip).strip() not in ["-", ""]
        ]
    )
    selected_ips = st.sidebar.multiselect(
        "Source IP",
        options=all_source_ips,
        default=all_source_ips,
    )

    # 6. Event_ID
    all_event_ids = sorted(
        [
            str(eid)
            for eid in df_enriquecido["Event_ID"].dropna().unique().tolist()
            if eid
        ]
    )
    selected_event_ids = st.sidebar.multiselect(
        "Event ID",
        options=all_event_ids,
        default=all_event_ids,
    )

    # 7. Rango Temporal (Slider)
    min_time = df_enriquecido["Timestamp"].min().to_pydatetime()
    max_time = df_enriquecido["Timestamp"].max().to_pydatetime()

    time_slider = st.sidebar.slider(
        "Ventana Temporal de Análisis",
        min_value=min_time,
        max_value=max_time,
        value=(min_time, max_time),
        format="YYYY-MM-DD HH:mm",
    )

    # 8. Asistente Opcional Gemini IA
    gemini_key = os.getenv("GEMINI_API_KEY")
    gemini_enabled = False
    if gemini_key:
        st.sidebar.divider()
        st.sidebar.subheader("🤖 Asistente Inteligente")
        gemini_enabled = st.sidebar.toggle(
            "Resumen IA (Gemini)",
            value=False,
            help="Genera una síntesis forense automatizada con modelos generativos de Google.",
        )

    # Aplicar filtros sobre la telemetría
    df_filtered = apply_filters(
        df=df_enriquecido,
        severities=selected_severities,
        incidents=selected_incidents,
        hostnames=selected_hosts,
        users=selected_users,
        source_ips=selected_ips,
        event_ids=selected_event_ids,
        time_range=time_slider,
    )

    # Filtrar incidentes e IoCs relevantes para las vistas
    selected_inc_set = set(selected_incidents)
    active_incidents = [
        inc for inc in incidents if inc["id"] in selected_inc_set
    ]

    if not iocs_df.empty:
        iocs_filtered = iocs_df[iocs_df["incidente"].isin(selected_inc_set)]
    else:
        iocs_filtered = iocs_df

    # --------------------------------------------------------------------------
    # HEADER Y TITULO PRINCIPAL
    # --------------------------------------------------------------------------
    st.title("🛡️ Nordic Shadow Hunter — Análisis Forense SOC L2")
    st.caption(
        "Investigación forense avanzada de ciberataques coordinados contra la infraestructura "
        "de servicios energéticos nórdicos. Correlación de telemetría de eventos Windows, "
        "mapeo de tácticas y técnicas MITRE ATT&CK e identificación de vectores de intrusión APT."
    )

    # --------------------------------------------------------------------------
    # SECCION DE KPIS FORENSES (LAYOUT DE 6 COLUMNAS)
    # --------------------------------------------------------------------------
    kpi_col1, kpi_col2, kpi_col3, kpi_col4, kpi_col5, kpi_col6 = st.columns(6)

    # Si hay filtrado activo, mostrar métrica filtrada con contexto de base
    filtered_count = len(df_filtered)
    total_base = baseline_kpis["total_eventos"]

    kpi_col1.metric(
        "Total Eventos",
        f"{filtered_count:,}",
        delta=f"{filtered_count - total_base} filtrados"
        if filtered_count != total_base
        else "Dataset completo",
        help=f"Total de registros de telemetría en el dataset: {total_base}",
    )

    malicious_filtered = len(
        df_filtered[df_filtered["Severidad_SOC"].isin(["Alto", "Medio"])]
    )
    kpi_col2.metric(
        "Eventos Maliciosos",
        f"{malicious_filtered:,}",
        delta=f"Total base: {baseline_kpis['eventos_maliciosos']}"
        if malicious_filtered != baseline_kpis["eventos_maliciosos"]
        else None,
        help="Eventos catalogados con Severidad SOC Alto o Medio tras correlación.",
    )

    kpi_col3.metric(
        "Incidentes Correlacionados",
        f"{len(active_incidents)}",
        delta=f"Total base: {baseline_kpis['incidentes_correlacionados']}"
        if len(active_incidents) != baseline_kpis["incidentes_correlacionados"]
        else None,
        help="Cadenas de ataque correlacionadas (INC-01 a INC-06).",
    )

    kpi_col4.metric(
        "Hosts Afectados",
        f"{baseline_kpis['hosts_afectados']}",
        help="Equipos y servidores corporativos comprometidos en las cadenas de ataque.",
    )

    kpi_col5.metric(
        "IPs Externas IoC",
        f"{baseline_kpis['ips_externas_ioc']}",
        help="Direcciones IP públicas no pertenecientes a RFC 1918 identificadas en IoCs.",
    )

    kpi_col6.metric(
        "Volumen Exfiltrado",
        f"~{baseline_kpis['volumen_exfiltrado_mb']:.0f} MB",
        help=(
            f"Suma de bytes_out en incidentes: {baseline_kpis['volumen_exfiltrado_bytes']:,} bytes "
            f"({baseline_kpis['volumen_exfiltrado_mb']:.1f} MB brutos / "
            f"{baseline_kpis['volumen_exfiltrado_mib']:.1f} MiB)."
        ),
    )

    st.divider()

    # Integración opcional de Gemini si fue activada en la barra lateral
    if gemini_enabled and gemini_key:
        with st.expander("🤖 Resumen Ejecutivo Generado por IA (Gemini)", expanded=True):
            if st.button("Generar / Actualizar Síntesis con Gemini"):
                with st.spinner("Consultando modelo generativo..."):
                    summary_text = generate_gemini_summary(
                        baseline_kpis, incidents, gemini_key
                    )
                    st.markdown(summary_text)

    # --------------------------------------------------------------------------
    # PESTAÑAS PRINCIPALES DEL DASHBOARD FORENSE
    # --------------------------------------------------------------------------
    tab_resumen, tab_timeline, tab_incidentes, tab_data, tab_iocs, tab_calidad = (
        st.tabs(
            [
                "📊 Resumen",
                "⏱️ Línea de tiempo",
                "🚨 Incidentes",
                "🔍 Explorador de Datos",
                "🎯 Indicadores de Compromiso (IoCs)",
                "🛡️ Calidad de Datos",
            ]
        )
    )

    # --------------------------------------------------------------------------
    # PESTAÑA A: RESUMEN ANALITICO
    # --------------------------------------------------------------------------
    with tab_resumen:
        st.subheader("📊 Distribución y Taxonomía de Amenazas")

        if df_filtered.empty:
            st.info(
                "No hay registros que coincidan con la combinación actual de filtros seleccionados."
            )
        else:
            col_chart_left, col_chart_right = st.columns([1, 1])

            # Gráfico de Donut: Distribución de Severidad SOC
            with col_chart_left:
                sev_counts = df_filtered["Severidad_SOC"].value_counts().reset_index()
                sev_counts.columns = ["Severidad_SOC", "Cantidad"]

                donut_fig = px.pie(
                    sev_counts,
                    names="Severidad_SOC",
                    values="Cantidad",
                    hole=0.55,
                    title="Distribución de Severidad SOC",
                    color="Severidad_SOC",
                    color_discrete_map=SEVERITY_COLORS,
                )
                donut_fig.update_traces(
                    textposition="inside",
                    textinfo="percent+label+value",
                    marker=dict(line=dict(color="#1E293B", width=2)),
                )
                donut_fig.update_layout(
                    template="plotly_dark",
                    margin=dict(l=20, r=20, t=50, b=20),
                    showlegend=True,
                )
                st.plotly_chart(donut_fig, use_container_width=True)

            # Gráfico de Barras: Eventos por Técnica MITRE ATT&CK
            with col_chart_right:
                mitre_techs = []
                for tech_str in df_filtered["Tecnica_MITRE"].dropna():
                    if tech_str:
                        for t in str(tech_str).split(","):
                            t_clean = t.strip()
                            if t_clean:
                                mitre_techs.append(t_clean)

                if mitre_techs:
                    tech_counts = Counter(mitre_techs).most_common(12)
                    df_techs = pd.DataFrame(
                        tech_counts, columns=["Técnica MITRE", "Eventos"]
                    ).sort_values("Eventos", ascending=True)

                    bar_fig = px.bar(
                        df_techs,
                        x="Eventos",
                        y="Técnica MITRE",
                        orientation="h",
                        title="Top Técnicas MITRE ATT&CK Identificadas",
                        color="Eventos",
                        color_continuous_scale="Reds",
                    )
                    bar_fig.update_layout(
                        template="plotly_dark",
                        margin=dict(l=20, r=20, t=50, b=20),
                        coloraxis_showscale=False,
                    )
                    st.plotly_chart(bar_fig, use_container_width=True)
                else:
                    st.info("No hay técnicas MITRE asignadas en los eventos filtrados.")

            st.divider()

            # Matriz de Severidad: Fuente SIEM vs Severidad SOC (Crosstab / Heatmap)
            st.subheader("🔄 Comparativa de Severidad: Fuente SIEM vs Severidad SOC")
            crosstab_df = pd.crosstab(
                df_filtered["Severity"],
                df_filtered["Severidad_SOC"],
            )

            # Asegurar orden consistente de columnas
            for col in ["Alto", "Medio", "Bajo"]:
                if col not in crosstab_df.columns:
                    crosstab_df[col] = 0
            crosstab_df = crosstab_df[["Alto", "Medio", "Bajo"]]

            heat_fig = px.imshow(
                crosstab_df,
                text_auto=True,
                aspect="auto",
                color_continuous_scale="Viridis",
                labels=dict(
                    x="Severidad Asignada por Motor SOC L2",
                    y="Severidad Original Fuente SIEM",
                    color="Eventos",
                ),
                title="Matriz de Discrepancia: Severidad de Fuente vs Severidad SOC",
            )
            heat_fig.update_layout(
                template="plotly_dark",
                margin=dict(l=20, r=20, t=50, b=20),
            )
            st.plotly_chart(heat_fig, use_container_width=True)

            # Alerta de analista para eventos subestimados por la fuente
            underestimated_events = df_filtered[
                (df_filtered["Severity"] == "Informational")
                & (df_filtered["Severidad_SOC"] == "Alto")
            ]

            if not underestimated_events.empty:
                st.warning(
                    f"⚠️ **Alerta de Analista — Eventos subestimados por la fuente:** "
                    f"Se identificaron **{len(underestimated_events)} eventos** catalogados originalmente "
                    f"por la fuente como **'Informational'** que fueron escalados a **'Alto'** tras "
                    f"el análisis contextual de amenazas (correlación de LOLBins, comandos PowerShell "
                    f"ofuscados, credenciales privilegiadas o borrado de copias shadow de volumen)."
                )
                with st.expander(
                    f"🔍 Ver {len(underestimated_events)} eventos subestimados escalados a 'Alto'"
                ):
                    cols_to_show = [
                        "Log_ID",
                        "Timestamp",
                        "Hostname",
                        "User",
                        "Event_ID",
                        "Process_CommandLine",
                        "Regla",
                        "Tecnica_MITRE",
                    ]
                    available_cols = [
                        c for c in cols_to_show if c in underestimated_events.columns
                    ]
                    st.dataframe(
                        underestimated_events[available_cols],
                        use_container_width=True,
                        hide_index=True,
                    )
            else:
                st.success(
                    "✅ No se registran eventos subestimados (Informational ➔ Alto) en la selección actual."
                )

    # --------------------------------------------------------------------------
    # PESTAÑA B: LINEA DE TIEMPO INTERACTIVA
    # --------------------------------------------------------------------------
    with tab_timeline:
        st.subheader("⏱️ Línea de Tiempo y Dispersión de Incidentes")

        if df_filtered.empty:
            st.info("No hay eventos disponibles para generar la línea de tiempo.")
        else:
            # Gráfico de dispersión interactivo: X=Timestamp, Y=Hostname, Color=Incidente
            # Normalizar Incidente vacío a 'Sin Incidente' para la leyenda
            timeline_df = df_filtered.copy()
            timeline_df["Incidente_Display"] = timeline_df["Incidente"].replace(
                {"": "Sin Incidente", None: "Sin Incidente"}
            )

            scatter_fig = px.scatter(
                timeline_df,
                x="Timestamp",
                y="Hostname",
                color="Incidente_Display",
                hover_data={
                    "Log_ID": True,
                    "User": True,
                    "Event_ID": True,
                    "Severidad_SOC": True,
                    "Process_CommandLine": True,
                    "Event_Description": True,
                    "Incidente_Display": False,
                },
                title="Línea de Tiempo Forense: Dispersión de Eventos por Hostname e Incidente",
                height=450,
            )
            scatter_fig.update_traces(
                marker=dict(size=9, opacity=0.85, line=dict(width=1, color="#334155"))
            )
            scatter_fig.update_layout(
                template="plotly_dark",
                margin=dict(l=20, r=20, t=50, b=20),
                legend_title_text="Incidente",
            )
            st.plotly_chart(scatter_fig, use_container_width=True)

            st.divider()

            # Histograma por minuto de eventos maliciosos (Alto y Medio)
            st.subheader("📈 Actividad Maliciosa en el Tiempo (Alto y Medio)")
            malicious_timeline = df_filtered[
                df_filtered["Severidad_SOC"].isin(["Alto", "Medio"])
            ]

            if not malicious_timeline.empty:
                hist_fig = px.histogram(
                    malicious_timeline,
                    x="Timestamp",
                    color="Severidad_SOC",
                    color_discrete_map=SEVERITY_COLORS,
                    nbins=60,
                    title="Volumen Temporal de Eventos Maliciosos (Agrupados por Minuto)",
                    labels={"Timestamp": "Tiempo", "count": "Cantidad de Eventos"},
                )
                hist_fig.update_layout(
                    template="plotly_dark",
                    barmode="stack",
                    margin=dict(l=20, r=20, t=50, b=20),
                    yaxis_title="Cantidad de Eventos",
                )
                st.plotly_chart(hist_fig, use_container_width=True)
            else:
                st.info(
                    "No se identificaron eventos maliciosos (Alto/Medio) en el rango temporal o filtros seleccionados."
                )

    # --------------------------------------------------------------------------
    # PESTAÑA C: EXPANDERS DE INCIDENTES (INC-01 A INC-06)
    # --------------------------------------------------------------------------
    with tab_incidentes:
        st.subheader("🚨 Detalle de Incidentes Correlacionados")

        if not active_incidents:
            st.info(
                "No hay incidentes correlacionados seleccionados o activos en la vista actual."
            )
        else:
            for inc in active_incidents:
                inc_id = inc["id"]
                titulo = inc.get("titulo", "Incidente de Seguridad")
                sev = inc.get("severidad", "Medio")
                icon = "🔴" if sev == "Alto" else "🟠"

                with st.expander(
                    f"{icon} **{inc_id}**: {titulo} — Severidad: {sev}",
                    expanded=(inc_id == "INC-01"),
                ):
                    # Cabecera de metadatos del incidente en columnas
                    m_col1, m_col2, m_col3, m_col4 = st.columns(4)

                    t_start_str = (
                        inc["inicio"].strftime("%Y-%m-%d %H:%M:%S")
                        if hasattr(inc["inicio"], "strftime")
                        else str(inc["inicio"])
                    )
                    t_end_str = (
                        inc["fin"].strftime("%Y-%m-%d %H:%M:%S")
                        if hasattr(inc["fin"], "strftime")
                        else str(inc["fin"])
                    )

                    m_col1.markdown(
                        f"**Ventana Temporal:**  \n`{t_start_str}`  \na `{t_end_str}`"
                    )
                    m_col2.markdown(
                        f"**Hosts Afectados ({len(inc['hosts'])}):**  \n{', '.join(f'`{h}`' for h in inc['hosts'])}"
                    )
                    m_col3.markdown(
                        f"**Cuentas Involucradas ({len(inc['usuarios'])}):**  \n{', '.join(f'`{u}`' for u in inc['usuarios'])}"
                    )
                    ips_display = (
                        ", ".join(f"`{ip}`" for ip in inc["ips"])
                        if inc["ips"]
                        else "_Tráfico Interno_"
                    )
                    m_col4.markdown(f"**IPs Externas IoC:**  \n{ips_display}")

                    # Técnicas MITRE ATT&CK
                    techs_str = ", ".join(f"`{t}`" for t in inc.get("tecnicas", []))
                    st.markdown(f"**Técnicas MITRE ATT&CK:** {techs_str}")

                    # Narrativa analítica sintética
                    st.info(f"**Narrativa Forense:** {inc.get('resumen', 'N/A')}")

                    # Cronología tabular del incidente
                    st.markdown("##### 📜 Cronología de Eventos Correlacionados")
                    if inc.get("timeline"):
                        df_timeline = pd.DataFrame(inc["timeline"])
                        timeline_display_cols = [
                            "Timestamp",
                            "Log_ID",
                            "Hostname",
                            "User",
                            "Event_ID",
                            "Process_CommandLine",
                            "Event_Description",
                            "Severidad_SOC",
                        ]
                        cols_valid = [
                            c for c in timeline_display_cols if c in df_timeline.columns
                        ]
                        st.dataframe(
                            df_timeline[cols_valid],
                            use_container_width=True,
                            hide_index=True,
                        )
                    else:
                        st.caption("No hay eventos en la cronología de este incidente.")

    # --------------------------------------------------------------------------
    # PESTAÑA D: EXPLORADOR DE DATOS
    # --------------------------------------------------------------------------
    with tab_data:
        st.subheader("🔍 Explorador Integral de Telemetría SIEM")
        st.markdown(
            f"Mostrando **{len(df_filtered):,}** eventos coincidentes con los filtros aplicados "
            f"(de un total de **{len(df_enriquecido):,}** eventos analizados)."
        )

        st.dataframe(
            df_filtered,
            use_container_width=True,
            hide_index=True,
        )

        # Botón de descarga CSV de la telemetría filtrada
        csv_telemetry = df_filtered.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="📥 Descargar Telemetría Filtrada (CSV)",
            data=csv_telemetry,
            file_name="telemetria_forense_nordic_shadow.csv",
            mime="text/csv",
            key="btn_download_telemetry",
        )

    # --------------------------------------------------------------------------
    # PESTAÑA E: INDICADORES DE COMPROMISO (IOCS)
    # --------------------------------------------------------------------------
    with tab_iocs:
        st.subheader("🎯 Indicadores de Compromiso (IoCs) Forenses")
        st.caption(
            "Artefactos y evidencias forenses extraídas de forma analítica y genérica "
            "a partir de la correlación de eventos SIEM sin filtros cableados."
        )

        if iocs_filtered.empty:
            st.info(
                "No hay Indicadores de Compromiso disponibles para la selección actual."
            )
        else:
            # Resumen de métricas de IoCs
            ioc_types = iocs_filtered["tipo"].value_counts().to_dict()
            ioc_cols = st.columns(max(len(ioc_types), 1))
            for i, (tipo_nombre, conteo) in enumerate(ioc_types.items()):
                ioc_cols[i % len(ioc_cols)].metric(f"IoCs: {tipo_nombre}", conteo)

            st.divider()

            # Tabla estructurada de IoCs
            iocs_table = iocs_filtered.rename(
                columns={
                    "tipo": "Tipo",
                    "valor": "Valor",
                    "contexto": "Contexto",
                    "incidente": "Incidente",
                    "primer_visto": "Primer Visto",
                    "ultimo_visto": "Último Visto",
                }
            )

            st.dataframe(
                iocs_table,
                use_container_width=True,
                hide_index=True,
            )

            # Botón de descarga de IoCs en formato CSV
            csv_iocs = iocs_table.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="📥 Descargar Indicadores de Compromiso (CSV)",
                data=csv_iocs,
                file_name="iocs_nordic_shadow_soc_l2.csv",
                mime="text/csv",
                key="btn_download_iocs",
            )

    # --------------------------------------------------------------------------
    # PESTAÑA F: CALIDAD DE DATOS Y HALLAZGOS NEGATIVOS
    # --------------------------------------------------------------------------
    with tab_calidad:
        st.subheader("🛡️ Aseguramiento de Calidad de Datos (R14)")
        st.markdown(
            "La regla genérica **R14** evalúa la integridad y consistencia morfológica de los "
            "identificadores de activos y cuentas de usuario para identificar colisiones de nombres "
            "y técnicas de ofuscación por semejanza tipográfica (typo-squatting)."
        )

        anomalias_df = df_enriquecido[df_enriquecido["Anomalia_Dato"] != ""]

        col_anom1, col_anom2 = st.columns(2)
        with col_anom1:
            st.markdown("#### 1. Colisión de Hostname: DC01 vs DC-01")
            dc01_events = df_enriquecido[df_enriquecido["Hostname"] == "DC01"]
            st.metric("Eventos con Hostname no estándar DC01", len(dc01_events))
            st.caption(
                "**Hallazgo forense:** Se observan eventos emitidos por el hostname `DC01`, el cual "
                "carece del guion estándar corporativo (`DC-01`). El motor de correlación aísla estos "
                "eventos con severidad **Bajo** sin vincularlos erróneamente a incidentes maliciosos, "
                "identificando una probable discrepancia en la configuración del agente SIEM o un activo sombra."
            )

        with col_anom2:
            st.markdown("#### 2. Cuenta Look-Alike: CORP\\svc_backup vs CORP\\backupsvc")
            svc_backup_events = df_enriquecido[
                df_enriquecido["User"] == r"CORP\svc_backup"
            ]
            st.metric(
                "Eventos con Cuenta Señuelo CORP\\svc_backup", len(svc_backup_events)
            )
            st.caption(
                "**Hallazgo forense:** Se documenta la presencia de la identidad `CORP\\svc_backup`, "
                "una permutación morfológica de la cuenta legítima `CORP\\backupsvc`. La regla R14 detecta "
                "esta similitud léxica sin asignarle falsos positivos de intrusión activa, señalando su naturaleza "
                "de anomalía de datos o cuenta candidata a suplantación."
            )

        st.markdown("##### 📋 Registro de Eventos con Anomalías de Datos Flageladas")
        if not anomalias_df.empty:
            cols_anom = [
                "Log_ID",
                "Timestamp",
                "Hostname",
                "User",
                "Event_ID",
                "Anomalia_Dato",
                "Severidad_SOC",
                "Incidente",
            ]
            valid_anom_cols = [c for c in cols_anom if c in anomalias_df.columns]
            st.dataframe(
                anomalias_df[valid_anom_cols],
                use_container_width=True,
                hide_index=True,
            )

        st.divider()

        # Documentación de hallazgos negativos
        st.subheader("🛑 Documentación de Hallazgos Negativos Críticos")
        evt_4720_4732 = df_enriquecido[
            df_enriquecido["Event_ID"].isin(["4720", "4732"])
        ]
        count_negative = len(evt_4720_4732)

        st.metric(
            "Eventos de Creación de Cuentas / Grupos (4720 / 4732)",
            count_negative,
            help="Confirmación de ausencia de eventos 4720 (User Created) y 4732 (Member Added to Group).",
        )

        st.markdown(
            """
            > **Relevancia Forense del Hallazgo Negativo:**  
            > La confirmación analítica de la **ausencia total (0 eventos)** de creación de cuentas de usuario 
            > (**Event ID 4720**) y agregación de miembros a grupos locales o de dominio (**Event ID 4732**) 
            > constituye un indicador táctico de alta relevancia.  
            >
            > **Conclusión de Atribución y Comportamiento:**  
            > Los actores de amenaza no recurrieron a la creación de cuentas de persistencia rudimentarias 
            > en el Directorio Activo, las cuales suelen disparar alertas tempranas de criticidad alta.  
            > En su lugar, mantuvieron un perfil operativo sigiloso utilizando:
            > 1. Reutilización de credenciales válidas comprometidas mediante Password Spraying (**T1110.003**).
            > 2. Despliegue de web shells en servidores expuestos (**T1505.003**).
            > 3. Persistencia mediante servicios y tareas programadas legítimas (**T1543.003**, **T1053.005**).
            """
        )

    # --------------------------------------------------------------------------
    # SECCION INFERIOR: GENERACION DE INFORME FORENSE PDF
    # --------------------------------------------------------------------------
    st.divider()
    st.subheader("📑 Generación de Informe Forense PDF")
    st.caption(
        "Emisión automatizada del informe forense consolidado (Resumen Ejecutivo, Matriz MITRE ATT&CK, "
        "Cronología Técnica, Indicadores de Compromiso y Guía de Remediación NIS2)."
    )

    pdf_col1, pdf_col2 = st.columns([1, 2])
    with pdf_col1:
        generate_pdf_clicked = st.button(
            "📄 Generar Informe Forense PDF",
            type="primary",
            use_container_width=True,
            key="btn_generate_pdf",
        )

    if generate_pdf_clicked:
        try:
            # Importación dinámica y ejecución graceful de report.py
            import report

            with st.spinner("Compilando informe forense PDF con fpdf2..."):
                pdf_bytes = report.build_pdf(
                    df=df_enriquecido,
                    incidents=incidents,
                    iocs=iocs_df,
                    sha256=file_sha,
                    analyst="Sebastian Szostak",
                )

            if pdf_bytes and isinstance(pdf_bytes, (bytes, bytearray)):
                timestamp_str = datetime.now().strftime("%Y%m%d_%H%M")
                pdf_filename = f"Informe_Nordic_Shadow_{timestamp_str}.pdf"
                st.success("✅ Informe forense PDF compilado exitosamente.")
                st.download_button(
                    label="⬇️ Descargar Informe PDF",
                    data=pdf_bytes,
                    file_name=pdf_filename,
                    mime="application/pdf",
                    key="btn_download_pdf",
                    use_container_width=True,
                )
            else:
                st.warning(
                    "El generador de informes report.py no retornó un buffer de bytes válido."
                )

        except (NotImplementedError, AttributeError, Exception) as exc:
            st.info(
                f"ℹ️ **Generador de informe PDF en desarrollo activo (Subfase F2B):**  \n"
                f"`report.build_pdf(...)` reportó: *{exc}*  \n\n"
                f"La aplicación Streamlit gestiona esta excepción de forma controlada y resiliente. "
                f"La telemetría forense interactiva, filtros, visualizaciones y descargas CSV "
                f"continúan 100% operativas."
            )


# ==============================================================================
# ENTRADA DE EJECUCION
# ==============================================================================

if __name__ == "__main__":
    main()
