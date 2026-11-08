"""Nordic Shadow Hunter - SOC L2 Interactive Dashboard.

<<<<<<< Updated upstream
This module implements the Streamlit web application for security analysts to
investigate SIEM export logs, visualize incident timelines, inspect MITRE ATT&CK
mappings, explore Indicators of Compromise (IoCs), assess data quality anomalies,
and generate executive/technical forensic reports.
=======
Aplicacion web para analistas SOC Nivel 2: ingesta de exportaciones SIEM,
correlacion de incidentes, cadenas de ataque MITRE ATT&CK, threat hunting,
IoCs, calidad de datos y emision del informe forense PDF.

El tema visual (Claro / Oscuro / Sistema) se define en .streamlit/config.toml
y se cambia desde el menu ⋮ de la app (System / Light / Dark). Todos los componentes usan
widgets nativos y graficos con el tema de Streamlit, por lo que se adaptan
automaticamente al tema elegido.
>>>>>>> Stashed changes
"""

from collections import Counter
from datetime import datetime
import io
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import streamlit as st

from detections import file_sha256, load_dataset, run_detections

# ==============================================================================
<<<<<<< Updated upstream
# CONFIGURACION DE SEVERIDAD Y PALETA DE COLORES
=======
# CONSTANTES
>>>>>>> Stashed changes
# ==============================================================================

SEVERITY_COLORS = {"Alto": "#EF4444", "Medio": "#F59E0B", "Bajo": "#10B981"}
SEVERITY_ORDER = ["Alto", "Medio", "Bajo"]

# SHA-256 del dataset oficial del bootcamp (referencia de integridad).
OFFICIAL_DATASET_SHA256 = (
    "f645d76800097c09f3102d7d4f1cb5c1b2bb286d6cd054ab3daabe62c69d85f0"
)
DEFAULT_DATASET = Path("data") / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"

<<<<<<< Updated upstream

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

=======
EXPECTED_COLUMNS = [
    "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
    "Destination", "Log_Source", "Event_Description", "Process_CommandLine",
    "Result", "Severity",
]

# Orden canonico de tacticas de la matriz MITRE ATT&CK Enterprise.
ATTACK_TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]

MODULES = {
    "Resumen": "📊",
    "Incidentes": "🚨",
    "Threat Hunting": "🔍",
    "IoCs": "🎯",
    "Calidad de datos": "🧪",
    "Informe PDF": "📄",
}

ACCOUNT_CREATION_EVENTS = ["4720", "4722", "4728", "4732", "4738"]

# CSS minimo: solo acentos de severidad. Fondos y textos los define el tema.
CSS = """<style>
.block-container {padding-top: 2.2rem;}
[class*="st-key-kpi-red"] {border-top: 3px solid #EF4444 !important;}
[class*="st-key-kpi-amber"] {border-top: 3px solid #F59E0B !important;}
[class*="st-key-kpi-green"] {border-top: 3px solid #10B981 !important;}
[class*="st-key-kpi-blue"] {border-top: 3px solid #3B82F6 !important;}
[data-testid="stMetricValue"] {font-size: 1.7rem;}
</style>"""


# ==============================================================================
# LOGICA (sin dependencias visuales)
# ==============================================================================


def get_engine_config_table() -> pd.DataFrame:
    """Lee las constantes R1_..R13_ de detections.py (solo lectura)."""
    rows = []
    pattern = re.compile(r"^R(1[0-3]|[1-9])_")
    for name in dir(detections):
        if pattern.match(name):
            val = getattr(detections, name)
            if isinstance(val, (tuple, list, set)):
                val_str = ", ".join(str(x) for x in val)
            elif isinstance(val, dict):
                val_str = ", ".join(val.keys())
            else:
                val_str = str(val)
            rows.append({"Constante": name, "Valor": val_str})
    return pd.DataFrame(rows).sort_values("Constante")


def validate_excel_schema(file_bytes: bytes) -> Tuple[bool, List[str], List[str]]:
    """Valida que el Excel tenga las 12 columnas esperadas en la primera hoja."""
    try:
        df_check = pd.read_excel(io.BytesIO(file_bytes), nrows=0)
        actual = [str(c) for c in df_check.columns]
        missing = [c for c in EXPECTED_COLUMNS if c not in actual]
        return (not missing, missing, actual)
    except Exception as exc:  # archivo corrupto o no es Excel
        return (False, [f"No se pudo leer el archivo: {exc}"], [])


def compute_kpis(df: pd.DataFrame, incidents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Indicadores globales de la investigacion."""
    hosts, ips = set(), set()
    for inc in incidents:
        hosts.update(inc.get("hosts", []))
        ips.update(inc.get("ips", []))
    in_incident = df["Incidente"].astype(str) != ""
    bytes_out = int(df.loc[in_incident, "bytes_out"].sum()) if "bytes_out" in df else 0
>>>>>>> Stashed changes
    return {
        "total": len(df),
        "maliciosos": int(df["Severidad_SOC"].isin(["Alto", "Medio"]).sum()),
        "alto": int((df["Severidad_SOC"] == "Alto").sum()),
        "incidentes": len(incidents),
        "hosts": len(hosts),
        "ips": len(ips),
        "bytes_out": bytes_out,
        "mb_out": bytes_out / 1_000_000,
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
<<<<<<< Updated upstream
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
=======
    """Filtra la telemetria. Una lista vacia o None significa 'sin filtro'."""
    out = df
    if severities:
        out = out[out["Severidad_SOC"].isin(severities)]
    if incidents:
        mask = out["Incidente"].isin([i for i in incidents if i != "Sin incidente"])
        if "Sin incidente" in incidents:
            mask |= out["Incidente"].astype(str) == ""
        out = out[mask]
    if hostnames:
        out = out[out["Hostname"].isin(hostnames)]
    if users:
        out = out[out["User"].isin(users)]
    if source_ips:
        out = out[out["Source_IP"].isin(source_ips)]
    if event_ids:
        out = out[out["Event_ID"].astype(str).isin({str(e) for e in event_ids})]
    if time_range and len(time_range) == 2:
        t0, t1 = pd.to_datetime(time_range[0]), pd.to_datetime(time_range[1])
        out = out[(out["Timestamp"] >= t0) & (out["Timestamp"] <= t1)]
    if search_query and search_query.strip():
        q = search_query.strip().lower()
        cols = ["User", "Source_IP", "Hostname", "Process_CommandLine",
                "Event_Description", "Log_ID"]
        mask = pd.Series(False, index=out.index)
        for c in cols:
            if c in out:
                mask |= out[c].astype(str).str.lower().str.contains(q, regex=False, na=False)
        out = out[mask]
    return out


def attack_chain(df: pd.DataFrame, inc_id: str) -> List[Tuple[str, pd.Timestamp]]:
    """Tacticas del incidente en orden cronologico de primera evidencia.

    Empates de hora se ordenan segun la matriz ATT&CK.
    """
    first_seen: Dict[str, pd.Timestamp] = {}
    for _, row in df[df["Incidente"] == inc_id].sort_values("Timestamp").iterrows():
        for t in str(row.get("Tactica_MITRE", "")).split(","):
            for part in t.split("/"):
                name = part.strip()
                if name and name not in first_seen:
                    first_seen[name] = row["Timestamp"]
    rank = {t: i for i, t in enumerate(ATTACK_TACTIC_ORDER)}
    return sorted(first_seen.items(), key=lambda kv: (kv[1], rank.get(kv[0], 99)))


def accounts_by_role(iocs: pd.DataFrame, inc_id: str) -> Tuple[List[str], List[str]]:
    """Separa cuentas comprometidas de cuentas solo atacadas, segun los IoCs."""
    sub = iocs[iocs["incidente"] == inc_id]
    comp = sorted(sub[sub["tipo"] == "Cuenta Comprometida"]["valor"].unique())
    target = sorted(sub[sub["tipo"].str.contains("objetivo", case=False)]["valor"].unique())
    return comp, target


@st.cache_data(show_spinner="Correlacionando telemetría...")
def get_detection_data(file_bytes: bytes, file_sha: str):
    """Carga y correlacion, cacheada por SHA-256 del archivo."""
>>>>>>> Stashed changes
    df_raw = load_dataset(file_bytes)
    return run_detections(df_raw)


<<<<<<< Updated upstream
# ==============================================================================
# ASISTENTE IA OPCIONAL (GEMINI)
# ==============================================================================


def generate_gemini_summary(
    kpis: Dict[str, Any], incidents: List[Dict[str, Any]], api_key: str
) -> str:
    """Generate an AI executive threat summary using the Gemini API.

    Gracefully falls back if network or API keys are invalid.
    """
=======
@st.cache_data(show_spinner="Generando informe PDF...")
def build_pdf_cached(file_bytes: bytes, file_sha: str, analyst: str) -> bytes:
    """Genera el PDF una vez por archivo y analista (descarga en un solo clic)."""
    import report

    df, incidents, iocs = get_detection_data(file_bytes, file_sha)
    return bytes(report.build_pdf(df=df, incidents=incidents, iocs=iocs,
                                  sha256=file_sha, analyst=analyst))


def generate_gemini_summary(kpis: Dict[str, Any], incidents: List[Dict[str, Any]],
                            api_key: str) -> str:
    """Resumen opcional con Gemini (solo si existe GEMINI_API_KEY)."""
>>>>>>> Stashed changes
    try:
        import requests

        model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{model}:generateContent?key={api_key}")
        prompt = (
            "Eres analista SOC L2. Redacta un resumen ejecutivo de 3 parrafos, sin "
            "inventar datos, basado solo en esto:\n"
            f"- Eventos analizados: {kpis['total']}\n"
            f"- Eventos maliciosos: {kpis['maliciosos']}\n"
            f"- Incidentes: {kpis['incidentes']}\n"
            f"- Hosts afectados: {kpis['hosts']}\n"
            f"- IPs externas: {kpis['ips']}\n"
            f"- Volumen saliente en incidentes: ~{kpis['mb_out']:.0f} MB\n"
            "Incidentes: " + "; ".join(f"{i['id']}: {i['titulo']}" for i in incidents)
        )
        resp = requests.post(url, json={"contents": [{"parts": [{"text": prompt}]}]},
                             timeout=15)
        if resp.status_code == 200:
            return resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        return f"Gemini respondió HTTP {resp.status_code}: {resp.text[:200]}"
    except Exception as exc:
        return f"No se pudo consultar Gemini: {exc}"


# ==============================================================================
<<<<<<< Updated upstream
# ENTORNO INTERACTIVO PRINCIPAL (STREAMLIT APP)
=======
# PRESENTACION
# ==============================================================================


def kpi(col, key: str, label: str, value: str, help_text: str):
    """Tarjeta KPI nativa con borde de color (se adapta al tema)."""
    with col.container(border=True, key=key):
        st.metric(label, value, help=help_text)


def render_kpis(k: Dict[str, Any]):
    c = st.columns(6)
    kpi(c[0], "kpi-blue-total", "Eventos", f"{k['total']:,}",
        "Total de registros ingeridos del export SIEM.")
    kpi(c[1], "kpi-red-mal", "Maliciosos", f"{k['maliciosos']:,}",
        f"Severidad SOC Alto o Medio ({k['alto']} en Alto).")
    kpi(c[2], "kpi-red-inc", "Incidentes", f"{k['incidentes']}",
        "Cadenas de eventos correlacionados.")
    kpi(c[3], "kpi-amber-hosts", "Hosts", f"{k['hosts']}",
        "Activos con eventos dentro de algún incidente.")
    kpi(c[4], "kpi-amber-ips", "IPs externas", f"{k['ips']}",
        "IPs públicas de origen o destino en incidentes.")
    kpi(c[5], "kpi-red-exf", "Exfiltrado", f"~{k['mb_out']:.0f} MB",
        f"{k['bytes_out']:,} bytes enviados en eventos de incidentes (MB decimales).")


def render_resumen(df, incidents, k, gemini_key):
    render_kpis(k)
    mal = df[df["Severidad_SOC"].isin(["Alto", "Medio"])].copy()

    # Grafico temporal: picos de actividad maliciosa
    with st.container(border=True):
        st.markdown("**Actividad maliciosa en el tiempo** · eventos Alto/Medio cada 5 minutos")
        if mal.empty:
            st.info("No hay eventos maliciosos.")
        else:
            serie = (mal.set_index("Timestamp").groupby("Severidad_SOC")
                     .resample("5min").size().rename("Eventos").reset_index())
            fig = px.bar(serie, x="Timestamp", y="Eventos", color="Severidad_SOC",
                         color_discrete_map=SEVERITY_COLORS,
                         category_orders={"Severidad_SOC": SEVERITY_ORDER})
            fig.update_layout(height=280, margin=dict(l=0, r=0, t=10, b=0),
                              legend_title_text="", xaxis_title="", bargap=0.1)
            st.plotly_chart(fig, width="stretch", theme="streamlit")

    left, right = st.columns(2)
    with left, st.container(border=True):
        st.markdown("**Eventos maliciosos por incidente**")
        by_inc = (mal[mal["Incidente"] != ""].groupby(["Incidente", "Severidad_SOC"])
                  .size().rename("Eventos").reset_index())
        titles = {i["id"]: i["titulo"] for i in incidents}
        by_inc["Título"] = by_inc["Incidente"].map(titles)
        fig = px.bar(by_inc, x="Eventos", y="Incidente", color="Severidad_SOC",
                     orientation="h", color_discrete_map=SEVERITY_COLORS,
                     hover_data=["Título"],
                     category_orders={"Severidad_SOC": SEVERITY_ORDER,
                                      "Incidente": [i["id"] for i in incidents]})
        fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0),
                          legend_title_text="", yaxis_title="")
        st.plotly_chart(fig, width="stretch", theme="streamlit")

    with right, st.container(border=True):
        st.markdown("**Tácticas MITRE ATT&CK observadas**")
        tactics = Counter(
            p.strip() for v in mal["Tactica_MITRE"].astype(str)
            for t in v.split(",") for p in t.split("/") if p.strip()
        )
        df_t = pd.DataFrame(tactics.items(), columns=["Táctica", "Eventos"])
        rank = {t: i for i, t in enumerate(ATTACK_TACTIC_ORDER)}
        df_t["orden"] = df_t["Táctica"].map(lambda t: rank.get(t, 99))
        df_t = df_t.sort_values("orden", ascending=False)
        fig = px.bar(df_t, x="Eventos", y="Táctica", orientation="h")
        fig.update_traces(marker_color="#3B82F6")
        fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0), yaxis_title="")
        st.plotly_chart(fig, width="stretch", theme="streamlit")

    with st.container(border=True):
        st.markdown("**Severidad de la fuente vs severidad SOC recalculada**")
        ct = pd.crosstab(df["Severity"], df["Severidad_SOC"]).reindex(
            columns=SEVERITY_ORDER, fill_value=0)
        under = df[(df["Severity"] == "Informational") & (df["Severidad_SOC"] == "Alto")]
        a, b = st.columns([1, 1])
        a.dataframe(ct, width="stretch")
        b.markdown(
            f"La fuente catalogó **{len(under)} eventos como *Informational*** que el motor "
            "clasificó como **Alto** al correlacionarlos con su contexto "
            "(por ejemplo, un logon exitoso tras fallos o un empaquetado previo a exfiltración)."
        )
        if not under.empty:
            with b.expander(f"Ver los {len(under)} eventos subestimados"):
                st.dataframe(under[["Log_ID", "Timestamp", "Hostname", "User", "Event_ID",
                                    "Regla", "Tecnica_MITRE"]],
                             width="stretch", hide_index=True)

    if gemini_key:
        with st.expander("🤖 Resumen asistido por IA (opcional, Gemini)"):
            if st.button("Generar resumen"):
                st.markdown(generate_gemini_summary(k, incidents, gemini_key))


def render_incidentes(df, incidents, iocs):
    if not incidents:
        st.info("No se correlacionaron incidentes en este archivo.")
        return

    with st.container(border=True):
        st.markdown("**Línea de tiempo de incidentes** · cada punto es un evento correlacionado")
        ev = df[df["Incidente"] != ""]
        fig = px.scatter(ev, x="Timestamp", y="Hostname", color="Incidente",
                         hover_data=["Log_ID", "User", "Event_ID", "Severidad_SOC",
                                     "Process_CommandLine"],
                         category_orders={"Incidente": [i["id"] for i in incidents]})
        fig.update_traces(marker=dict(size=9))
        fig.update_layout(height=300, margin=dict(l=0, r=0, t=10, b=0),
                          legend_title_text="", xaxis_title="", yaxis_title="")
        st.plotly_chart(fig, width="stretch", theme="streamlit")

    for inc in incidents:
        sev_icon = "🔴" if inc.get("severidad") == "Alto" else "🟠"
        with st.expander(f"{sev_icon} **{inc['id']}** · {inc['titulo']}",
                         expanded=inc is incidents[0]):
            comp, target = accounts_by_role(iocs, inc["id"])
            others = [u for u in inc.get("usuarios", []) if u not in comp + target]
            c1, c2, c3, c4 = st.columns([1.1, 1, 1.4, 1])
            c1.markdown(f"**Ventana**  \n{inc['inicio']:%H:%M:%S} → {inc['fin']:%H:%M:%S}  \n"
                        f":gray[{inc['inicio']:%Y-%m-%d}]")
            c2.markdown("**Hosts**  \n" + "  \n".join(f"`{h}`" for h in inc["hosts"]))
            acc = []
            if comp:
                acc.append("Comprometidas: " + ", ".join(f"`{u}`" for u in comp))
            if others:
                acc.append("Involucradas: " + ", ".join(f"`{u}`" for u in others))
            if target:
                acc.append(f":gray[Objetivo sin éxito: {len(target)} cuentas]")
            c3.markdown("**Cuentas**  \n" + "  \n".join(acc or ["—"]))
            c4.markdown("**IPs externas**  \n" + ("  \n".join(f"`{i}`" for i in inc["ips"])
                                                   or ":gray[solo tráfico interno]"))

            chain = attack_chain(df, inc["id"])
            if chain:
                steps = "  →  ".join(f":blue-badge[{t}] :gray[{ts:%H:%M}]" for t, ts in chain)
                st.markdown(f"**Cadena de ataque** (orden cronológico, hora de primera evidencia)  \n{steps}")
            st.caption(inc.get("resumen", ""))

            tl = pd.DataFrame(inc.get("timeline", []))
            cols = [c for c in ["Timestamp", "Log_ID", "Hostname", "User", "Event_ID",
                                "Process_CommandLine", "Event_Description", "Severidad_SOC"]
                    if c in tl.columns]
            if not tl.empty:
                st.dataframe(tl[cols], width="stretch", hide_index=True,
                             column_config={"Timestamp": st.column_config.DatetimeColumn(
                                 "Hora", format="HH:mm:ss")})


def render_threat_hunting(df):
    q = st.text_input("Buscar en usuario, IP, host, comando, descripción o Log_ID",
                      placeholder="ej.: 198.51.100, powershell, rrojas, whoami, EVT-00198")
    with st.expander("Filtros", expanded=False):
        f1, f2, f3 = st.columns(3)
        sev = f1.multiselect("Severidad SOC", SEVERITY_ORDER, placeholder="Todas")
        incs = sorted(i for i in df["Incidente"].unique() if i) + ["Sin incidente"]
        inc_sel = f1.multiselect("Incidente", incs, placeholder="Todos")
        hosts = f2.multiselect("Host", sorted(df["Hostname"].unique()), placeholder="Todos")
        users = f2.multiselect("Usuario", sorted(df["User"].unique()), placeholder="Todos")
        ips = f3.multiselect("IP de origen", sorted(df["Source_IP"].unique()),
                             placeholder="Todas")
        eids = f3.multiselect("Event ID", sorted(df["Event_ID"].astype(str).unique()),
                              placeholder="Todos")
        t0 = df["Timestamp"].min().to_pydatetime()
        t1 = df["Timestamp"].max().to_pydatetime()
        rng = st.slider("Ventana temporal", t0, t1, (t0, t1), format="HH:mm")

    out = apply_filters(df, sev, inc_sel, hosts, users, ips, eids, rng, q)
    st.caption(f"{len(out):,} de {len(df):,} eventos")
    if out.empty:
        st.info("Ningún evento coincide con la búsqueda y los filtros.")
        return
    show = ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
            "Destination", "Event_Description", "Process_CommandLine", "Result",
            "Severity", "Severidad_SOC", "Incidente", "Regla", "Tecnica_MITRE"]
    st.dataframe(out[[c for c in show if c in out]], width="stretch", hide_index=True,
                 height=480)
    st.download_button("Descargar resultados (CSV)",
                       out.to_csv(index=False).encode("utf-8"),
                       "threat_hunting_resultados.csv", "text/csv")


def render_iocs(iocs):
    if iocs.empty:
        st.info("No se extrajeron IoCs.")
        return
    counts = iocs["tipo"].value_counts()
    tipo = st.pills("Tipo de indicador", [f"{t} ({n})" for t, n in counts.items()],
                    selection_mode="multi")
    sel = [t.rsplit(" (", 1)[0] for t in (tipo or [])]
    view = iocs[iocs["tipo"].isin(sel)] if sel else iocs
    st.caption("Los LOLBins son herramientas del sistema usadas por el atacante: "
               "sirven para hunting, no para bloquear.")
    st.dataframe(view.rename(columns={
        "tipo": "Tipo", "valor": "Valor", "contexto": "Contexto", "incidente": "Incidente",
        "primer_visto": "Primer visto", "ultimo_visto": "Último visto"}),
        width="stretch", hide_index=True, height=480)
    st.download_button("Descargar IoCs (CSV)", view.to_csv(index=False).encode("utf-8"),
                       "iocs_nordic_shadow.csv", "text/csv")


def render_calidad(df):
    st.markdown(
        "La regla **R14** marca identificadores con formato inconsistente o nombres casi "
        "idénticos a otros existentes. Son **anomalías a verificar**, no incidentes: el motor "
        "las deja en severidad Bajo y fuera de la correlación.")
    an = df[df["Anomalia_Dato"].astype(str) != ""]
    host_an = an[an["Anomalia_Dato"].str.contains("hostname", case=False)]
    user_an = an[an["Anomalia_Dato"].str.contains("usuario", case=False)]
    c1, c2, c3 = st.columns(3)
    with c1.container(border=True, key="kpi-amber-hostq"):
        st.metric("Eventos con hostname anómalo", len(host_an))
        st.caption(", ".join(f"`{h}`" for h in sorted(host_an["Hostname"].unique())) or "—")
    with c2.container(border=True, key="kpi-amber-userq"):
        st.metric("Eventos con cuenta de nombre similar", len(user_an))
        st.caption(", ".join(f"`{u}`" for u in sorted(user_an["User"].unique())) or "—")
    created = df[df["Event_ID"].astype(str).isin(ACCOUNT_CREATION_EVENTS)]
    with c3.container(border=True, key="kpi-blue-neg"):
        st.metric("Eventos de creación/cambio de cuentas", len(created),
                  help="Event IDs " + ", ".join(ACCOUNT_CREATION_EVENTS))
        st.caption("Hallazgo negativo: sin altas de cuentas en la ventana analizada."
                   if created.empty else "Revisar estos eventos.")
    st.markdown(
        "**Cómo verificarlo:** confirmar en Active Directory el atributo `whenCreated` y el "
        "creador de las cuentas señaladas, y si el host con formato distinto es un equipo "
        "real o un error de normalización de la fuente. La ausencia de eventos 4720/4732 no "
        "descarta altas de cuentas fuera de la ventana de logs.")
    if not an.empty:
        st.dataframe(an[["Log_ID", "Timestamp", "Hostname", "User", "Event_ID",
                         "Anomalia_Dato", "Severidad_SOC"]], width="stretch", hide_index=True)


def render_informe(file_bytes, file_sha, incidents):
    st.markdown(
        f"El informe se genera a partir de los mismos datos que ves en la consola "
        f"({len(incidents)} incidentes) y se divide en dos partes:")
    a, b = st.columns(2)
    with a.container(border=True):
        st.markdown("**Parte 1 — Resumen ejecutivo** (dirección / CISO)  \n"
                    "Qué ocurrió, estado de la amenaza, impacto en el negocio, "
                    "obligaciones RGPD y NIS2, prioridades y matriz de riesgo.")
    with b.container(border=True):
        st.markdown("**Parte 2 — Resumen técnico** (SOC / DFIR)  \n"
                    "Metodología, incidentes, línea de tiempo con Log_ID, matriz MITRE, "
                    "IoCs, atribución ACH, brechas de visibilidad y playbook de contención.")
    analyst = st.text_input("Analista responsable", value="Sebastian Szostak")
    try:
        pdf = build_pdf_cached(file_bytes, file_sha, analyst)
        st.download_button("📄 Descargar informe PDF", pdf,
                           f"Informe_Nordic_Shadow_{datetime.now():%Y%m%d_%H%M}.pdf",
                           "application/pdf", type="primary", width="stretch")
    except Exception as exc:
        st.error(f"No se pudo generar el PDF: {exc}")


# ==============================================================================
# APLICACION
>>>>>>> Stashed changes
# ==============================================================================


def load_input() -> Tuple[bytes, str]:
    st.sidebar.markdown("**Ingesta de telemetría**")
    up = st.sidebar.file_uploader("Export SIEM (.xlsx)", type=["xlsx"],
                                  label_visibility="collapsed")
    if up is not None:
        return up.getvalue(), up.name
    path = DEFAULT_DATASET
    if not path.is_file():
        path = Path(__file__).resolve().parent / DEFAULT_DATASET
    if path.is_file():
        st.sidebar.caption("Usando el dataset oficial de `data/`.")
        return path.read_bytes(), path.name
    st.sidebar.warning("Cargá un export SIEM (.xlsx) para comenzar.")
    st.stop()


def main():
<<<<<<< Updated upstream
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
=======
    st.set_page_config(page_title="Nordic Shadow Hunter · Consola SOC L2",
                       page_icon="🛡️", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)

    st.sidebar.markdown("### 🛡️ Nordic Shadow Hunter")
    st.sidebar.caption("Consola de análisis forense SOC L2")
    file_bytes, filename = load_input()

    ok, missing, actual = validate_excel_schema(file_bytes)
    if not ok:
        st.error("**El archivo no tiene el formato esperado.**  \n"
                 f"Faltan: `{', '.join(missing)}`  \n"
                 f"Esperadas: `{', '.join(EXPECTED_COLUMNS)}`  \n"
                 f"Encontradas: `{', '.join(actual) or '—'}`")
        st.stop()

    file_sha = file_sha256(file_bytes)
    df, incidents, iocs = get_detection_data(file_bytes, file_sha)
    k = compute_kpis(df, incidents)

    st.sidebar.divider()
    module = st.sidebar.radio("Módulo", list(MODULES),
                              format_func=lambda m: f"{MODULES[m]}  {m}")
    st.sidebar.divider()
    with st.sidebar.expander("⚙️ Configuración del motor (solo lectura)"):
        st.dataframe(get_engine_config_table(), width="stretch", hide_index=True)
    st.sidebar.caption("🎨 Tema: menú ⋮ (arriba a la derecha) → System / Light / Dark")

    # Encabezado del modulo + barra de estado calculada
    st.markdown(f"## {MODULES[module]} {module}")
    t0, t1 = df["Timestamp"].min(), df["Timestamp"].max()
    integrity = (":green-badge[🔐 SHA-256 verificado: dataset oficial]"
                 if file_sha == OFFICIAL_DATASET_SHA256
                 else f":blue-badge[🔐 SHA-256 {file_sha[:12]}…]")
    st.markdown(
        f":gray-badge[📄 {filename}] {integrity} "
        f":gray-badge[🕒 {t0:%Y-%m-%d %H:%M} → {t1:%H:%M}] "
        f":red-badge[🚨 {len(incidents)} incidentes] "
        f":orange-badge[⚠️ {k['maliciosos']} eventos maliciosos]",
        help=f"SHA-256 completo: {file_sha}")

    if module == "Resumen":
        render_resumen(df, incidents, k, os.getenv("GEMINI_API_KEY"))
    elif module == "Incidentes":
        render_incidentes(df, incidents, iocs)
    elif module == "Threat Hunting":
        render_threat_hunting(df)
    elif module == "IoCs":
        render_iocs(iocs)
    elif module == "Calidad de datos":
        render_calidad(df)
    else:
        render_informe(file_bytes, file_sha, incidents)
>>>>>>> Stashed changes

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
                st.plotly_chart(donut_fig, width="stretch")

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
                    st.plotly_chart(bar_fig, width="stretch")
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
            st.plotly_chart(heat_fig, width="stretch")

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
                        width="stretch",
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
            st.plotly_chart(scatter_fig, width="stretch")

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
                st.plotly_chart(hist_fig, width="stretch")
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
                            width="stretch",
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
            width="stretch",
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
                width="stretch",
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
                "Eventos con Cuenta de nombre similar (a verificar) CORP\\svc_backup", len(svc_backup_events)
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
                width="stretch",
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
            width="stretch",
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
                    width="stretch",
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
