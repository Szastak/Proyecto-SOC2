"""Nordic Shadow Hunter - Consola SOC L2.

Aplicacion web para analistas SOC Nivel 2: ingesta de exportaciones SIEM,
correlacion de incidentes, cadenas de ataque MITRE ATT&CK, threat hunting,
IoCs, calidad de datos y emision del informe forense PDF.

El tema visual (Claro / Oscuro / Sistema) se define en .streamlit/config.toml
y se cambia desde el menu ⋮ de la app (System / Light / Dark). Todos los componentes usan
widgets nativos y graficos con el tema de Streamlit, por lo que se adaptan
automaticamente al tema elegido.
"""

from collections import Counter
from datetime import datetime
import io
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import streamlit as st

import detections
from detections import file_sha256, load_dataset, run_detections

# ==============================================================================
# CONSTANTES
# ==============================================================================

SEVERITY_COLORS = {"Alto": "#EF4444", "Medio": "#F59E0B", "Bajo": "#10B981"}
SEVERITY_ORDER = ["Alto", "Medio", "Bajo"]

# SHA-256 del dataset oficial del bootcamp (referencia de integridad).
OFFICIAL_DATASET_SHA256 = (
    "f645d76800097c09f3102d7d4f1cb5c1b2bb286d6cd054ab3daabe62c69d85f0"
)
DEFAULT_DATASET = Path("data") / "SOC_L2_Logs_Ampliados_Multiples_Incidentes.xlsx"

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
    search_query: Optional[str] = None,
) -> pd.DataFrame:
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
    df_raw = load_dataset(file_bytes)
    return run_detections(df_raw)


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
# PRESENTACION
# ==============================================================================


def style_time_axis(fig, height: int):
    """Eje temporal navegable desde PC: barra de desplazamiento + botones de escala."""
    fig.update_xaxes(
        rangeslider=dict(visible=True, thickness=0.09),
        rangeselector=dict(
            buttons=[
                dict(count=15, label="15 min", step="minute", stepmode="backward"),
                dict(count=30, label="30 min", step="minute", stepmode="backward"),
                dict(count=1, label="1 h", step="hour", stepmode="backward"),
                dict(label="Todo", step="all"),
            ],
            x=0, y=1.12, xanchor="left", yanchor="bottom",
            bgcolor="rgba(59,130,246,0.10)", activecolor="rgba(59,130,246,0.40)",
            bordercolor="rgba(59,130,246,0.55)", borderwidth=1,
            font=dict(color="#3B82F6"),
        ),
        title_text="",
    )
    fig.update_layout(
        height=height,
        margin=dict(l=0, r=0, t=70, b=0),
        legend=dict(orientation="h", x=0.27, y=1.12, xanchor="left", yanchor="bottom",
                    title_text=""),
        dragmode="pan",
    )
    return fig


# Barra de herramientas del grafico: sin logo y con zoom por rueda del mouse.
PLOTLY_CONFIG = {"displaylogo": False, "scrollZoom": True,
                 "modeBarButtonsToRemove": ["lasso2d", "select2d"]}


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
            fig.update_layout(bargap=0.1)
            style_time_axis(fig, 380)
            st.plotly_chart(fig, width="stretch", theme="streamlit", config=PLOTLY_CONFIG)
            st.caption("Arrastrá la barra inferior o usá los botones para recorrer la escala "
                       "de tiempo; doble clic sobre el gráfico vuelve a la vista completa.")

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
        st.plotly_chart(fig, width="stretch", theme="streamlit", config=PLOTLY_CONFIG)

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
        st.plotly_chart(fig, width="stretch", theme="streamlit", config=PLOTLY_CONFIG)

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
        fig.update_layout(yaxis_title="")
        style_time_axis(fig, 420)
        st.plotly_chart(fig, width="stretch", theme="streamlit", config=PLOTLY_CONFIG)
        st.caption("Arrastrá la barra inferior o usá los botones para recorrer la escala "
                   "de tiempo; doble clic sobre el gráfico vuelve a la vista completa.")

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


if __name__ == "__main__":
    main()
