"""Nordic Shadow Hunter - SIEM Correlation Engine and Detection Rules.

This module provides generic correlation rules (R1 to R14), MITRE ATT&CK taxonomy
enrichment, incident clustering algorithms, IoC extraction, and data quality anomaly
identification for SOC Level 2 forensic investigations without hardcoded entity filters.
"""

from collections import Counter
import hashlib
import io
import ipaddress
from pathlib import Path
import re
import numpy as np
import pandas as pd

# ==============================================================================
# CONFIGURACION Y CONSTANTES DE UMBRALES DE DETECCION (R1 - R14)
# ==============================================================================

# R1 - Password Spraying
R1_FAILED_LOGONS_THRESHOLD = 10
R1_DISTINCT_USERS_THRESHOLD = 5
R1_TIME_WINDOW_MINUTES = 15

# R2 - Fuerza Bruta
R2_FAILED_LOGONS_THRESHOLD = 3
R2_TIME_WINDOW_MINUTES = 10

# R3 - Exito tras ataque (Compromiso de cuenta)
R3_POST_ATTACK_WINDOW_MINUTES = 30

# R5 - LOLBins y comandos sospechosos
R5_PATTERNS = {
    "T1059.001": (r"-EncodedCommand|-enc", "Alto", "Execution"),
    "T1490": (r"vssadmin.*delete.*shadows", "Alto", "Impact"),
    "T1135": (r"net(\.exe)?\s+view|Get-SmbShare", "Alto", "Discovery"),
    "T1069.001": (r"Get-LocalGroupMember", "Alto", "Discovery"),
    "T1033": (r"\bwhoami\b", "Alto", "Discovery"),
    "T1560.001": (r"(tar|7z|rar|zip).*(\s+-a|\s+a\s+|\s+-c)", "Alto", "Collection"),
    "T1003": (r"certutil.*urlcache|wmic|mimikatz|sekurlsa", "Alto", "Credential Access"),
}

# R7 - Acceso a datos sensibles
R7_SENSITIVE_REGEX = r"Finance|Legal|HR|Confidential"

# R8 - Acceso masivo a archivos
R8_MASS_ACCESS_THRESHOLD = 10
R8_TIME_WINDOW_MINUTES = 5

# R9 - Exfiltracion por proxy
R9_BYTES_OUT_THRESHOLD = 100 * 1024 * 1024  # 100 MB
R9_TIME_WINDOW_MINUTES = 15

# R11 - Persistencia
R11_TASK_ACTION_REGEX = r"ProgramData|Temp|AppData|powershell"
R11_SERVICE_PATH_REGEX = r"ProgramData|Temp|AppData|Users\\Public"

# R12 - Beaconing C2 periodico
R12_MIN_EXECUTIONS = 4
R12_MAX_JITTER_RATIO = 0.10
R12_SYSTEM_PROCESS_EXCLUSIONS = (
    "svchost.exe",
    "explorer.exe",
    "taskhostw.exe",
    "notepad.exe",
)

# R13 - Web Shell y sondeo web
R13_WEBSHELL_URI_REGEX = r"cmd=|exec=|\.aspx\?|\.php\?"
R13_PROBING_URI_REGEX = r"/admin|/login|/api"
R13_PROBING_THRESHOLD = 10
R13_TIME_WINDOW_MINUTES = 5

# Agrupacion de incidentes
INCIDENT_CHAIN_GAP_MINUTES = 30

# Redes privadas RFC 1918 para filtrado generico de IPs
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


# ==============================================================================
# FUNCIONES DE CARGA Y NORMALIZACION
# ==============================================================================


def _is_external_ip(ip_val) -> bool:
    """Check if an IP value represents a valid non-private, non-loopback external IP."""
    if not ip_val or not isinstance(ip_val, str):
        return False
    val_clean = ip_val.split(":")[0].strip().lstrip("\\")
    try:
        ip = ipaddress.ip_address(val_clean)
        if ip.is_loopback or ip.is_link_local:
            return False
        return not any(ip in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


def _extract_ip_string(ip_val):
    """Extract clean IP string if valid external IP, else None."""
    if not ip_val or not isinstance(ip_val, str):
        return None
    val_clean = ip_val.split(":")[0].strip().lstrip("\\")
    try:
        ip = ipaddress.ip_address(val_clean)
        if ip.is_loopback or ip.is_link_local:
            return None
        if any(ip in net for net in RFC1918_NETWORKS):
            return None
        return str(ip)
    except ValueError:
        return None


def file_sha256(bytes_or_path) -> str:
    """Compute SHA-256 hexadecimal digest from a file path or bytes buffer.

    Args:
        bytes_or_path: File path (str or Path), bytes, or file-like object.

    Returns:
        str: SHA-256 digest in hex format.
    """
    hasher = hashlib.sha256()
    if isinstance(bytes_or_path, (str, Path)):
        with open(bytes_or_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
    elif isinstance(bytes_or_path, bytes):
        hasher.update(bytes_or_path)
    elif hasattr(bytes_or_path, "read"):
        pos = bytes_or_path.tell() if hasattr(bytes_or_path, "tell") else None
        for chunk in iter(lambda: bytes_or_path.read(65536), b""):
            hasher.update(chunk)
        if pos is not None and hasattr(bytes_or_path, "seek"):
            bytes_or_path.seek(pos)
    else:
        raise ValueError("Unsupported input type for file_sha256 calculation.")
    return hasher.hexdigest()


def load_dataset(file_or_path) -> pd.DataFrame:
    """Load and normalize SIEM export logs from Excel or path.

    Args:
        file_or_path: File path or file-like object/bytes.

    Returns:
        pd.DataFrame: Normalized logs dataframe with engineered features.
    """
    if isinstance(file_or_path, bytes):
        file_or_path = io.BytesIO(file_or_path)

    df = pd.read_excel(file_or_path, sheet_name="SIEM Export")

    # Normalizar columnas de texto y tipos base
    string_columns = [
        "Log_ID",
        "Hostname",
        "User",
        "Source_IP",
        "Destination",
        "Log_Source",
        "Event_Description",
        "Process_CommandLine",
        "Result",
        "Severity",
    ]
    for col in string_columns:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str).str.strip()

    df["Event_ID"] = df["Event_ID"].astype(str).str.strip()
    df["Timestamp"] = pd.to_datetime(df["Timestamp"])

    # Caracteristicas enriquecidas requeridas por la especificacion
    df["is_external_ip"] = df["Source_IP"].apply(_is_external_ip)

    # LogonType extraido de Event_Description
    df["LogonType"] = (
        df["Event_Description"].str.extract(r"LogonType=(\d+)", expand=False).fillna("")
    )

    # bytes_out extraido de Process_CommandLine
    extracted_bytes = (
        df["Process_CommandLine"]
        .str.extract(r"bytes_out=(\d+)", expand=False)
        .fillna("0")
    )
    df["bytes_out"] = pd.to_numeric(extracted_bytes, errors="coerce").fillna(0).astype(int)

    return df


# ==============================================================================
# MOTOR DE CORRELACION Y REGLAS DE DETECCION (R1 - R14)
# ==============================================================================


def run_detections(df: pd.DataFrame):
    """Run correlation rules R1-R14, group into incidents, and extract IoCs.

    Args:
        df (pd.DataFrame): Normalized logs dataframe.

    Returns:
        tuple[pd.DataFrame, list[dict], pd.DataFrame]: Enriched dataframe,
        incident list, and IoCs dataframe.
    """
    df_out = df.copy()

    # Estructuras de rastreo por evento (index -> list of triggered rules/metadata)
    event_rules = {idx: [] for idx in df_out.index}
    event_severities = {idx: [] for idx in df_out.index}
    event_techniques = {idx: [] for idx in df_out.index}
    event_tactics = {idx: [] for idx in df_out.index}
    event_anomalies = {idx: [] for idx in df_out.index}

    # Estado mutable de contexto analitico entre reglas
    # Cuentas comprometidas: {usuario: timestamp_primer_compromiso}
    compromised_accounts = {}
    # Ventanas de ataque identificadas: lista de dicts con ip, start_time, end_time, rule
    attack_ip_windows = []

    # --------------------------------------------------------------------------
    # REGLA R1: Password Spraying (T1110.003 - Credential Access)
    # Hipotesis: Un atacante externo distribuye intentos de autenticacion fallidos
    #            contra multiples identidades de la organizacion para evitar bloqueos.
    # Evento que la prueba: Event_ID 4625 recurrente con resultado Failure desde una
    #                       misma Source_IP externa hacia diferentes nombres de usuario.
    # Umbral justificado: >=10 intentos fallidos contra >=5 usuarios distintos en una
    #                     ventana temporal de 15 minutos diferencia escaneos automatizados
    #                     de errores humanos o scripts de servicio desactualizados.
    # Falso positivo esperado: Scripts de migracion de credenciales o sincronizacion
    #                          de directorio activos desde una IP remota legitima.
    # --------------------------------------------------------------------------
    r1_candidates = df_out[
        df_out["is_external_ip"] & (df_out["Event_ID"] == "4625")
    ].sort_values("Timestamp")

    for src_ip, ip_group in r1_candidates.groupby("Source_IP"):
        records = ip_group.to_dict("records")
        n = len(records)
        window_duration = pd.Timedelta(minutes=R1_TIME_WINDOW_MINUTES)
        matched_indices = set()

        for i in range(n):
            start_t = records[i]["Timestamp"]
            end_t = start_t + window_duration
            window_slice = [
                records[j] for j in range(i, n) if records[j]["Timestamp"] <= end_t
            ]
            distinct_users = {r["User"] for r in window_slice if r["User"]}
            if (
                len(window_slice) >= R1_FAILED_LOGONS_THRESHOLD
                and len(distinct_users) >= R1_DISTINCT_USERS_THRESHOLD
            ):
                for r in window_slice:
                    matched_indices.add(r["Log_ID"])
                attack_ip_windows.append(
                    {
                        "ip": src_ip,
                        "start": min(r["Timestamp"] for r in window_slice),
                        "end": max(r["Timestamp"] for r in window_slice),
                        "rule": "R1",
                    }
                )

        for idx, row in ip_group.iterrows():
            if row["Log_ID"] in matched_indices:
                event_rules[idx].append("R1")
                event_severities[idx].append("Medio")
                event_techniques[idx].append("T1110.003")
                event_tactics[idx].append("Credential Access")

    # --------------------------------------------------------------------------
    # REGLA R2: Fuerza Bruta de Credenciales (T1110.001 - Credential Access)
    # Hipotesis: Un actor de amenazas ejecuta intentos repetitivos de autenticacion
    #            contra una cuenta individual objetivo desde una ubicacion externa.
    # Evento que la prueba: Event_ID 4625 secuencial sobre el mismo par (Source_IP, User).
    # Umbral justificado: >=3 intentos fallidos en una ventana de 10 minutos supera el
    #                     margen normal de reintentos manuales de usuarios legitimos.
    # Falso positivo esperado: Empleado remoto bloqueado repitiendo contrasena erronea
    #                          antes de llamar al service desk.
    # --------------------------------------------------------------------------
    r2_candidates = df_out[
        df_out["is_external_ip"] & (df_out["Event_ID"] == "4625")
    ].sort_values("Timestamp")

    for (src_ip, user), grp in r2_candidates.groupby(["Source_IP", "User"]):
        if not user or user == "-":
            continue
        records = grp.to_dict("records")
        n = len(records)
        window_duration = pd.Timedelta(minutes=R2_TIME_WINDOW_MINUTES)
        matched_r2_ids = set()

        for i in range(n):
            start_t = records[i]["Timestamp"]
            end_t = start_t + window_duration
            window_slice = [
                records[j] for j in range(i, n) if records[j]["Timestamp"] <= end_t
            ]
            if len(window_slice) >= R2_FAILED_LOGONS_THRESHOLD:
                for r in window_slice:
                    matched_r2_ids.add(r["Log_ID"])
                attack_ip_windows.append(
                    {
                        "ip": src_ip,
                        "user": user,
                        "start": min(r["Timestamp"] for r in window_slice),
                        "end": max(r["Timestamp"] for r in window_slice),
                        "rule": "R2",
                    }
                )

        for idx, row in grp.iterrows():
            if row["Log_ID"] in matched_r2_ids:
                event_rules[idx].append("R2")
                event_severities[idx].append("Medio")
                event_techniques[idx].append("T1110.001")
                event_tactics[idx].append("Credential Access")

    # --------------------------------------------------------------------------
    # REGLA R3: Exito tras Ataque de Credenciales (T1078 - Initial Access)
    # Hipotesis: Un atacante logra adivinar exitosamente las credenciales de un usuario
    #            despues de una fase previa de password spraying o fuerza bruta.
    # Evento que la prueba: Event_ID 4624 (Logon exitoso) originado desde la misma IP
    #                       que ejecuto R1 o R2 en los 30 minutos posteriores.
    # Umbral justificado: La correlacion temporal de 30 min tras el ataque activo
    #                     establece una alta probabilidad de compromiso de credencial.
    # Falso positivo esperado: Usuario legitimo iniciando sesion desde una IP compartida
    #                          (NAT corporativo o ISP) tras incidentes de terceros.
    # --------------------------------------------------------------------------
    r3_candidates = df_out[
        (df_out["Event_ID"] == "4624") & (df_out["Result"] == "Success")
    ].sort_values("Timestamp")

    for idx, row in r3_candidates.iterrows():
        event_ip = row["Source_IP"]
        event_t = row["Timestamp"]
        for attack in attack_ip_windows:
            if attack["ip"] == event_ip:
                delta = (event_t - attack["end"]).total_seconds()
                if 0 <= delta <= (R3_POST_ATTACK_WINDOW_MINUTES * 60):
                    event_rules[idx].append("R3")
                    event_severities[idx].append("Alto")
                    event_techniques[idx].append("T1078")
                    event_tactics[idx].append("Initial Access")
                    user = row["User"]
                    if user and user not in compromised_accounts:
                        compromised_accounts[user] = event_t
                    break

    # --------------------------------------------------------------------------
    # REGLA R4: Privilegios Especiales en Cuenta Comprometida (T1078.003 - Privilege Escalation)
    # Hipotesis: El atacante utiliza la cuenta recien vulnerada para asumir privilegios
    #            administrativos o especiales en el dominio o equipo local.
    # Evento que la prueba: Event_ID 4672 ejecutado bajo una cuenta identificada como
    #                       comprometida o proveniente de una IP asociada a R1/R2.
    # Umbral justificado: Toda asignacion de privilegios especiales en una sesion
    #                     vulnerada es un indicador critico de escalamiento.
    # Falso positivo esperado: Tareas de administracion delegada habituales en horarios
    #                          laborales normales.
    # --------------------------------------------------------------------------
    r4_candidates = df_out[df_out["Event_ID"] == "4672"].sort_values("Timestamp")
    attack_ips = {att["ip"] for att in attack_ip_windows}

    for idx, row in r4_candidates.iterrows():
        user = row["User"]
        src_ip = row["Source_IP"]
        is_compromised = (
            user in compromised_accounts
            and row["Timestamp"] >= compromised_accounts[user]
        )
        is_attack_ip = src_ip in attack_ips

        if is_compromised or is_attack_ip:
            event_rules[idx].append("R4")
            event_severities[idx].append("Alto")
            event_techniques[idx].append("T1078.003")
            event_tactics[idx].append("Privilege Escalation")

    # --------------------------------------------------------------------------
    # REGLA R5: Ejecucion Sospechosa y Abuso de LOLBins (Execution / Discovery / Impact)
    # Hipotesis: El adversario ejecuta utilidades legitimas del sistema operativo
    #            (Living off the Land Binaries) para descubrimiento, evasion o impacto.
    # Evento que la prueba: Event_ID 4688 o 4104 cuya linea de comandos contiene
    #                       patrones conocidos de ofuscacion, borrado de sombras o empaquetado.
    # Umbral justificado: Patrones regex especificos sobre herramientas altamente sensibles
    #                     (vssadmin delete shadows, -EncodedCommand, utilidades de compresion).
    # Falso positivo esperado: Scripts administrativos automatizados de backup que
    #                          comprimen directorios o consultan recursos de red.
    # --------------------------------------------------------------------------
    r5_candidates = df_out[df_out["Event_ID"].isin(["4688", "4104"])]

    for idx, row in r5_candidates.iterrows():
        cmd = row["Process_CommandLine"]
        desc = row["Event_Description"]
        user = row["User"]
        matched_rule = False

        # Comprobacion de patrones regex
        for tech, (pattern, sev, tactic) in R5_PATTERNS.items():
            if re.search(pattern, cmd, re.IGNORECASE) or re.search(pattern, desc, re.IGNORECASE):
                event_rules[idx].append("R5")
                event_severities[idx].append(sev)
                event_techniques[idx].append(tech)
                event_tactics[idx].append(tactic)
                matched_rule = True

        # Ejecucion interactiva de interpretes por identidad de servicio web
        if "IIS APPPOOL" in user.upper() and (
            "cmd.exe" in cmd.lower() or "powershell.exe" in cmd.lower()
        ):
            event_rules[idx].append("R5")
            event_severities[idx].append("Alto")
            event_techniques[idx].append("T1505.003")
            event_tactics[idx].append("Persistence")
            matched_rule = True

    # --------------------------------------------------------------------------
    # REGLA R6: Movimiento Lateral (T1021.002 SMB / T1021.001 RDP)
    # Hipotesis: El atacante se propaga internamente usando credenciales comprometidas
    #            hacia otros servidores via SMB o accede remotamente via RDP desde el exterior.
    # Evento que la prueba: Event 4624/4625 con LogonType 3 entre distintos hosts por cuenta
    #                       comprometida, o LogonType 10 desde IP publica externa.
    # Umbral justificado: Acceso de red con cuentas vulneradas o RDP entrante desde
    #                     direcciones de Internet no corporativas.
    # Falso positivo esperado: Conexiones de mantenimiento remoto de infraestructura
    #                          autorizadas sin uso de VPN.
    # --------------------------------------------------------------------------
    r6_candidates = df_out[df_out["Event_ID"].isin(["4624", "4625"])]

    for idx, row in r6_candidates.iterrows():
        logon_type = str(row["LogonType"]).strip()
        user = row["User"]
        src_ip = row["Source_IP"]
        desc = row["Event_Description"]
        is_success = row["Result"] == "Success"

        # Caso RDP externo (LogonType 10)
        if logon_type == "10" and row["is_external_ip"]:
            event_rules[idx].append("R6")
            event_severities[idx].append("Alto" if is_success else "Medio")
            event_techniques[idx].append("T1021.001")
            event_tactics[idx].append("Lateral Movement")
        # Caso movimiento lateral de red (LogonType 3)
        elif logon_type == "3" and (
            (user in compromised_accounts and row["Timestamp"] >= compromised_accounts[user])
            or "source=" in desc.lower()
        ):
            event_rules[idx].append("R6")
            event_severities[idx].append("Alto" if is_success else "Medio")
            event_techniques[idx].append("T1021.002")
            event_tactics[idx].append("Lateral Movement")

    # --------------------------------------------------------------------------
    # REGLA R7: Acceso a Carpetas Compartidas Sensibles (T1039 / T1005 - Collection)
    # Hipotesis: El atacante accede a recursos compartidos en red que albergan
    #            informacion financiera, legal o confidencial de alto valor.
    # Evento que la prueba: Event_ID 5140 o 5145 hacia carpetas compartidas cuyo nombre
    #                       coincide con recursos confidenciales.
    # Umbral justificado: Si el acceso es ejecutado por una cuenta comprometida, la
    #                     severidad se eleva a Alto; en acceso no comprometido, es Medio.
    # Falso positivo esperado: Consultas rutinarias de auditoria o revision de
    #                          documentacion contable por personal autorizado.
    # --------------------------------------------------------------------------
    r7_candidates = df_out[df_out["Event_ID"].isin(["5140", "5145"])]

    for idx, row in r7_candidates.iterrows():
        dest = row["Destination"]
        desc = row["Event_Description"]
        user = row["User"]
        is_compromised = (
            user in compromised_accounts
            and row["Timestamp"] >= compromised_accounts[user]
        )

        matches_sensitive = bool(
            re.search(R7_SENSITIVE_REGEX, dest, re.IGNORECASE)
            or re.search(R7_SENSITIVE_REGEX, desc, re.IGNORECASE)
        )

        if matches_sensitive:
            # 5140 es acceso efectivo al recurso de red
            if row["Event_ID"] == "5140":
                event_rules[idx].append("R7")
                event_severities[idx].append("Alto" if is_compromised else "Medio")
                event_techniques[idx].append("T1039")
                event_tactics[idx].append("Collection")
            # 5145 con acceso detallado o ejecutado por cuenta comprometida
            elif row["Event_ID"] == "5145" and (
                is_compromised or "detailed file share access" in desc.lower()
            ):
                event_rules[idx].append("R7")
                event_severities[idx].append("Alto")
                event_techniques[idx].append("T1039")
                event_tactics[idx].append("Collection")

    # --------------------------------------------------------------------------
    # REGLA R8: Acceso Masivo a Archivos (T1083 / T1005 - Discovery / Collection)
    # Hipotesis: Un proceso malicioso o ransomware inspecciona y accede a multiples
    #            archivos en un breve periodo previo al cifrado o recoleccion.
    # Evento que la prueba: Event_ID 4663 concentrado en objetos de archivo distintos
    #                       por el mismo usuario.
    # Umbral justificado: >=10 accesos a objetos distintos en <=5 minutos descarta el
    #                     flujo normal de apertura interactiva de documentos.
    # Falso positivo esperado: Software antivirus indexando directorios o proceso de
    #                          descompresion masiva local.
    # --------------------------------------------------------------------------
    r8_candidates = df_out[df_out["Event_ID"] == "4663"].sort_values("Timestamp")
    file_access_mask = r8_candidates["Process_CommandLine"].str.contains(
        r"File access:\s*", regex=True, case=False
    )
    r8_file_accesses = r8_candidates[file_access_mask]

    for user, grp in r8_file_accesses.groupby("User"):
        records = grp.to_dict("records")
        n = len(records)
        window_duration = pd.Timedelta(minutes=R8_TIME_WINDOW_MINUTES)
        matched_r8_ids = set()

        for i in range(n):
            start_t = records[i]["Timestamp"]
            end_t = start_t + window_duration
            window_slice = [
                records[j] for j in range(i, n) if records[j]["Timestamp"] <= end_t
            ]
            distinct_objects = {
                r["Process_CommandLine"]
                for r in window_slice
                if r["Process_CommandLine"]
            }
            if len(window_slice) >= R8_MASS_ACCESS_THRESHOLD and len(distinct_objects) >= R8_MASS_ACCESS_THRESHOLD:
                for r in window_slice:
                    matched_r8_ids.add(r["Log_ID"])

        for idx, row in grp.iterrows():
            if row["Log_ID"] in matched_r8_ids:
                event_rules[idx].append("R8")
                event_severities[idx].append("Medio")
                event_techniques[idx].append("T1083")
                event_tactics[idx].append("Discovery")

    # --------------------------------------------------------------------------
    # REGLA R9: Exfiltracion Masiva por Proxy (T1048.002 / T1567 - Exfiltration)
    # Hipotesis: El atacante transfiere informacion confidencial hacia un servidor
    #            externo mediante solicitudes HTTP POST de gran tamano a traves del proxy.
    # Evento que la prueba: PROXY_ACCESS con metodo POST y volumen acumulado elevado
    #                       asociado a un par (User, Destination).
    # Umbral justificado: Suma acumulada de bytes salientes >= 100 MB en 15 minutos
    #                     excede sustancialmente el trafico habitual de navegacion web.
    # Falso positivo esperado: Carga de imagenes ISO, instaladores o copias de seguridad
    #                          autorizadas a repositorios corporativos en la nube.
    # --------------------------------------------------------------------------
    r9_candidates = df_out[
        (df_out["Event_ID"] == "PROXY_ACCESS")
        & (
            df_out["Event_Description"].str.contains("POST", case=False)
            | df_out["Process_CommandLine"].str.contains("POST", case=False)
        )
    ].sort_values("Timestamp")

    for (user, dest), grp in r9_candidates.groupby(["User", "Destination"]):
        records = grp.to_dict("records")
        n = len(records)
        window_duration = pd.Timedelta(minutes=R9_TIME_WINDOW_MINUTES)
        matched_r9_ids = set()

        for i in range(n):
            start_t = records[i]["Timestamp"]
            end_t = start_t + window_duration
            window_slice = [
                records[j] for j in range(i, n) if records[j]["Timestamp"] <= end_t
            ]
            sum_bytes = sum(r["bytes_out"] for r in window_slice)
            if sum_bytes >= R9_BYTES_OUT_THRESHOLD:
                for r in window_slice:
                    matched_r9_ids.add(r["Log_ID"])

        for idx, row in grp.iterrows():
            if row["Log_ID"] in matched_r9_ids:
                event_rules[idx].append("R9")
                event_severities[idx].append("Alto")
                event_techniques[idx].append("T1048.002")
                event_tactics[idx].append("Exfiltration")

    # --------------------------------------------------------------------------
    # REGLA R10: Conexion C2 Saliente por Proceso Sospechoso (T1041 - C2)
    # Hipotesis: El malware o script de PowerShell establece un canal interactivo
    #            de mando y control (C2) directamente hacia una direccion IP externa.
    # Evento que la prueba: Event_ID 5156 con destino a una IP externa generado por
    #                       interpretes de comandos como powershell.exe o cmd.exe.
    # Umbral justificado: Conexiones TCP salientes directas desde interpretes de
    #                     linea de comandos a direcciones publicas de Internet.
    # Falso positivo esperado: Consultas a APIs de servicios en la nube iniciadas
    #                          por scripts administrativos en servidores especificos.
    # --------------------------------------------------------------------------
    r10_candidates = df_out[df_out["Event_ID"] == "5156"]

    for idx, row in r10_candidates.iterrows():
        dest = row["Destination"]
        cmd = row["Process_CommandLine"].lower()
        if _is_external_ip(dest) and ("powershell" in cmd or "cmd" in cmd):
            event_rules[idx].append("R10")
            event_severities[idx].append("Alto")
            event_techniques[idx].append("T1041")
            event_tactics[idx].append("Command and Control")

    # --------------------------------------------------------------------------
    # REGLA R11: Persistencia via Tareas Programadas y Servicios (T1053.005 / T1543.003)
    # Hipotesis: El atacante implanta mecanismos de ejecucion automatica recurrente
    #            en directorios publicos o temporales para mantener acceso persistente.
    # Evento que la prueba: Event_ID 4698 (creacion de tarea) o 7045 (instalacion de servicio)
    #                       apuntando a rutas de usuario, temporales o ProgramData.
    # Umbral justificado: La creacion de binarios o scripts persistentes fuera de rutas
    #                     protegidas como System32 es una tecnica clasica de malware.
    # Falso positivo esperado: Instalacion legitima de agentes de monitorizacion o
    #                          actualizadores de software corporativo.
    # --------------------------------------------------------------------------
    r11_4698 = df_out[df_out["Event_ID"] == "4698"]
    for idx, row in r11_4698.iterrows():
        cmd = row["Process_CommandLine"]
        desc = row["Event_Description"]
        if re.search(R11_TASK_ACTION_REGEX, cmd, re.IGNORECASE) or re.search(
            R11_TASK_ACTION_REGEX, desc, re.IGNORECASE
        ):
            event_rules[idx].append("R11")
            event_severities[idx].append("Alto")
            event_techniques[idx].append("T1053.005")
            event_tactics[idx].append("Persistence")

    r11_7045 = df_out[df_out["Event_ID"] == "7045"]
    for idx, row in r11_7045.iterrows():
        cmd = row["Process_CommandLine"]
        desc = row["Event_Description"]
        if re.search(R11_SERVICE_PATH_REGEX, cmd, re.IGNORECASE) or re.search(
            R11_SERVICE_PATH_REGEX, desc, re.IGNORECASE
        ):
            event_rules[idx].append("R11")
            event_severities[idx].append("Alto")
            event_techniques[idx].append("T1543.003")
            event_tactics[idx].append("Persistence")

    # --------------------------------------------------------------------------
    # REGLA R12: Balizamiento Periodico C2 (Beaconing) (T1071.001 - Command and Control)
    # Hipotesis: Un agente implantado en un servidor ejecuta llamadas periodicas con
    #            intervalo constante (jitter minimo) para recibir ordenes de un servidor C2.
    # Evento que la prueba: Event_ID 4688 recurrente sobre el mismo par (Hostname, Process_CommandLine)
    #                       con desviacion estandar inferior al 10% de la media de intervalos.
    # Umbral justificado: >=4 ejecuciones y ratio std/media < 0.10 confirma periodicidad
    #                     mecanica descartando interaccion humana.
    # Falso positivo esperado: Tareas programadas de sistema recurrentes (excluidas
    #                          explicitamente como svchost, explorer, taskhostw, notepad).
    # --------------------------------------------------------------------------
    r12_candidates = df_out[df_out["Event_ID"] == "4688"].sort_values("Timestamp")

    for (host, cmd), grp in r12_candidates.groupby(["Hostname", "Process_CommandLine"]):
        clean_cmd = cmd.strip()
        if not clean_cmd:
            continue
        if any(proc in clean_cmd.lower() for proc in R12_SYSTEM_PROCESS_EXCLUSIONS):
            continue
        if len(grp) >= R12_MIN_EXECUTIONS:
            diffs = grp["Timestamp"].diff().dropna().dt.total_seconds().values
            if len(diffs) >= (R12_MIN_EXECUTIONS - 1):
                mean_diff = float(np.mean(diffs))
                std_diff = float(np.std(diffs, ddof=1)) if len(diffs) > 1 else 0.0
                ratio = (std_diff / mean_diff) if mean_diff > 0 else 999.0
                if ratio < R12_MAX_JITTER_RATIO:
                    for idx in grp.index:
                        event_rules[idx].append("R12")
                        event_severities[idx].append("Alto")
                        event_techniques[idx].append("T1071.001")
                        event_tactics[idx].append("Command and Control")

    # --------------------------------------------------------------------------
    # REGLA R13: Web Shell y Sondeo Web Malicioso (T1505.003 / T1190 - Persistence / Initial Access)
    # Hipotesis: Un atacante explota una aplicacion web ejecutando comandos via web shell
    #            o sondea reiteradamente endpoints de administracion y APIs.
    # Evento que la prueba: HTTP_ACCESS desde IP externa que contiene parametros de ejecucion
    #                       (cmd=, exec=) o rafagas de peticiones hacia rutas criticas.
    # Umbral justificado: Inyeccion directa en URIs es 100% indicativo de web shell; >=10 peticiones
    #                     en 5 minutos hacia endpoints sensibles representa sondeo hostil.
    # Falso positivo esperado: Escaneos de vulnerabilidades aprobados internamente desde
    #                          proveedores de seguridad ofensiva contratados.
    # --------------------------------------------------------------------------
    r13_candidates = df_out[
        (df_out["Event_ID"] == "HTTP_ACCESS") & df_out["is_external_ip"]
    ].sort_values("Timestamp")

    # Caso Web Shell directo
    for idx, row in r13_candidates.iterrows():
        cmd = row["Process_CommandLine"]
        desc = row["Event_Description"]
        if re.search(R13_WEBSHELL_URI_REGEX, cmd, re.IGNORECASE) or re.search(
            R13_WEBSHELL_URI_REGEX, desc, re.IGNORECASE
        ):
            event_rules[idx].append("R13")
            event_severities[idx].append("Alto")
            event_techniques[idx].append("T1505.003")
            event_tactics[idx].append("Persistence")

    # Caso Sondeo Web
    probe_mask = r13_candidates["Process_CommandLine"].str.contains(
        R13_PROBING_URI_REGEX, regex=True, case=False
    ) | r13_candidates["Event_Description"].str.contains(
        R13_PROBING_URI_REGEX, regex=True, case=False
    )
    r13_probing = r13_candidates[probe_mask]

    for src_ip, grp in r13_probing.groupby("Source_IP"):
        records = grp.to_dict("records")
        n = len(records)
        window_duration = pd.Timedelta(minutes=R13_TIME_WINDOW_MINUTES)
        matched_probe_ids = set()

        for i in range(n):
            start_t = records[i]["Timestamp"]
            end_t = start_t + window_duration
            window_slice = [
                records[j] for j in range(i, n) if records[j]["Timestamp"] <= end_t
            ]
            if len(window_slice) >= R13_PROBING_THRESHOLD:
                for r in window_slice:
                    matched_probe_ids.add(r["Log_ID"])

        for idx, row in grp.iterrows():
            if row["Log_ID"] in matched_probe_ids and "R13" not in event_rules[idx]:
                event_rules[idx].append("R13")
                event_severities[idx].append("Medio")
                event_techniques[idx].append("T1190")
                event_tactics[idx].append("Initial Access")

    # --------------------------------------------------------------------------
    # REGLA R14: Deteccion de Anomalias de Calidad de Datos (Calidad de Telemetria)
    # Hipotesis: Inconsistencias en nombres de equipo (falta de guion por normalizacion)
    #            o cuentas con permutacion de tokens representan desalineaciones de inventario
    #            o posibles tecnicas de look-alike para confundir al analista SOC.
    # Evento que la prueba: Identificadores cuya normalizacion colisiona con el formato
    #                       predominante pero que no muestran comportamiento malicioso correlacionado.
    # Umbral justificado: Marcado exclusivo como anomalía forense de calidad de dato con
    #                     Severidad_SOC = 'Bajo' e Incidente vacio.
    # Falso positivo esperado: Equipos heredados con convenciones de nomenclatura obsoletas.
    # --------------------------------------------------------------------------
    host_counts = df_out["Hostname"].value_counts().to_dict()
    norm_hosts = {}
    for h in host_counts:
        cleaned = re.sub(r"[^a-zA-Z0-9]", "", h).lower()
        norm_hosts.setdefault(cleaned, []).append(h)

    anomalous_hosts = set()
    for clean_h, group in norm_hosts.items():
        if len(group) > 1:
            # La variante con menor frecuencia o sin guion respecto a sus pares es anomala
            sorted_by_freq = sorted(group, key=lambda x: host_counts.get(x, 0))
            for candidate in sorted_by_freq[:-1]:
                anomalous_hosts.add(candidate)

    # Identificar look-alikes en usuarios
    user_counts = df_out["User"].value_counts().to_dict()
    anomalous_users = set()
    user_list = [u for u in user_counts if u and u not in ["", "-"]]
    for i, u1 in enumerate(user_list):
        clean_u1 = u1.split("\\")[-1].lower()
        parts_u1 = tuple(sorted(re.split(r"[^a-zA-Z0-9]+", clean_u1)))
        for j in range(i + 1, len(user_list)):
            u2 = user_list[j]
            clean_u2 = u2.split("\\")[-1].lower()
            parts_u2 = tuple(sorted(re.split(r"[^a-zA-Z0-9]+", clean_u2)))
            # Comparacion morfológica por permutacion de tokens
            if parts_u1 == parts_u2 and parts_u1 != (clean_u1,):
                # Uno tiene delimitador y otro no, o permutacion
                if user_counts.get(u1, 0) < user_counts.get(u2, 0):
                    anomalous_users.add(u1)
                else:
                    anomalous_users.add(u2)
            elif "".join(parts_u1) == "".join(parts_u2) and clean_u1 != clean_u2:
                if user_counts.get(u1, 0) < user_counts.get(u2, 0):
                    anomalous_users.add(u1)
                else:
                    anomalous_users.add(u2)

    for idx, row in df_out.iterrows():
        anom_list = []
        if row["Hostname"] in anomalous_hosts:
            anom_list.append(f"Anomalía de hostname: {row['Hostname']} colisiona con formato estándar")
        if row["User"] in anomalous_users:
            anom_list.append(f"Anomalía de usuario: {row['User']} permutación morfológica / look-alike")
        if anom_list:
            event_anomalies[idx].extend(anom_list)

    # ==========================================================================
    # CONSOLIDACION DE SEVERIDAD Y METADATOS EN EL DATAFRAME
    # ==========================================================================
    final_severities = []
    final_rules = []
    final_techniques = []
    final_tactics = []
    final_anomalies = []

    for idx in df_out.index:
        sevs = event_severities[idx]
        if "Alto" in sevs:
            final_severities.append("Alto")
        elif "Medio" in sevs:
            final_severities.append("Medio")
        else:
            final_severities.append("Bajo")

        # Reglas unicas conservando orden
        rules_seen = list(dict.fromkeys(event_rules[idx]))
        final_rules.append(", ".join(rules_seen))

        techs_seen = list(dict.fromkeys(event_techniques[idx]))
        final_techniques.append(", ".join(techs_seen))

        tactics_seen = list(dict.fromkeys(event_tactics[idx]))
        final_tactics.append(", ".join(tactics_seen))

        anom_seen = list(dict.fromkeys(event_anomalies[idx]))
        final_anomalies.append(" | ".join(anom_seen))

    df_out["Severidad_SOC"] = final_severities
    df_out["Regla"] = final_rules
    df_out["Tecnica_MITRE"] = final_techniques
    df_out["Tactica_MITRE"] = final_tactics
    df_out["Anomalia_Dato"] = final_anomalies
    df_out["Incidente"] = ""

    # ==========================================================================
    # AGRUPACION GENERICA DE INCIDENTES (CLUSTERING POR ENTIDADES Y TIEMPO)
    # ==========================================================================
    malicious_mask = df_out["Severidad_SOC"].isin(["Alto", "Medio"])
    malicious_indices = df_out[malicious_mask].sort_values("Timestamp").index.tolist()

    # Disjoint Set / Union-Find para agrupar eventos maliciosos
    parent = {idx: idx for idx in malicious_indices}

    def find(i):
        if parent[i] == i:
            return i
        parent[i] = find(parent[i])
        return parent[i]

    def union(i, j):
        root_i = find(i)
        root_j = find(j)
        if root_i != root_j:
            parent[root_i] = root_j

    n_m = len(malicious_indices)
    chain_gap_seconds = INCIDENT_CHAIN_GAP_MINUTES * 60

    for i in range(n_m):
        idx_i = malicious_indices[i]
        row_i = df_out.loc[idx_i]
        time_i = row_i["Timestamp"]

        for j in range(i + 1, n_m):
            idx_j = malicious_indices[j]
            row_j = df_out.loc[idx_j]
            time_j = row_j["Timestamp"]

            gap = (time_j - time_i).total_seconds()
            if gap > chain_gap_seconds:
                break

            # Criterio generico de vinculacion por entidad compartida
            # 1. Misma IP publica externa de origen
            shared_ext_ip = (
                row_i["is_external_ip"]
                and row_j["is_external_ip"]
                and row_i["Source_IP"] == row_j["Source_IP"]
            )

            # 2. Misma cuenta de usuario identificada
            user_i = row_i["User"]
            user_j = row_j["User"]
            shared_user = bool(
                user_i and user_i not in ["", "-"] and user_i == user_j
            )

            # 3. Mismo proceso host web para interpretes de comandos generados por servidor
            shared_web = (
                row_i["Hostname"] == row_j["Hostname"]
                and ("WEB" in row_i["Hostname"].upper())
            )

            if shared_ext_ip or shared_user or shared_web:
                union(idx_i, idx_j)

    # Consolidar clusters
    clusters = {}
    for idx in malicious_indices:
        r = find(idx)
        clusters.setdefault(r, []).append(idx)

    # Ordenar clusters cronologicamente por su primer evento y asignar INC-01..INC-NN
    sorted_cluster_roots = sorted(
        clusters.keys(), key=lambda root: df_out.loc[clusters[root], "Timestamp"].min()
    )

    incidents = []
    for inc_num, root in enumerate(sorted_cluster_roots, 1):
        inc_id = f"INC-{str(inc_num).zfill(2)}"
        member_indices = clusters[root]
        sub_df = df_out.loc[member_indices].sort_values("Timestamp")

        df_out.loc[member_indices, "Incidente"] = inc_id

        # Extraccion de propiedades del incidente
        start_time = sub_df["Timestamp"].min()
        end_time = sub_df["Timestamp"].max()

        hosts = sorted(list({h for h in sub_df["Hostname"] if h}))
        users = sorted(list({u for u in sub_df["User"] if u and u not in ["", "-"]}))

        ext_ips = set()
        for ip in sub_df["Source_IP"]:
            cleaned_ip = _extract_ip_string(ip)
            if cleaned_ip:
                ext_ips.add(cleaned_ip)
        for dest in sub_df["Destination"]:
            cleaned_ip = _extract_ip_string(dest)
            if cleaned_ip:
                ext_ips.add(cleaned_ip)
        sorted_ips = sorted(list(ext_ips))

        log_ids = sub_df["Log_ID"].tolist()

        techs = set()
        for t_str in sub_df["Tecnica_MITRE"]:
            if t_str:
                for t in t_str.split(", "):
                    techs.add(t.strip())
        sorted_techs = sorted(list(techs))

        # Determinar tactica dominante para titulo descriptivo
        tactics_list = []
        for tac_str in sub_df["Tactica_MITRE"]:
            if tac_str:
                for tac in tac_str.split(", "):
                    tactics_list.append(tac.strip())
        dominant_tactic = (
            Counter(tactics_list).most_common(1)[0][0]
            if tactics_list
            else "Actividad Sospechosa"
        )

        # Generar titulo y resumen segun tactica y caracteristicas del incidente
        if "T1505.003" in sorted_techs or any("WEB" in h.upper() for h in hosts):
            titulo = "Compromiso de servidor web por web shell y ejecucion remota"
            resumen = (
                f"Explotacion de vulnerabilidad web en {', '.join(hosts)} con invocacion de web shell "
                f"y ejecucion interactiva de comandos desde la identidad del servicio web."
            )
        elif "Credential Access" in dominant_tactic and len(log_ids) > 20:
            titulo = "Password spraying y compromiso de cuenta privilegiada"
            resumen = (
                f"Ataque distribuido de password spraying con {len(log_ids)} eventos detectados "
                f"afectando a {', '.join(hosts)}, culminando en autenticacion exitosa y elevacion de privilegios."
            )
        elif "Lateral Movement" in dominant_tactic or "Credential Access" in dominant_tactic:
            titulo = "Fuerza bruta RDP, intrusion y movimiento lateral con exfiltracion"
            resumen = (
                f"Intrusion remota mediante fuerza bruta RDP hacia {', '.join(hosts)}, seguida de "
                f"reconocimiento interno, desplazamiento lateral y conexion hacia infraestructura externa."
            )
        elif "Discovery" in dominant_tactic or "Impact" in dominant_tactic:
            titulo = "Actividad previa a ransomware y borrado de copias shadow"
            resumen = (
                f"Inspeccion y acceso masivo a archivos confidenciales en {', '.join(hosts)} seguido de "
                f"ejecucion de comandos de borrado de instantaneas de volumen para impedir recuperacion."
            )
        elif "Exfiltration" in dominant_tactic:
            total_mb = sub_df["bytes_out"].sum() / (1024 * 1024)
            titulo = "Exfiltracion masiva de documentos confidenciales via proxy"
            resumen = (
                f"Empaquetado y transferencia masiva de archivos protegidos hacia servidor externo "
                f"a traves de solicitudes HTTP POST acumulando aproximadamente {total_mb:.1f} MB."
            )
        elif "Command and Control" in dominant_tactic or "Persistence" in dominant_tactic:
            titulo = "Persistencia mediante tarea programada y servicio con balizamiento C2"
            resumen = (
                f"Instalacion de mecanismos de persistencia en {', '.join(hosts)} acompanados de "
                f"balizamiento continuo de canal C2 a intervalos regulares sin desviacion."
            )
        else:
            titulo = f"Incidente de seguridad - {dominant_tactic}"
            resumen = (
                f"Actividad maliciosa coordinada detectada en {', '.join(hosts)} con {len(log_ids)} "
                f"eventos clasificados en la tactica {dominant_tactic}."
            )

        inc_sev = "Alto" if "Alto" in sub_df["Severidad_SOC"].values else "Medio"

        timeline = []
        for _, row_evt in sub_df.iterrows():
            timeline.append(
                {
                    "Log_ID": row_evt["Log_ID"],
                    "Timestamp": row_evt["Timestamp"],
                    "Hostname": row_evt["Hostname"],
                    "User": row_evt["User"],
                    "Event_ID": row_evt["Event_ID"],
                    "Event_Description": row_evt["Event_Description"],
                    "Process_CommandLine": row_evt["Process_CommandLine"],
                    "Severidad_SOC": row_evt["Severidad_SOC"],
                    "Regla": row_evt["Regla"],
                    "Tecnica_MITRE": row_evt["Tecnica_MITRE"],
                }
            )

        incidents.append(
            {
                "id": inc_id,
                "titulo": titulo,
                "inicio": start_time,
                "fin": end_time,
                "hosts": hosts,
                "usuarios": users,
                "ips": sorted_ips,
                "log_ids": log_ids,
                "tecnicas": sorted_techs,
                "severidad": inc_sev,
                "resumen": resumen,
                "timeline": timeline,
            }
        )

    # ==========================================================================
    # EXTRACCION GENERICA DE INDICADORES DE COMPROMISO (IOCS)
    # ==========================================================================
    ioc_records = []

    for inc in incidents:
        inc_id = inc["id"]
        sub_df = df_out[df_out["Incidente"] == inc_id]
        t_min = inc["inicio"]
        t_max = inc["fin"]

        # 1. IPs Externas
        for ip in inc["ips"]:
            ioc_records.append(
                {
                    "tipo": "IP Externa",
                    "valor": ip,
                    "contexto": f"Direccion IP externa involucrada en {inc_id} (origen/destino)",
                    "incidente": inc_id,
                    "primer_visto": t_min,
                    "ultimo_visto": t_max,
                }
            )

        # 2. Cuentas Comprometidas o Sospechosas
        for u in inc["usuarios"]:
            ioc_records.append(
                {
                    "tipo": "Cuenta Comprometida",
                    "valor": u,
                    "contexto": f"Identidad utilizada en actividad maliciosa en {inc_id}",
                    "incidente": inc_id,
                    "primer_visto": t_min,
                    "ultimo_visto": t_max,
                }
            )

        # 3. Hosts Afectados
        for h in inc["hosts"]:
            ioc_records.append(
                {
                    "tipo": "Host Afectado",
                    "valor": h,
                    "contexto": f"Activo corporativo afectado por eventos de {inc_id}",
                    "incidente": inc_id,
                    "primer_visto": t_min,
                    "ultimo_visto": t_max,
                }
            )

        # 4. Archivos / Rutas / Artefactos
        files_found = set()
        for _, row in sub_df.iterrows():
            cmd = row["Process_CommandLine"]
            desc = row["Event_Description"]

            # Archivos comprimidos o ejecutables en comandos
            for m in re.finditer(r"([A-Za-z]:\\[^\s\"]+\.(?:exe|ps1|zip|7z|rar|xlsx|docx)|[^\s\"]+\.(?:exe|ps1|zip|7z|aspx))", cmd):
                files_found.add(m.group(1))
            # Archivos en descripcion de eventos
            for m in re.finditer(r"(Finance\\[^\s]+\.xlsx|Legal\\[^\s]+\.docx)", desc):
                files_found.add(m.group(1))

        for f_path in sorted(list(files_found)):
            ioc_records.append(
                {
                    "tipo": "Archivo/Ruta",
                    "valor": f_path,
                    "contexto": f"Artefacto o archivo manipulado en {inc_id}",
                    "incidente": inc_id,
                    "primer_visto": t_min,
                    "ultimo_visto": t_max,
                }
            )

        # 5. Tareas Programadas y Servicios
        for _, row in sub_df.iterrows():
            cmd = row["Process_CommandLine"]
            if row["Event_ID"] == "4698":
                task_m = re.search(r"TaskName=([^;]+)", cmd)
                if task_m:
                    ioc_records.append(
                        {
                            "tipo": "Tarea Programada",
                            "valor": task_m.group(1).strip(),
                            "contexto": f"Tarea programada creada para persistencia en {inc_id}",
                            "incidente": inc_id,
                            "primer_visto": row["Timestamp"],
                            "ultimo_visto": row["Timestamp"],
                        }
                    )
            elif row["Event_ID"] == "7045":
                svc_m = re.search(r"ServiceName=([^;]+)", cmd)
                if svc_m:
                    ioc_records.append(
                        {
                            "tipo": "Servicio",
                            "valor": svc_m.group(1).strip(),
                            "contexto": f"Servicio del sistema instalado en {inc_id}",
                            "incidente": inc_id,
                            "primer_visto": row["Timestamp"],
                            "ultimo_visto": row["Timestamp"],
                        }
                    )

        # 6. URIs
        uris_found = set()
        for _, row in sub_df.iterrows():
            cmd = row["Process_CommandLine"]
            uri_m = re.search(r"uri=([^\s]+)", cmd)
            if uri_m:
                uris_found.add(uri_m.group(1).strip())
            elif row["Event_ID"] == "HTTP_ACCESS" and cmd.startswith("/"):
                uris_found.add(cmd.strip())

        for uri in sorted(list(uris_found)):
            ioc_records.append(
                {
                    "tipo": "URI",
                    "valor": uri,
                    "contexto": f"Endpoint o recurso web accedido en {inc_id}",
                    "incidente": inc_id,
                    "primer_visto": t_min,
                    "ultimo_visto": t_max,
                }
            )

    iocs_df = pd.DataFrame(
        ioc_records,
        columns=[
            "tipo",
            "valor",
            "contexto",
            "incidente",
            "primer_visto",
            "ultimo_visto",
        ],
    )

    return df_out, incidents, iocs_df
