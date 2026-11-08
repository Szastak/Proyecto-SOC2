# Reglas de Detección KQL para Microsoft Sentinel — Nordic Shadow Hunter

Este directorio contiene las 13 reglas de correlación y detección implementadas en **Kusto Query Language (KQL)** para **Microsoft Sentinel** (Azure Sentinel / Defender XDR), equivalentes a la lógica analítica de detección de amenazas desarrollada en `detections.py` del proyecto *Nordic Shadow Hunter*.

---

## 1. Arquitectura y Fuentes de Datos en Microsoft Sentinel

Las reglas explotan las tablas normalizadas del esquema de Microsoft Sentinel y Azure Log Analytics:

| Tabla de Telemetría Sentinel | Origen de Datos | Identificadores de Eventos Relevantes |
| :--- | :--- | :--- |
| `SecurityEvent` | Windows Security Event Log (Agente AMA / MMA) | `4625`, `4624`, `4672`, `4688`, `4104`, `5140`, `5145`, `4663`, `5156`, `4698` |
| `CommonSecurityLog` | Proxies Web, Firewalls de Próxima Generación (NGFW), Gateways Seguros (Zscaler, Palo Alto, Fortinet, Squid) | Métodos HTTP (`POST`), bytes salientes (`SentBytes`), URLs y destinos |
| `W3CIISLog` | Servidores Web Microsoft IIS | Solicitudes HTTP (`csUriStem`, `csUriQuery`, `cIP`, códigos de estado `scStatus`) |
| `Event` / `System` | Windows System Event Log | `7045` (Instalación de nuevos servicios en el sistema) |
| `DeviceProcessEvents` / `DeviceNetworkEvents` | Microsoft Defender for Endpoint (MDE / Defender XDR) | Telemetría complementaria de procesos y sockets de red a nivel de endpoint |

---

## 2. Matriz de Mapeo: Reglas R01 a R13

| Regla | Archivo KQL | Técnica MITRE | Táctica MITRE | Tabla Sentinel | Umbral Exacto | Resumen Operativo / Hipótesis |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- |
| **R01** | `R01_password_spraying.kql` | **T1110.003** (Password Spraying) | Credential Access | `SecurityEvent` | >= 10 fallos contra >= 5 usuarios en 15 min | Un atacante externo intenta autenticarse contra múltiples cuentas corporativas desde una misma IP pública para evitar bloqueos por contraseña. |
| **R02** | `R02_brute_force.kql` | **T1110.001** (Password Guessing) | Credential Access | `SecurityEvent` | >= 3 fallos sobre el mismo usuario en 10 min | Ataque reiterado de adivinación de credenciales contra una cuenta objetivo individual desde una IP externa. |
| **R03** | `R03_compromised_account.kql` | **T1078** (Valid Accounts) | Initial Access / Defense Evasion | `SecurityEvent` | Éxito (4624) en <= 30 min tras ataque R1/R2 | Autenticación exitosa desde la misma IP externa que ejecutó pulverización o fuerza bruta previa, confirmando cuenta vulnerada. |
| **R04** | `R04_special_privileges.kql` | **T1078.003** (Domain/Local Accounts) | Privilege Escalation / Persistence | `SecurityEvent` | Evento 4672 en cuenta comprometida o IP de ataque | Asignación de privilegios administrativos especiales a una sesión asociada a una cuenta o IP externa previamente atacada. |
| **R05** | `R05_suspicious_execution_lolbins.kql` | **T1059.001**, **T1490**, **T1135**, **T1069.001**, **T1033**, **T1560.001**, **T1003**, **T1505.003** | Execution, Impact, Discovery, Collection, Credential Access, Persistence | `SecurityEvent` (4688, 4104) / `DeviceProcessEvents` | 1 evento con regex sospechoso o shell bajo IIS | Ejecución de binarios legítimos de Windows (LOLBins) para evasión, dumping de contraseñas, borrado de sombras, descubrimiento o shell web interactiva. |
| **R06** | `R06_lateral_movement.kql` | **T1021.001** (RDP), **T1021.002** (SMB) | Lateral Movement | `SecurityEvent` (4624, 4625) | RDP exterior (LogonType 10) o SMB (LogonType 3) por cuenta comprometida | Propagación interna hacia otros servidores mediante recursos de red compartidos (SMB) o accesos remotos RDP directos desde Internet. |
| **R07** | `R07_sensitive_share_access.kql` | **T1039** (Data from Network Shared Drive), **T1005** | Collection | `SecurityEvent` (5140, 5145) | 1 acceso a carpetas matching `Finance\|Legal\|HR\|Confidential` | Acceso a recursos compartidos de red que albergan datos financieros, legales, de recursos humanos o confidenciales de alto impacto. |
| **R08** | `R08_mass_file_access.kql` | **T1083** (File & Directory Discovery), **T1005** | Discovery / Collection | `SecurityEvent` (4663) | >= 10 accesos a >= 10 archivos distintos en 5 min | Acceso masivo concentrado a múltiples archivos locales en breve periodo, indicativo de ransomware previo al cifrado o recolección de datos. |
| **R09** | `R09_proxy_exfiltration.kql` | **T1048.002** (Exfiltration Over Web Service), **T1567** | Exfiltration | `CommonSecurityLog` | Suma de bytes salientes >= 100 MB en 15 min vía POST | Transferencia masiva de información confidencial hacia servidores externos mediante peticiones HTTP POST a través del proxy corporativo. |
| **R10** | `R10_c2_exfiltration.kql` | **T1041** (Exfiltration Over C2 Channel), **T1071.001** | Command & Control / Exfiltration | `SecurityEvent` (5156) / `DeviceNetworkEvents` | 1 conexión saliente externa desde `powershell.exe` o `cmd.exe` | Establecimiento de conexión de red TCP directa hacia una dirección IP externa iniciada por intérpretes de comandos de Windows. |
| **R11** | `R11_persistence_tasks_services.kql` | **T1053.005** (Scheduled Task), **T1543.003** (Windows Service) | Persistence / Privilege Escalation | `SecurityEvent` (4698), `Event`/`System` (7045) | 1 tarea en rutas temporales o servicio en `ProgramData`/`Temp`/`AppData` | Creación de tareas programadas o instalación de servicios del sistema que ejecutan binarios ubicados en rutas de usuario no protegidas. |
| **R12** | `R12_c2_beaconing.kql` | **T1071.001** (Web Protocols) | Command and Control | `SecurityEvent` (4688) / `DeviceProcessEvents` | >= 4 ejecuciones y ratio (std / avg) < 0.10 | Ejecución periódica regular con baja varianza de intervalo (jitter < 10%), indicativo de llamadas automatizadas hacia un servidor C2. |
| **R13** | `R13_web_shell_probing.kql` | **T1505.003** (Web Shell), **T1190** (Exploit Public-Facing App) | Persistence / Initial Access | `W3CIISLog` | 1 request con `cmd=\|exec=` o >= 10 requests a `/admin\|/login\|/api` en 5 min | Inyección de comandos vía web shell o ráfaga de sondeo contra rutas administrativas y APIs desde direcciones IP externas. |

---

## 3. Especificación Detallada de Reglas y Equivalencia Analítica

### R01 — Password Spraying (`R01_password_spraying.kql`)
- **Objetivo**: Detectar ataques distribuidos de autenticación horizontal.
- **Lógica KQL**: Filtra `SecurityEvent` con `EventID == 4625`, valida que la IP de origen sea pública (`ipv4_is_private(IpAddress) == false`), agrupa por `IpAddress` en bloques de `15m` y verifica `count() >= 10` y `dcount(TargetUserName) >= 5`.
- **Equivalencia Python**: Refleja `R1_FAILED_LOGONS_THRESHOLD = 10`, `R1_DISTINCT_USERS_THRESHOLD = 5` y `R1_TIME_WINDOW_MINUTES = 15`.
- **Falsos Positivos y Tuning**: Servidores proxy que consolidan múltiples usuarios remotos; sincronizadores de Azure AD Connect. Descartar mediante Watchlist de IPs autorizadas.

### R02 — Fuerza Bruta (`R02_brute_force.kql`)
- **Objetivo**: Detectar intentos repetidos de autenticación contra un usuario específico.
- **Lógica KQL**: Filtra `EventID == 4625` desde IP externa, agrupa por `IpAddress` y `TargetUserName` en bloques de `10m` con `count() >= 3`.
- **Equivalencia Python**: Refleja `R2_FAILED_LOGONS_THRESHOLD = 3` y `R2_TIME_WINDOW_MINUTES = 10`.
- **Falsos Positivos y Tuning**: Usuarios móviles con contraseñas cambiadas recientemente reintentando conexión en clientes de correo. Correlacionar con eventos de bloqueo `4740`.

### R03 — Compromiso de Cuenta (`R03_compromised_account.kql`)
- **Objetivo**: Detectar inicio de sesión exitoso posterior a una ráfaga de ataques de credenciales.
- **Lógica KQL**: Efectúa un `join` temporal entre IPs externas que dispararon `EventID == 4625` (>= 3 fallos) e inicios de sesión exitosos (`EventID == 4624`) dentro de los 30 minutos posteriores (`between (0 .. 30)`).
- **Equivalencia Python**: Refleja `R3_POST_ATTACK_WINDOW_MINUTES = 30` aplicado sobre las ventanas de ataque de R1 y R2.
- **Falsos Positivos y Tuning**: Redes públicas con CGNAT donde un usuario falla y otro usuario legítimo acierta. Afinar exigiendo coincidencia entre usuario atacado y usuario autenticado.

### R04 — Privilegios Especiales en Cuenta Comprometida (`R04_special_privileges.kql`)
- **Objetivo**: Alertar sobre la asignación de privilegios administrativos a una cuenta o sesión vulnerada.
- **Lógica KQL**: Correlaciona `EventID == 4672` con el conjunto de usuarios que han sido objeto de ataques externos en la ventana previa.
- **Equivalencia Python**: Evalúa si `user in compromised_accounts` o si la IP pertenece al conjunto de ataque.
- **Falsos Positivos y Tuning**: Tareas del sistema bajo `SYSTEM` o `LOCAL SERVICE` (excluidas en la consulta).

### R05 — Ejecución Sospechosa y LOLBins (`R05_suspicious_execution_lolbins.kql`)
- **Objetivo**: Identificar abuso de utilidades nativas del sistema y scripts interactivos anómalos.
- **Lógica KQL**: Inspecciona `EventID in (4688, 4104)`, cotejando expresiones regulares de comandos ofuscados (`-EncodedCommand`), borrado de copias sombra (`vssadmin delete shadows`), descubrimiento (`whoami`, `net view`, `Get-LocalGroupMember`), empaquetado (`tar`, `7z`, `rar`, `zip`), extracción de credenciales (`certutil urlcache`, `mimikatz`) y shells bajo identidades web (`IIS APPPOOL`).
- **Equivalencia Python**: Refleja exhaustivamente el diccionario `R5_PATTERNS`.
- **Falsos Positivos y Tuning**: Scripts de automatización de TI o copias de seguridad legítimas. Excluir binarios firmados y procesos padre como `CcmExec.exe`.

### R06 — Movimiento Lateral (`R06_lateral_movement.kql`)
- **Objetivo**: Detectar propagación en la red interna o conexiones interactivas externas no autorizadas.
- **Lógica KQL**: Filtra `EventID in (4624, 4625)`. Evalúa dos vectores: (1) RDP externo (`LogonType == 10` con IP pública) y (2) SMB de red (`LogonType == 3` con cuentas bajo sospecha previa).
- **Equivalencia Python**: Evalúa bifurcación de RDP y SMB reflejando la lógica de `detections.py`.
- **Falsos Positivos y Tuning**: Administradores usando RDP público o escaneos internos de vulnerabilidades. Excluir subredes de bastiones o VPNs corporativas.

### R07 — Acceso a Recursos Compartidos Sensibles (`R07_sensitive_share_access.kql`)
- **Objetivo**: Proteger repositorios de red que almacenan activos de alto impacto financiero, legal o confidencial.
- **Lógica KQL**: Examina eventos `5140` y `5145` verificando si `ShareName` o `RelativeTargetName` coinciden con `(?i)(Finance|Legal|HR|Confidential)`.
- **Equivalencia Python**: Refleja `R7_SENSITIVE_REGEX = r"Finance|Legal|HR|Confidential"`.
- **Falsos Positivos y Tuning**: Empleados de finanzas o recursos humanos en horario laboral habitual. Filtrar por pertenencia a grupos de Active Directory autorizados.

### R08 — Acceso Masivo a Archivos (`R08_mass_file_access.kql`)
- **Objetivo**: Detectar patrones tempranos de ransomware o exfiltración masiva local.
- **Lógica KQL**: Analiza `EventID == 4663` sobre objetos de archivo, agrupando por usuario en ventanas de `5m` con `TotalAccessCount >= 10` y `DistinctFilesCount >= 10`.
- **Equivalencia Python**: Refleja `R8_MASS_ACCESS_THRESHOLD = 10` y `R8_TIME_WINDOW_MINUTES = 5`.
- **Falsos Positivos y Tuning**: Indexadores de búsqueda de Windows o software antivirus analizando el disco. Descartar procesos como `SearchIndexer.exe` o `MsMpEng.exe`.

### R09 — Exfiltración Masiva por Proxy (`R09_proxy_exfiltration.kql`)
- **Objetivo**: Descubrir transferencias voluminosas salientes hacia destinos externos.
- **Lógica KQL**: Consulta `CommonSecurityLog` filtrando por método `POST`, agrupando por usuario y destino en ventanas de `15m`, sumando `SentBytes >= 100 * 1024 * 1024` (100 MB).
- **Equivalencia Python**: Refleja `R9_BYTES_OUT_THRESHOLD = 100 * 1024 * 1024` y `R9_TIME_WINDOW_MINUTES = 15`.
- **Falsos Positivos y Tuning**: Cargas de copias de seguridad corporativas hacia almacenamiento en la nube autorizado. Excluir mediante Watchlist de dominios sancionados.

### R10 — Conexión C2 Saliente por CLI (`R10_c2_exfiltration.kql`)
- **Objetivo**: Detectar sockets de red establecidos directamente por consolas de comandos hacia Internet.
- **Lógica KQL**: Evalúa `EventID == 5156` en `SecurityEvent` verificando que el proceso originador sea `powershell.exe` o `cmd.exe` y la dirección remota sea una IP pública no privada.
- **Equivalencia Python**: Refleja la correlación de `Event_ID == "5156"` con `_is_external_ip(dest)` y CLI.
- **Falsos Positivos y Tuning**: Scripts DevOps invocando APIs públicas como GitHub o Azure Resource Manager. Excluir IPs o rangos autorizados.

### R11 — Persistencia vía Tareas Programadas y Servicios (`R11_persistence_tasks_services.kql`)
- **Objetivo**: Detectar anclaje de persistencia en rutas desprotegidas del sistema.
- **Lógica KQL**: Unifica `EventID == 4698` (tarea programada) apuntando a `ProgramData`, `Temp`, `AppData` o `powershell` con `EventID == 7045` (nuevo servicio) apuntando a rutas como `Users\Public` o directorios temporales.
- **Equivalencia Python**: Refleja `R11_TASK_ACTION_REGEX` y `R11_SERVICE_PATH_REGEX`.
- **Falsos Positivos y Tuning**: Actualizadores de software en espacio de usuario (Google Update, Zoom). Excluir nombres de tareas de fabricantes reconocidos.

### R12 — Balizamiento Periódico C2 (`R12_c2_beaconing.kql`)
- **Objetivo**: Descubrir actividad regular de mando y control basada en ejecuciones periódicas de procesos.
- **Lógica KQL**: Ordena eventos `4688` por equipo y línea de comando, calcula deltas sucesivos con `serialize` y `prev()`, obtiene la media (`avg`) y desviación estándar (`stdev`) de los intervalos, y valida que `ExecutionCount >= 4` con un ratio de jitter (`stdev / avg`) menor a `0.10` (10%). Excluye procesos nativos (`svchost`, `explorer`, `taskhostw`, `notepad`).
- **Equivalencia Python**: Refleja `R12_MIN_EXECUTIONS = 4`, `R12_MAX_JITTER_RATIO = 0.10` y `R12_SYSTEM_PROCESS_EXCLUSIONS`.
- **Falsos Positivos y Tuning**: Tareas periódicas de monitoreo interno con intervalos fijos. Agregar a lista de scripts de diagnóstico autorizados.

### R13 — Web Shell y Sondeo Web Malicioso (`R13_web_shell_probing.kql`)
- **Objetivo**: Detectar comandos interactivos contra servidores web y escaneo hostil de endpoints.
- **Lógica KQL**: Consulta `W3CIISLog` desde IPs externas bifurcando en: (1) Presencia de parámetros de web shell (`cmd=`, `exec=`, `.aspx?`, `.php?`) como alerta de Severidad Alta, y (2) Sondeo masivo hacia `/admin`, `/login`, `/api` con `>= 10` peticiones en `5m` como Severidad Media.
- **Equivalencia Python**: Refleja `R13_WEBSHELL_URI_REGEX`, `R13_PROBING_URI_REGEX`, `R13_PROBING_THRESHOLD = 10` y `R13_TIME_WINDOW_MINUTES = 5`.
- **Falsos Positivos y Tuning**: Pruebas de estrés y escaneos de vulnerabilidades aprobados. Excluir IPs de proveedores de seguridad defensiva/ofensiva contratados.

---

## 4. Guía de Despliegue en Microsoft Sentinel

### 4.1. Creación Manual de Reglas Analíticas Programadas (Scheduled Analytics Rules)

1. Iniciar sesión en el portal de Azure: [https://portal.azure.com](https://portal.azure.com) o en el portal unificado de Microsoft Defender: [https://security.microsoft.com](https://security.microsoft.com).
2. Navegar a **Microsoft Sentinel** y seleccionar el **Workspace de Log Analytics** del proyecto.
3. En el menú de navegación izquierdo, dentro de la sección **Configuration**, hacer clic en **Analytics**.
4. En la barra superior, seleccionar **Create** -> **Scheduled query rule**.
5. Completar el asistente en 5 fases:
   - **Paso 1: General**:
     - *Name*: Copiar el `Rule Name & ID` del encabezado KQL (ej. `[Nordic Shadow Hunter] R01 - Password Spraying Attack`).
     - *Description*: Detallar la hipótesis analítica y técnica MITRE.
     - *Tactics & Techniques*: Seleccionar las tácticas y técnicas MITRE indicadas en la cabecera.
     - *Severity*: Asignar la severidad correspondiente (`High`, `Medium` o `Low`).
   - **Paso 2: Set rule logic**:
     - *Rule query*: Pegar la consulta KQL contenida en el archivo `.kql` correspondiente.
     - *Alert enrichment (Entity mapping)*:
       - **Account**: Mapear `TargetUserName` o `UserAccount` a `Account -> Name`.
       - **Host**: Mapear `Computer` a `Host -> HostName`.
       - **IP**: Mapear `IpAddress` o `ClientIP` a `IP -> Address`.
       - **URL**: Mapear `SampleFullURI` o `Destination` a `URL -> Url`.
     - *Query scheduling*:
       - **Run query every**: Configurar según la ventana temporal de la regla (ej. `15 minutes` para R01, `10 minutes` para R02, `5 minutes` para R08/R13).
       - **Lookup data to evaluate**: Ajustar al marco temporal analítico (ej. `1 hour` o `2 hours`).
     - *Incident settings*:
       - Habilitar **Create incidents from alerts triggered by this analytics rule**.
       - Configurar **Alert grouping** para agrupar alertas repetidas durante la ventana de análisis en un único incidente.
   - **Paso 3: Incident settings**:
     - Configurar agrupación por entidad (e.g., agrupar por cuenta de usuario o IP de origen dentro de una ventana de 5 horas).
   - **Paso 4: Automated response**:
     - (Opcional) Vincular Playbooks de Logic Apps (SOAR) para aislamiento automático de hosts, bloqueo de cuentas o enriquecimiento con VirusTotal / AbuseIPDB.
   - **Paso 5: Review and create**:
     - Validar la sintaxis y presionar **Save**.

### 4.2. Despliegue Automatizado mediante ARM / Bicep

Cada regla KQL puede ser exportada e implementada como un recurso `Microsoft.OperationalInsights/workspaces/providers/metadata` o `Microsoft.SecurityInsights/alertRules`:

```bicep
resource sentinelRuleR01 'Microsoft.SecurityInsights/alertRules@2023-02-01-preview' = {
  name: guid(workspace.id, 'R01_password_spraying')
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: '[Nordic Shadow Hunter] R01 - Password Spraying'
    description: 'Detects password spraying against multiple user accounts from an external IP.'
    severity: 'Medium'
    enabled: true
    query: loadTextContent('./R01_password_spraying.kql')
    queryFrequency: 'PT15M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'CredentialAccess'
    ]
    techniques: [
      'T1110'
    ]
  }
}
```

### 4.3. Implementación de Listas de Exclusión (Watchlists)

Para facilitar la sintonización continua sin modificar la consulta central KQL:
1. Crear una Watchlist en Sentinel con el Alias `ApprovedProxies` o `AuthorizedSecurityScanners`.
2. Modificar la cláusula de exclusión en la regla:
   ```kql
   let AllowedIPs = _GetWatchlist('ApprovedProxies') | project tostring(IPAddress);
   SecurityEvent
   | where not(IpAddress in (AllowedIPs))
   ```

---

## 5. Verificación y Testing de Consultas KQL

Para validar las reglas en un entorno de desarrollo o pre-producción:
1. Abrir **Logs** en el espacio de trabajo de Log Analytics.
2. Ejecutar la consulta KQL limitando el marco temporal (`ago(24h)`).
3. Validar que las proyecciones de campos cumplan con el formato esperado y que no se produzcan errores semánticos ni de tipos de datos.
