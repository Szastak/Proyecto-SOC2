"""Nordic Shadow Hunter - Forensic Analysis, ACH, and Narrative Content.

This module houses curated analytical narratives, including Analysis of Competing
Hypotheses (ACH) for threat actor attribution, regulatory impact assessments
(NIS2 early notification, RGPD Art. 33), visibility gap documentation, and
step-by-step remediation playbooks with concrete operational commands.
"""

# ==============================================================================
# METADATOS Y CONSTANTES DE CABECERA Y PIE
# ==============================================================================

METADATA = {
    "TITLE": "INFORME FORENSE Y DE RESPUESTA A INCIDENTES",
    "SUBTITLE": "Investigación Forense Multi-Incidente — Caso Nordic Shadow",
    "CLIENT": "Sector Energético Nórdico (Operador de Infraestructura Crítica)",
    "ORGANIZATION": "CSIRT / IR Estocolmo",
    "CLASSIFICATION": "TLP:AMBER",
    "HEADER_TEXT": "INFORME DE INCIDENTE — CASO NORDIC SHADOW | TLP:AMBER",
    "FOOTER_TEXT": "Confidencial",
}

# ==============================================================================
# PARTE 1 - RESUMEN EJECUTIVO (ORIENTADO A NEGOCIO Y DIRECCION)
# ==============================================================================

EXECUTIVE_SUMMARY = {
    "SECTION_1_TITLE": "PARTE 1 — RESUMEN EJECUTIVO",
    "SECTION_1_1_TITLE": "1.1 Qué Ocurrió",
    "SECTION_1_1_TEXT": (
        "Durante el período de monitorización analizado se detectó una cadena coordinada y multifacética "
        "de incidentes de seguridad que afectó a la infraestructura crítica del operador energético. "
        "El motor de correlación procesó un total de 715 eventos de telemetría SIEM, identificando 121 eventos "
        "maliciosos agrupados en 6 incidentes de alta criticidad distribuidos en 7 activos clave "
        "(DC-01, APP-SRV01, FS-SRV01, WEB-01, WS-018, WS-023 y WS-031). Los vectores incluyeron ataques "
        "externos de password spraying sobre controladores de dominio, intrusiones remotas vía fuerza bruta "
        "RDP, explotación de servidores web expuestos mediante web shells, desplazamiento lateral hacia servidores "
        "de archivos, exfiltración masiva de información sensible (~253 MB) y ejecución de comandos destructivos "
        "destinados a eliminar instantáneas de volumen (Volume Shadow Copies) como preparación previa a ransomware."
    ),
    "SECTION_1_2_TITLE": "1.2 Estado de la Amenaza",
    "SECTION_1_2_STATUS": "Activa hasta confirmar contención",
    "SECTION_1_2_TEXT": (
        "El estado operacional de la amenaza se califica formalmente como 'Activa hasta confirmar contención'. "
        "A pesar de que varias fases de ataque han concluido su ventana temporal visible, persisten mecanismos "
        "de persistencia no erradicados (servicio WinUpdateHelper y tarea programada UpdateCheck en APP-SRV01, "
        "así como la presencia del archivo web shell test.aspx en WEB-01). Asimismo, debido a la naturaleza "
        "de las credenciales comprometidas y a la falta de telemetría perimetral completa, no es posible descartar "
        "canales durmientes de acceso secundario o movimiento lateral adicional no interceptado."
    ),
    "SECTION_1_3_TITLE": "1.3 Impacto en el Negocio",
    "SECTION_1_3_ITEMS": [
        (
            "Envío Confirmado de ~253 MB tras Comprimir Documentos Legales",
            "Envío confirmado de ~253 MB hacia un servidor externo tras comprimir documentos legales (el contenido "
            "exacto no se puede verificar con la telemetría), atribuido exclusivamente al incidente INC-04 (cuenta CORP\\rrojas "
            "desde \\FS-SRV01\\Legal hacia 198.51.100.88 vía proxy HTTP POST). En el caso de Finanzas (INC-02), la "
            "telemetría constata una conexión saliente por PowerShell hacia 203.0.113.88:443 pero sin volumen medido. "
            "Riesgo crítico de fuga de información confidencial y espionaje corporativo.",
        ),
        (
            "Borrado de Instantáneas Pre-Ransomware",
            "Invocación de 'vssadmin delete shadows /all /quiet' en estaciones de trabajo y servidores de archivos, "
            "inhabilitando la recuperación local rápida del sistema de archivos. Patrón característico de preparación "
            "inmediata para cifrado extorsivo (ransomware).",
        ),
        (
            "Persistencia en Servidores Críticos de Aplicación",
            "Instalación del servicio 'WinUpdateHelper' y de la tarea programada '\\Microsoft\\Windows\\UpdateCheck' en "
            "APP-SRV01, acoplados a ejecuciones continuas de balizamiento C2 a intervalos regulares sin fluctuación, "
            "permitiendo reconexión autónoma del adversario.",
        ),
        (
            "Compromiso de Servidor Web Perimetral",
            "Explotación de vulnerabilidad pública e implantación de web shell 'test.aspx' en WEB-01, otorgando "
            "ejecución remota de comandos bajo el contexto de identidad 'IIS APPPOOL\\DefaultAppPool'.",
        ),
    ],
    "SECTION_1_4_TITLE": "1.4 Cumplimiento Normativo: RGPD y Directiva NIS2",
    "SECTION_1_4_RGPD": (
        "Notificación RGPD (Artículo 33):\n"
        "La evidencia forense constata la exfiltración exitosa de documentos corporativos sensibles que incluyen "
        "datos de recursos humanos, contratos legales y transacciones financieras vinculadas a personas físicas identificables. "
        "De conformidad con el Artículo 33 del Reglamento General de Protección de Datos (RGPD / GDPR), la entidad tiene la "
        "obligación legal de notificar la brecha de seguridad a la Autoridad de Protección de Datos de Suecia "
        "(IMY - Integritetsskyddsmyndigheten) dentro del plazo máximo de 72 horas desde que se tuvo constancia del incidente. "
        "Asimismo, se debe evaluar el impacto sobre los interesados para determinar la necesidad de comunicación directa (Art. 34)."
    ),
    "SECTION_1_4_NIS2": (
        "Directiva NIS2 (Operador Esencial del Sector Energético):\n"
        "Al tratarse de una entidad del sector de la energía catalogada como Operador Esencial bajo la Directiva NIS2 "
        "(Directiva UE 2022/2555), rigen los plazos estrictos de notificación obligatoria de incidentes significativos:\n"
        "  1. Alerta Temprana (24 horas): Emisión de una alerta temprana ante la autoridad competente en Suecia, CERT-SE (NCSC/FRA), "
        "dentro de las 24 horas siguientes al conocimiento del incidente con sospecha de intencionalidad o impacto transfronterizo.\n"
        "  2. Notificación de Incidente (72 horas): Actualización con evaluación inicial de gravedad, consecuencias e indicadores de compromiso.\n"
        "  3. Informe Final (1 mes): Entrega de reporte técnico y forense exhaustivo con causas raíz, medidas mitigadoras e impacto cuantificado."
    ),
    "SECTION_1_5_TITLE": "1.5 Prioridades Recomendadas de Mitigación",
    "RECOMMENDED_PRIORITIES_HEADERS": ["Prioridad", "Acción Operativa", "Responsable", "Plazo"],
    "RECOMMENDED_PRIORITIES": [
        [
            "P1 (Inmediata)",
            "Aislamiento de red de hosts comprometidos (WEB-01, APP-SRV01, FS-SRV01, WS-018, WS-023, WS-031) y bloqueo en firewall perimetral de las 5 IPs atacantes externas.",
            "SecOps / SOC L2",
            "< 2 horas",
        ],
        [
            "P2 (Crítica)",
            "Revocación inmediata de tokens y reseteo de contraseñas de cuentas vulneradas (mgarcia, backupsvc, rrojas, admin, helpdesk, IIS APPPOOL\\DefaultAppPool); remoción de privilegios de admin local a mgarcia en WS-031.",
            "Identity / SysAdmin",
            "< 4 horas",
        ],
        [
            "P3 (Regulatoria)",
            "Emisión de Alerta Temprana NIS2 ante CERT-SE (NCSC/FRA) y preparación de la notificación formal ante IMY por brecha de datos personales RGPD Art. 33.",
            "DPO / Legal / CISO",
            "< 24 h (NIS2) / < 72 h (RGPD)",
        ],
        [
            "P4 (Erradicación)",
            "Eliminación de artefactos de persistencia: borrado de servicio WinUpdateHelper y tarea programada UpdateCheck en APP-SRV01; eliminación de web shell test.aspx en WEB-01.",
            "Incident Response",
            "< 24 horas",
        ],
        [
            "P5 (Resiliencia)",
            "Auditoría de copias de seguridad offline (inmutables/WORM); imposición estricta de MFA en todos los accesos externos y RDP; despliegue de Sysmon con Hash=SHA256.",
            "Arquitectura TI / CISO",
            "48 a 72 horas",
        ],
    ],
    "SECTION_1_6_TITLE": "1.6 Matriz de Riesgo por Incidente",
    "RISK_MATRIX_HEADERS": ["Incidente", "Título Operativo", "Nivel de Riesgo", "Justificación de Negocio"],
    "RISK_MATRIX": [
        [
            "INC-01",
            "Password spraying y compromiso de cuenta privilegiada",
            "Alto",
            "Compromiso de credenciales corporativas (mgarcia) en WS-031 con privilegios locales preexistentes.",
        ],
        [
            "INC-02",
            "Fuerza bruta RDP, intrusión y movimiento lateral",
            "Alto",
            "Intrusión exitosa sobre cuenta admin hacia APP-SRV01 y salto lateral a FS-SRV01.",
        ],
        [
            "INC-03",
            "Actividad previa a ransomware y borrado de copias shadow",
            "Crítico",
            "Destrucción de instantáneas de volumen vssadmin y acceso masivo a archivos de red.",
        ],
        [
            "INC-04",
            "Exfiltración masiva de documentos confidenciales vía proxy",
            "Crítico",
            "Envío confirmado de ~253 MB hacia un servidor externo tras comprimir documentos legales (el contenido exacto no se puede verificar con la telemetría).",
        ],
        [
            "INC-05",
            "Persistencia mediante tarea y servicio con balizamiento C2",
            "Alto",
            "Canal de mando y control persistente en servidor de aplicaciones mediante balizamiento regular.",
        ],
        [
            "INC-06",
            "Compromiso de servidor web por web shell y ejecución remota",
            "Alto",
            "Servidor perimetral WEB-01 comprometido con shell aspx interactiva y reconocimiento local.",
        ],
    ],
}

# ==============================================================================
# PARTE 2 - RESUMEN TECNICO (DETALLADO PARA ANALISTAS E INGENIERIA)
# ==============================================================================

TECHNICAL_SUMMARY = {
    "SECTION_2_TITLE": "PARTE 2 — RESUMEN TÉCNICO Y EVIDENCIA FORENSE",
    "SECTION_2_1_TITLE": "2.1 Alcance, Metodología e Integridad de Telemetría",
    "SECTION_2_1_TEXT": (
        "La presente investigación forense abarca la ingestión y análisis de la telemetría provista en formato SIEM, "
        "que integra registros de seguridad de Windows Event Logs (Domain Controllers, servidores miembros y estaciones de trabajo), "
        "logs de proxy corporativo HTTP y eventos de monitorización de procesos.\n"
        "Metodología:\n"
        "  1. Integridad Criptográfica: Verificación de la muestra original mediante cálculo de resumen SHA-256.\n"
        "  2. Motor de Correlación Genérico: Aplicación de 14 reglas de detección (R1 a R14) basadas en umbrales estadísticos, "
        "patrones LOLBins y ventanas temporales, sin filtros de entidades hardcodeadas.\n"
        "  3. Agrupación de Incidentes: Algoritmo de clustering temporal y de conectividad con ventana máxima de inactividad de 30 minutos.\n"
        "  4. Taxonomía MITRE ATT&CK: Mapeo de eventos contra técnicas y tácticas de la matriz Enterprise v14.\n"
        "  5. Extracción de IoCs: Consolidación de direcciones IP externas, identidades vulneradas, nombres de host, rutas y artefactos.\n"
        "Limitaciones: La telemetría provista carece de logs de cortafuegos de borde, registros de VPN, eventos de autenticación "
        "Kerberos (4768/4769) y hashes criptográficos en creación de procesos (Sysmon EID 1). "
        "Asimismo, las 5 IPs externas pertenecen a rangos de documentación RFC 5737; el enriquecimiento con threat intel/MISP no arroja coincidencias."
    ),
    "SECTION_2_2_TITLE": "2.2 Resumen Consolidado de Incidentes",
    "INCIDENTS_TABLE_HEADERS": ["ID", "Título", "Ventana Temporal", "Hosts Afectados", "Cuentas", "Técnicas MITRE"],
    "SECTION_2_3_TITLE": "2.3 Línea de Tiempo Detallada por Incidente (Log_IDs)",
    "TIMELINE_HEADERS": ["Log_ID", "Timestamp", "Host", "Usuario", "EID", "Detalle / Línea de Comando", "Severidad"],
    "SECTION_2_4_TITLE": "2.4 Matriz MITRE ATT&CK Consolidada",
    "MITRE_HEADERS": ["Táctica", "Técnica", "ID", "Incidentes", "Evidencia Log_ID"],
    "MITRE_DICTIONARY": {
        "T1110.003": ("Credential Access", "Password Spraying"),
        "T1110.001": ("Credential Access", "Password Guessing / Brute Force"),
        "T1078": ("Initial Access", "Valid Accounts"),
        "T1078.003": ("Privilege Escalation", "Local Accounts"),
        "T1021.001": ("Lateral Movement", "Remote Desktop Protocol"),
        "T1021.002": ("Lateral Movement", "SMB/Windows Admin Shares"),
        "T1135": ("Discovery", "Network Share Discovery"),
        "T1069.001": ("Discovery", "Local Groups Discovery"),
        "T1033": ("Discovery", "System Owner/User Discovery"),
        "T1083": ("Discovery", "File and Directory Discovery"),
        "T1059.001": ("Execution", "PowerShell Execution"),
        "T1505.003": ("Persistence", "Web Shell"),
        "T1560.001": ("Collection", "Archive via Utility"),
        "T1039": ("Collection", "Data from Network Shared Drive"),
        "T1048.002": ("Exfiltration", "Exfiltration Over Asymmetric Non-C2 Protocol"),
        "T1041": ("Command and Control", "Exfiltration Over C2 Channel"),
        "T1071.001": ("Command and Control", "Web Protocols (HTTP Beaconing)"),
        "T1053.005": ("Persistence", "Scheduled Task"),
        "T1543.003": ("Persistence", "Windows Service"),
        "T1190": ("Initial Access", "Exploit Public-Facing Application"),
        "T1490": ("Impact", "Inhibit System Recovery (Delete Volume Shadows)"),
    },
    "SECTION_2_5_TITLE": "2.5 Indicadores de Compromiso (IoCs)",
    "IOC_TABLE_HEADERS": ["Tipo", "Valor / Indicador", "Contexto Forense", "Incidente", "Primer Visto", "Último Visto"],
    "IOC_HASHES_NOTE": (
        "Nota Explícita sobre Hashes Criptográficos:\n"
        "Hashes de archivos: No disponibles en la telemetría provista. La configuración de auditoría de creación "
        "de procesos en los registros de seguridad no incluyó la captura de hashes criptográficos (SHA-256 o MD5). "
        "Se recomienda desplegar Sysmon con el Event ID 1 configurado para registrar hashes SHA-256 de forma obligatoria."
    ),
    "SECTION_2_6_TITLE": "2.6 Correlación y Análisis de Atribución (Metodología ACH)",
    "ACH_INTRO": (
        "Para determinar la naturaleza y origen de los ataques observados, se aplicó la metodología de Análisis de "
        "Hipótesis Competitivas (ACH — Analysis of Competing Hypotheses), evaluando sistemáticamente la evidencia técnica "
        "frente a tres hipótesis mutuamente excluyentes."
    ),
    "ACH_HYPOTHESES": {
        "H1": "Un único actor de amenazas coordinado ejecutando una campaña de intrusión lineal y estructurada.",
        "H2": "Múltiples actores de amenazas oportunistas e independientes actuando de manera concurrente.",
        "H3": "Un Initial Access Broker (IAB) que obtuvo accesos iniciales y los traspasó o vendió a operadores independientes.",
    },
    "ACH_EVIDENCE_HEADERS": ["Evidencia / Factor Observado", "H1 (Único)", "H2 (Múltiples)", "H3 (IAB + Operadores)"],
    "ACH_EVIDENCE_TABLE": [
        [
            "Direcciones IP de origen disjuntas por incidente (203.0.113.74, 198.51.100.77, 192.0.2.91, 203.0.113.88, 198.51.100.88)",
            "Inconsistente (-)",
            "Muy Consistente (++)",
            "Consistente (+)",
        ],
        [
            "Divergencia radical de TTPs (Spraying masivo vs RDP Brute Force vs Web Shell vs Exfiltración HTTP vs vssadmin)",
            "Inconsistente (-)",
            "Muy Consistente (++)",
            "Consistente (+)",
        ],
        [
            "Ventana de actividad de mgarcia cesa a las 08:40 y nunca vuelve a ser utilizada por otros incidentes",
            "Inconsistente (-)",
            "Consistente (+)",
            "Inconsistente (-)",
        ],
        [
            "Ataque externo por fuerza bruta RDP a cuenta admin (redundante e ilógico si un único actor ya tenía acceso interno)",
            "Muy Inconsistente (--)",
            "Muy Consistente (++)",
            "Consistente (+)",
        ],
        [
            "Sin evidencia de volcado de credenciales (no hay telemetría EDR/Sysmon) en memoria (LSASS/Mimikatz) en la estación WS-031 tras el acceso",
            "Inconsistente (-)",
            "Consistente (+)",
            "Consistente (+)",
        ],
    ],
    "ACH_ANALYSIS_TEXT": (
        "Evaluación Forense de la Evidencia:\n"
        "1. Infraestructura de Red Dispar: Cada incidente opera desde una dirección IP pública completamente diferenciada "
        "sin solapamiento temporal ni de rangos AS. No se observan pivotes desde las mismas máquinas perimetrales.\n"
        "2. Redundancia Táctica: La cuenta 'admin' es atacada mediante fuerza bruta RDP externa sobre APP-SRV01 a las 09:15, "
        "lo cual resulta operativo y tácticamente redundante para un actor único que ya había consolidado acceso con privilegios "
        "administrativos en WS-031 a las 08:35.\n"
        "3. Comportamiento Estanco de Cuentas: La identidad 'mgarcia' queda inerte tras las 08:40. En paralelo, 'backupsvc' y 'rrojas' "
        "aparecen en fases posteriores en hosts diferentes sin trazas de movimiento lateral cruzado entre dichas cuentas.\n"
        "4. Perfil Operacional Heterogéneo: Coexisten técnicas típicas de ransomware oportunista (eliminación ruidosa de vssadmin), "
        "ciberespionaje/fuga de datos (exfiltración silenciosa vía proxy de Legal/Finanzas) y explotación perimetral web clásica (web shell)."
    ),
    "ACH_CONCLUSION_TEXT": (
        "Conclusión Analítica:\n"
        "La hipótesis H2 (Múltiples actores de amenazas oportunistas e independientes) es la más consistente con el conjunto "
        "de evidencias observadas. La hipótesis H3 (Initial Access Broker que traspasa accesos a diferentes operadores) no puede "
        "descartarse por completo, dada la secuencia temporal de ciertos accesos. La hipótesis H1 queda prácticamente refutada "
        "por la redundancia e incompatibilidad de vectores.\n"
        "Nivel de Confianza: BAJO-MEDIO. Esta estimación se encuentra estrictamente condicionada por las brechas de visibilidad "
        "perimetral (carencia de logs de VPN y firewall) que impiden verificar si existió compartición de infraestructura a nivel de transporte."
    ),
    "SECTION_2_7_TITLE": "2.7 Calidad de Datos, Telemetría y Brechas de Visibilidad",
    "VISIBILITY_GAPS": [
        (
            "Ausencia de Logs de Firewall Perimetral y VPN",
            "No se dispone de registros de conexiones entrantes perimetrales, imposibilitando correlacionar las sesiones de red "
            "con identidades VPN, factores de doble autenticación o intentos de intrusión previos a la capa de aplicación.",
        ),
        (
            "Carencia de Telemetría EDR / Sysmon sobre LSASS (T1003)",
            "No se cuenta con eventos de acceso a procesos (Sysmon Event ID 10) que permitan constatar o descartar intentos de volcado "
            "de memoria del proceso lsass.exe en las estaciones de trabajo comprometidas.",
        ),
        (
            "Falta de Registro de Eventos Kerberos (4768 / 4769)",
            "La ausencia de eventos de emisión de TGT (4768) y solicitudes de Ticket de Servicio TGS (4769) genera un punto ciego "
            "crítico ante técnicas avanzadas de Kerberoasting, AS-REP Roasting o Pass-the-Ticket.",
        ),
        (
            "Omisión de Eventos de Logon con Credenciales Explícitas (4648)",
            "No se auditan inicios de sesión mediante 'RunAs' o inyección de credenciales explícitas, dificultando el rastreo fino "
            "de elevaciones secundarias en contexto interactivo.",
        ),
        (
            "Falta de Integración con Inteligencia de Amenazas (CTI / MISP)",
            "Se detecta una dependencia exclusiva de telemetría interna. Las 5 IPs externas pertenecen a rangos de "
            "documentación RFC 5737; el enriquecimiento con threat intel/MISP no arroja coincidencias "
            "(recomiéndase integración formal con plataforma MISP y feeds del CSIRT sectorial).",
        ),
    ],
    "NOTE_EVENT_4672": (
        "Aclaración Técnica Fundamental sobre Evento 4672 (mgarcia):\n"
        "El registro del Event ID 4672 ('Special privileges assigned to new logon') para la cuenta mgarcia en la máquina WS-031 "
        "NO constituyó una escalada técnica de privilegios durante la sesión. El análisis forense indica que la cuenta ya tenía "
        "privilegios sensibles en WS-031, representando una violación directa del Principio de Menor Privilegio (Least Privilege) "
        "en la política de estaciones de usuario corporativas."
    ),
    "BACKUPSVC_INITIAL_VECTOR": (
        "Vector Inicial de Compromiso de backupsvc:\n"
        "El vector inicial por el cual el adversario obtuvo la credencial de la cuenta 'backupsvc' NO pudo ser determinado "
        "a partir de la telemetría disponible. En los eventos de password spraying (INC-01) dicha cuenta fue objeto de intentos "
        "fallidos sin éxito en el log. Por consiguiente, la credencial fue obtenida fuera de banda (volcado previo no registrado, "
        "phishing, reutilización de claves o compromiso de repositorio externo)."
    ),
    "SVC_BACKUP_DC01_ANOMALY": (
        "Anomalías de Calidad de Datos (R14) y Hallazgo Negativo en Active Directory:\n"
        "La regla R14 identificó discrepancias estructurales: la presencia del hostname 'DC01' (sin guion, frente al canónico 'DC-01') "
        "y el uso de la identidad 'CORP\\svc_backup' (frente a la cuenta estándar 'CORP\\backupsvc').\n"
        "Hipótesis para Verificación en Active Directory: Se requiere consultar en el controlador de dominio los atributos "
        "'whenCreated', 'whenChanged', el historial 'sAMAccountName' y el SID del creador del objeto ('objectSid').\n"
        "Hallazgo Negativo Determinante: No existe ningún evento de creación ni modificación de cuentas ni de grupos de seguridad "
        "(Event IDs 4720, 4722, 4728, 4732 o 4738) en toda la telemetría provista. Esto confirma que ninguna de estas entidades "
        "fue creada en caliente durante la ventana de investigación."
    ),
    "SECTION_2_8_TITLE": "2.8 Playbook Operativo de Contención, Erradicación y Recuperación",
    "PLAYBOOK_HEADERS": ["Fase / Incidente", "Objetivo Operativo", "Comando Técnico / Acción Ejecutable"],
    "CONTAINMENT_PLAYBOOKS": [
        [
            "INC-01 (Spraying / WS-031)",
            "Aislamiento de Endpoint y Mitigación de Identidad",
            (
                "1. Aislar máquina vía Defender for Endpoint:\n"
                "   Invoke-RestMethod -Uri 'https://api.securitycenter.microsoft.com/api/machines/WS-031/isolate' -Method Post\n"
                "2. Deshabilitar cuenta comprometida:\n"
                "   Disable-ADAccount -Identity 'mgarcia'\n"
                "3. Revocar sesiones activas de M365/Entra ID:\n"
                "   Revoke-MgUserSignInSession -UserId 'mgarcia@nordicenergy.se'\n"
                "4. Bloquear IP de ataque en Firewall perimetral:\n"
                "   New-NetFirewallRule -DisplayName 'Block-Attacker-203.0.113.74' -Direction Inbound -Action Block -RemoteAddress 203.0.113.74\n"
                "5. Remover mgarcia del grupo de Administradores locales:\n"
                "   Remove-LocalGroupMember -Group 'Administradores' -Member 'CORP\\mgarcia'"
            ),
        ],
        [
            "INC-02 (RDP Brute Force / APP-SRV01)",
            "Contención de RDP y Reseteo de Cuenta Administrativa",
            (
                "1. Bloquear IP de origen RDP:\n"
                "   New-NetFirewallRule -DisplayName 'Block-Attacker-198.51.100.77' -Direction Inbound -Action Block -RemoteAddress 198.51.100.77\n"
                "2. Bloquear conexión saliente de exfiltración:\n"
                "   New-NetFirewallRule -DisplayName 'Block-Outbound-203.0.113.88' -Direction Outbound -Action Block -RemoteAddress 203.0.113.88\n"
                "3. Deshabilitar y resetear contraseña de cuenta admin:\n"
                "   Disable-ADAccount -Identity 'admin'; Set-ADAccountPassword -Identity 'admin' -Reset\n"
                "4. Forzar Network Level Authentication (NLA) obligatorio en RDP:\n"
                "   Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1\n"
                "5. Aislar temporalmente APP-SRV01 para inspección forense de memoria."
            ),
        ],
        [
            "INC-03 (Pre-Ransomware / FS-SRV01, WS-023)",
            "Protección de Almacenamiento y Verificación de Copias",
            (
                "1. Aislamiento preventivo inmediato de FS-SRV01 y WS-023.\n"
                "2. Deshabilitar cuenta backupsvc:\n"
                "   Disable-ADAccount -Identity 'backupsvc'\n"
                "3. Verificación offline de copias de seguridad (WORM / cinta inmutable):\n"
                "   Confirmar integridad de respaldos desconectados no alcanzables por vssadmin delete.\n"
                "4. Restringir acceso al binario vssadmin.exe mediante directiva AppLocker / WDAC."
            ),
        ],
        [
            "INC-04 (Exfiltración Proxy / WS-018)",
            "Interrupción de Canal de Fuga y Saneamiento de Cuentas",
            (
                "1. Bloquear destino proxy en pasarela perimetral:\n"
                "   Set-ProxyBlockRule -Destination '198.51.100.88' -Action Deny\n"
                "2. Deshabilitar cuenta rrojas y cerrar sesiones activas:\n"
                "   Disable-ADAccount -Identity 'rrojas'; Revoke-MgUserSignInSession -UserId 'rrojas@nordicenergy.se'\n"
                "3. Auditoría forense de archivos accedidos en recursos compartidos Finance y Legal."
            ),
        ],
        [
            "INC-05 (Persistencia C2 / APP-SRV01)",
            "Erradicación de Mecanismos de Persistencia y Balizamiento",
            (
                "1. Detener y eliminar servicio malicioso:\n"
                "   Stop-Service -Name 'WinUpdateHelper' -Force\n"
                "   sc.exe delete WinUpdateHelper\n"
                "2. Eliminar tarea programada maliciosa:\n"
                "   schtasks /delete /tn '\\Microsoft\\Windows\\UpdateCheck' /f\n"
                "3. Contención de red y detección de destino C2:\n"
                "   Identificar el destino C2 con EDR/firewall (no observado en la telemetría) y bloquearlo una vez confirmado; aislar APP-SRV01."
            ),
        ],
        [
            "INC-06 (Web Shell / WEB-01)",
            "Erradicación de Web Shell y Blindaje de Servidor Web",
            (
                "1. Aislar de red el servidor web perimetral WEB-01.\n"
                "2. Detener Application Pool de IIS:\n"
                "   Stop-WebAppPool -Name 'DefaultAppPool'\n"
                "3. Eliminar artefacto web shell:\n"
                "   Remove-Item -Path 'C:\\inetpub\\wwwroot\\test.aspx' -Force\n"
                "4. Bloquear dirección IP atacante:\n"
                "   New-NetFirewallRule -DisplayName 'Block-Attacker-192.0.2.91' -Direction Inbound -Action Block -RemoteAddress 192.0.2.91\n"
                "5. Desplegar reglas de inspección WAF para impedir carga y ejecución remota de scripts."
            ),
        ],
    ],
}

# ==============================================================================
# ANEXOS TECNICOS: REGLAS Y GLOSARIO
# ==============================================================================

ANNEX_A = {
    "TITLE": "Anexo A: Reglas de Detección y Umbrales Operativos (R1 a R14)",
    "HEADERS": ["Regla", "Nombre Operativo", "Umbral / Criterio Técnico", "Severidad", "Táctica MITRE"],
    "RULES": [
        ["R1", "Password Spraying", ">= 10 fallos (EID 4625), >= 5 usuarios distintos en 15 min desde IP externa", "Medio", "Credential Access"],
        ["R2", "Fuerza Bruta (Logon/RDP)", ">= 3 fallos (EID 4625) en 10 min sobre el mismo usuario/host desde IP externa", "Medio", "Credential Access"],
        ["R3", "Cuenta Comprometida tras Ataque", "Logon exitoso (EID 4624) dentro de 30 min tras evento R1 o R2", "Alto", "Initial Access"],
        ["R4", "Privilegios en Sesión Comprometida", "4672 en sesión de cuenta comprometida", "Alto", "Privilege Escalation"],
        ["R5", "LOLBins y Comandos Sospechosos", "Invocación de -EncodedCommand, vssadmin delete, tar/7z, whoami, net view o shell bajo IIS", "Alto", "Execution / Impact"],
        ["R6", "Movimiento Lateral (RDP/SMB)", "Logon Tipo 10 (RDP) desde IP externa o Tipo 3 (SMB) por cuenta comprometida", "Alto / Medio", "Lateral Movement"],
        ["R7", "Acceso a Compartidos Sensibles", "Acceso (EID 5140/5145) a shares con Finance, Legal, HR o Confidential", "Alto / Medio", "Collection"],
        ["R8", "Acceso Masivo a Archivos", "Acceso masivo >= 10 objetos 4663 en 5 min", "Medio", "Discovery / Collection"],
        ["R9", "Exfiltración Masiva por Proxy", "Transferencia HTTP POST con suma bytes_out >= 100 MB en 15 min", "Alto", "Exfiltration"],
        ["R10", "Conexión C2 / Exfiltración Saliente", "5156 saliente a IP externa por powershell/cmd, T1041 Exfiltration", "Alto", "Exfiltration / C2"],
        ["R11", "Persistencia (Tareas / Servicios)", "Creación de tarea (EID 4698) o servicio (EID 7045) en rutas de usuario/temp", "Alto", "Persistence"],
        ["R12", "Balizamiento C2 Periódico", "Mismo proceso ejecutado >= 4 veces con jitter < 10%, T1071", "Alto", "Command and Control"],
        ["R13", "Web Shell y Sondeo Web", "Peticiones a .aspx/.php con cmd= o >= 10 sondeos a /admin|/login|/api en 5 min", "Alto / Medio", "Initial Access / Persistence"],
        ["R14", "Anomalía en Calidad de Datos", "Colisión de hostnames normalizados (DC01/DC-01) o cuentas permutadas", "Bajo", "Operacional"],
    ],
}

ANNEX_B = {
    "TITLE": "Anexo B: Glosario de Event IDs y Fuentes de Log Utilizadas",
    "HEADERS": ["Event ID", "Fuente de Telemetría", "Nombre del Evento", "Relevancia Operativa SOC L2"],
    "EVENTS": [
        ["4624", "Security Log", "An account was successfully logged on", "Identificación de inicios de sesión, tipo de logon (3, 10) e IP origen."],
        ["4625", "Security Log", "An account failed to log on", "Detección de ataques de password spraying y fuerza bruta remota."],
        ["4672", "Security Log", "Special privileges assigned to new logon", "Asignación de privilegios administrativos en sesión (least privilege check)."],
        ["4688", "Security Log", "A new process has been created", "Rastreo de ejecución de procesos interactivos y argumentos LOLBins."],
        ["4698", "Security Log", "A scheduled task was created", "Detección de mecanismos de persistencia basados en tareas del sistema."],
        ["4702", "Security Log", "A scheduled task was updated", "Monitoreo de alteraciones en configuraciones de persistencia existentes."],
        ["5140", "Security Log", "A network share object was accessed", "Inspección de acceso a carpetas compartidas en servidores de red."],
        ["5145", "Security Log", "A network share object was checked", "Auditoría detallada de archivos accedidos en recursos sensibles."],
        ["7045", "System Log", "A service was installed in the system", "Identificación de persistencia y elevación mediante servicios de Windows."],
        ["HTTP_ACCESS", "Web Server (IIS)", "Inbound HTTP Request", "Detección de explotación de vulnerabilidades web y ejecución de web shells."],
        ["PROXY_LOG", "Proxy Corporativo", "Outbound HTTP/HTTPS Traffic", "Monitoreo de transferencias masivas de datos y balizamiento periódico C2."],
    ],
}
