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
    "SUBTITLE": "Investigacion Forense Multi-Incidente - Caso Nordic Shadow",
    "CLIENT": "Sector Energetico Nordico (Operador de Infraestructura Critica)",
    "ORGANIZATION": "CSIRT / IR Estocolmo",
    "CLASSIFICATION": "TLP:AMBER",
    "HEADER_TEXT": "INFORME DE INCIDENTE \u2014 CASO NORDIC SHADOW | TLP:AMBER",
    "FOOTER_TEXT": "Confidencial",
}

# ==============================================================================
# PARTE 1 - RESUMEN EJECUTIVO (ORIENTADO A NEGOCIO Y DIRECCION)
# ==============================================================================

EXECUTIVE_SUMMARY = {
    "SECTION_1_TITLE": "PARTE 1 \u2014 RESUMEN EJECUTIVO",
    "SECTION_1_1_TITLE": "1.1 Que Ocurrio",
    "SECTION_1_1_TEXT": (
        "Durante el periodo de monitorizacion analizado se detecto una cadena coordinada y multifasetica "
        "de incidentes de seguridad que afecto a la infraestructura critica del operador energetico. "
        "El motor de correlacion proceso un total de 715 eventos de telemetria SIEM, identificando 121 eventos "
        "maliciosos agrupados en 6 incidentes de alta criticidad distribuidos en 7 activos clave "
        "(DC-01, APP-SRV01, FS-SRV01, WEB-01, WS-018, WS-023 y WS-031). Los vectores incluyeron ataques "
        "externos de password spraying sobre controladores de dominio, intrusiones remotas via fuerza bruta "
        "RDP, explotacion de servidores web expuestos mediante web shells, desplazamiento lateral hacia servidores "
        "de archivos, exfiltracion masiva de informacion sensible (~253 MB) y ejecucion de comandos destructivos "
        "destinados a eliminar instantaneas de volumen (Volume Shadow Copies) como preparacion previa a ransomware."
    ),
    "SECTION_1_2_TITLE": "1.2 Estado de la Amenaza",
    "SECTION_1_2_STATUS": "Activa hasta confirmar contencion",
    "SECTION_1_2_TEXT": (
        "El estado operacional de la amenaza se califica formalmente como 'Activa hasta confirmar contencion'. "
        "A pesar de que varias fases de ataque han concluido su ventana temporal visible, persisten mecanismos "
        "de persistencia no erradicados (servicio WinUpdateHelper y tarea programada UpdateCheck en APP-SRV01, "
        "asi como la presencia del archivo web shell test.aspx en WEB-01). Asimismo, debido a la naturaleza "
        "de las credenciales comprometidas y a la falta de telemetria perimetral completa, no es posible descartar "
        "canales durmientes de acceso secundario o movimiento lateral adicional no interceptado."
    ),
    "SECTION_1_3_TITLE": "1.3 Impacto en el Negocio",
    "SECTION_1_3_ITEMS": [
        (
            "Exfiltracion Confidencial (~253 MB)",
            "Transferencia masiva no autorizada de documentacion clasificada de las areas de Finanzas y Asuntos "
            "Legales (\\FS-SRV01\\Finance y \\FS-SRV01\\Legal) hacia servidores externos a traves de solicitudes HTTP POST "
            "acumulando ~253 MB. Riesgo critico de espionaje industrial, fuga de propiedad intelectual y dano reputacional.",
        ),
        (
            "Borrado de Instantaneas Pre-Ransomware",
            "Invocacion de 'vssadmin delete shadows /all /quiet' en estaciones de trabajo y servidores de archivos, "
            "inhabilitando la recuperacion local rapida del sistema de archivos. Patron caracteristico de preparacion "
            "inmediata para cifrado extorsivo (ransomware).",
        ),
        (
            "Persistencia en Servidores Criticos de Aplicacion",
            "Instalacion del servicio 'WinUpdateHelper' y de la tarea programada '\\Microsoft\\Windows\\UpdateCheck' en "
            "APP-SRV01, acoplados a ejecuciones continuas de balizamiento C2 a intervalos regulares sin fluctuacion, "
            "permitiendo reconexion autonoma del adversario.",
        ),
        (
            "Compromiso de Servidor Web Perimetral",
            "Explotacion de vulnerabilidad publica e implantacion de web shell 'test.aspx' en WEB-01, otorgando "
            "ejecucion remota de comandos bajo el contexto de identidad 'IIS APPPOOL\\DefaultAppPool'.",
        ),
    ],
    "SECTION_1_4_TITLE": "1.4 Cumplimiento Normativo: RGPD y Directiva NIS2",
    "SECTION_1_4_RGPD": (
        "Notificacion RGPD (Articulo 33):\n"
        "La evidencia forense constata la exfiltracion exitosa de documentos corporativos sensibles que incluyen "
        "datos de recursos humanos, contratos legales y transacciones financieras vinculadas a personas fisicas identificables. "
        "De conformidad con el Articulo 33 del Reglamento General de Proteccion de Datos (RGPD / GDPR), la entidad tiene la "
        "obligacion legal de notificar la brecha de seguridad a la Autoridad de Proteccion de Datos de Suecia "
        "(IMY - Integritetsskyddsmyndigheten) dentro del plazo maximo de 72 horas desde que se tuvo constancia del incidente. "
        "Asimismo, se debe evaluar el impacto sobre los interesados para determinar la necesidad de comunicacion directa (Art. 34)."
    ),
    "SECTION_1_4_NIS2": (
        "Directiva NIS2 (Operador Esencial del Sector Energetico):\n"
        "Al tratarse de una entidad del sector de la energia catalogada como Operador Esencial bajo la Directiva NIS2 "
        "(Directiva UE 2022/2555), rigen los plazos estrictos de notificacion obligatoria de incidentes significativos:\n"
        "  1. Alerta Temprana (24 horas): Emision de una alerta temprana ante la autoridad competente (MSB / CSIRT Nacional de Suecia) "
        "dentro de las 24 horas siguientes al conocimiento del incidente con sospecha de intencionalidad o impacto transfronterizo.\n"
        "  2. Notificacion de Incidente (72 horas): Actualizacion con evaluacion inicial de gravedad, consecuencias e indicadores de compromiso.\n"
        "  3. Informe Final (1 mes): Entrega de reporte tecnico y forense exhaustivo con causas raiz, medidas mitigadoras e impacto cuantificado."
    ),
    "SECTION_1_5_TITLE": "1.5 Prioridades Recomendadas de Mitigacion",
    "RECOMMENDED_PRIORITIES_HEADERS": ["Prioridad", "Accion Operativa", "Responsable", "Plazo"],
    "RECOMMENDED_PRIORITIES": [
        [
            "P1 (Inmediata)",
            "Aislamiento de red de hosts comprometidos (WEB-01, APP-SRV01, FS-SRV01, WS-018, WS-023, WS-031) y bloqueo en firewall perimetral de las 5 IPs atacantes externas.",
            "SecOps / SOC L2",
            "< 2 horas",
        ],
        [
            "P2 (Critica)",
            "Revocacion inmediata de tokens y reseteo de contraseñas de cuentas vulneradas (mgarcia, backupsvc, rrojas, admin); remocion de privilegios de admin local a mgarcia en WS-031.",
            "Identity / SysAdmin",
            "< 4 horas",
        ],
        [
            "P3 (Regulatoria)",
            "Emision de Alerta Temprana NIS2 ante el CSIRT Nacional (MSB) y preparacion de la notificacion formal ante IMY por brecha de datos personales RGPD Art. 33.",
            "DPO / Legal / CISO",
            "< 24 h (NIS2) / < 72 h (RGPD)",
        ],
        [
            "P4 (Erradicacion)",
            "Eliminacion de artefactos de persistencia: borrado de servicio WinUpdateHelper y tarea programada UpdateCheck en APP-SRV01; eliminacion de web shell test.aspx en WEB-01.",
            "Incident Response",
            "< 24 horas",
        ],
        [
            "P5 (Resiliencia)",
            "Auditoria de copias de seguridad offline (inmutables/WORM); imposicion estricta de MFA en todos los accesos externos y RDP; despliegue de Sysmon con Hash=SHA256.",
            "Arquitectura TI / CISO",
            "48 a 72 horas",
        ],
    ],
    "SECTION_1_6_TITLE": "1.6 Matriz de Riesgo por Incidente",
    "RISK_MATRIX_HEADERS": ["Incidente", "Titulo Operativo", "Nivel de Riesgo", "Justificacion de Negocio"],
    "RISK_MATRIX": [
        [
            "INC-01",
            "Password spraying y compromiso de cuenta privilegiada",
            "Alto",
            "Compromiso de credenciales corporativas (mgarcia) en WS-031 con privilegios locales preexistentes.",
        ],
        [
            "INC-02",
            "Fuerza bruta RDP, intrusion y movimiento lateral",
            "Alto",
            "Intrusion exitosa sobre cuenta admin hacia APP-SRV01 y salto lateral a FS-SRV01.",
        ],
        [
            "INC-03",
            "Actividad previa a ransomware y borrado de copias shadow",
            "Critico",
            "Destruccion de instantaneas de volumen vssadmin y acceso masivo a archivos de red.",
        ],
        [
            "INC-04",
            "Exfiltracion masiva de documentos confidenciales via proxy",
            "Critico",
            "Fuga comprobada de ~253 MB de contratos legales y registros financieros hacia servidor externo.",
        ],
        [
            "INC-05",
            "Persistencia mediante tarea y servicio con balizamiento C2",
            "Alto",
            "Canal de mando y control persistente en servidor de aplicaciones mediante balizamiento regular.",
        ],
        [
            "INC-06",
            "Compromiso de servidor web por web shell y ejecucion remota",
            "Alto",
            "Servidor perimetral WEB-01 comprometido con shell aspx interactiva y reconocimiento local.",
        ],
    ],
}

# ==============================================================================
# PARTE 2 - RESUMEN TECNICO (DETALLADO PARA ANALISTAS E INGENIERIA)
# ==============================================================================

TECHNICAL_SUMMARY = {
    "SECTION_2_TITLE": "PARTE 2 \u2014 RESUMEN TECNICO Y EVIDENCIA FORENSE",
    "SECTION_2_1_TITLE": "2.1 Alcance, Metodologia e Integridad de Telemetria",
    "SECTION_2_1_TEXT": (
        "La presente investigacion forense abarca la ingestion y analisis de la telemetria provista en formato SIEM, "
        "que integra registros de seguridad de Windows Event Logs (Domain Controllers, servidores miembros y estaciones de trabajo), "
        "logs de proxy corporativo HTTP y eventos de monitorizacion de procesos.\n"
        "Metodologia:\n"
        "  1. Integridad Criptografica: Verificacion de la muestra original mediante calculo de resumen SHA-256.\n"
        "  2. Motor de Correlacion Generico: Aplicacion de 14 reglas de deteccion (R1 a R14) basadas en umbrales estadisticos, "
        "patrones LOLBins y ventanas temporales, sin filtros de entidades hardcodeadas.\n"
        "  3. Agrupacion de Incidentes: Algoritmo de clustering temporal y de conectividad con ventana maxima de inactividad de 30 minutos.\n"
        "  4. Taxonomia MITRE ATT&CK: Mapeo de eventos contra tecnicas y tacticas de la matriz Enterprise v14.\n"
        "  5. Extraccion de IoCs: Consolidacion de direcciones IP externas, identidades vulneradas, nombres de host, rutas y artefactos.\n"
        "Limitaciones: La telemetria provista carece de logs de cortafuegos de borde, registros de VPN, eventos de autenticacion "
        "Kerberos (4768/4769) y hashes criptograficos en creacion de procesos (Sysmon EID 1)."
    ),
    "SECTION_2_2_TITLE": "2.2 Resumen Consolidado de Incidentes",
    "INCIDENTS_TABLE_HEADERS": ["ID", "Titulo", "Ventana Temporal", "Hosts Afectados", "Cuentas", "Tecnicas MITRE"],
    "SECTION_2_3_TITLE": "2.3 Linea de Tiempo Detallada por Incidente (Log_IDs)",
    "TIMELINE_HEADERS": ["Log_ID", "Timestamp", "Host", "Usuario", "EID", "Detalle / Linea de Comando", "Severidad"],
    "SECTION_2_4_TITLE": "2.4 Matriz MITRE ATT&CK Consolidada",
    "MITRE_HEADERS": ["Tactica", "Tecnica", "ID", "Incidentes", "Evidencia Log_ID"],
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
    "IOC_TABLE_HEADERS": ["Tipo", "Valor / Indicador", "Contexto Forense", "Incidente", "Primer Visto", "Ultimo Visto"],
    "IOC_HASHES_NOTE": (
        "Nota Explicita sobre Hashes Criptograficos:\n"
        "Hashes de archivos: No disponibles en la telemetria provista. La configuracion de auditoria de creacion "
        "de procesos en los registros de seguridad no incluyo la captura de hashes criptograficos (SHA-256 o MD5). "
        "Se recomienda desplegar Sysmon con el Event ID 1 configurado para registrar hashes SHA-256 de forma obligatoria."
    ),
    "SECTION_2_6_TITLE": "2.6 Correlacion y Analisis de Atribucion (Metodologia ACH)",
    "ACH_INTRO": (
        "Para determinar la naturaleza y origen de los ataques observados, se aplico la metodologia de Analisis de "
        "Hipotesis Competitivas (ACH - Analysis of Competing Hypotheses), evaluando sistematicamente la evidencia tecnica "
        "frente a tres hipotesis mutuamente excluyentes."
    ),
    "ACH_HYPOTHESES": {
        "H1": "Un unico actor de amenazas coordinado ejecutando una campana de intrusion lineal y estructurada.",
        "H2": "Multiples actores de amenazas oportunistas e independientes actuando de manera concurrente.",
        "H3": "Un Initial Access Broker (IAB) que obtuvo accesos iniciales y los traspaso o vendio a operadores independientes.",
    },
    "ACH_EVIDENCE_HEADERS": ["Evidencia / Factor Observado", "H1 (Unico)", "H2 (Multiples)", "H3 (IAB + Operadores)"],
    "ACH_EVIDENCE_TABLE": [
        [
            "Direcciones IP de origen disjuntas por incidente (203.0.113.74, 198.51.100.77, 192.0.2.91, 203.0.113.88, 198.51.100.88)",
            "Inconsistente (-)",
            "Muy Consistente (++)",
            "Consistente (+)",
        ],
        [
            "Divergencia radical de TTPs (Spraying masivo vs RDP Brute Force vs Web Shell vs Exfiltracion HTTP vs vssadmin)",
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
            "Ataque externo por fuerza bruta RDP a cuenta admin (redundante e ilogico si un unico actor ya tenia acceso interno)",
            "Muy Inconsistente (--)",
            "Muy Consistente (++)",
            "Consistente (+)",
        ],
        [
            "Ausencia total de volcado de credenciales en memoria (LSASS/Mimikatz) en la estacion WS-031 tras el acceso",
            "Inconsistente (-)",
            "Consistente (+)",
            "Consistente (+)",
        ],
    ],
    "ACH_ANALYSIS_TEXT": (
        "Evaluacion Forense de la Evidencia:\n"
        "1. Infraestructura de Red Dispar: Cada incidente opera desde una direccion IP publica completamente diferenciada "
        "sin solapamiento temporal ni de rangos AS. No se observan pivotes desde las mismas maquinas perimetrales.\n"
        "2. Redundancia Tactica: La cuenta 'admin' es atacada mediante fuerza bruta RDP externa sobre APP-SRV01 a las 09:15, "
        "lo cual resulta operativo y tacticamente redundante para un actor unico que ya habia consolidado acceso con privilegios "
        "administrativos en WS-031 a las 08:35.\n"
        "3. Comportamiento Estanco de Cuentas: La identidad 'mgarcia' queda inerte tras las 08:40. En paralelo, 'backupsvc' y 'rrojas' "
        "aparecen en fases posteriores en hosts diferentes sin trazas de movimiento lateral cruzado entre dichas cuentas.\n"
        "4. Perfil Operacional Heterogeneo: Coexisten tecnicas tipicas de ransomware oportunista (eliminacion ruidosa de vssadmin), "
        "ciberespionaje/fuga de datos (exfiltracion silenciosa vía proxy de Legal/Finanzas) y explotacion perimetral web clasica (web shell)."
    ),
    "ACH_CONCLUSION_TEXT": (
        "Conclusion Analitica:\n"
        "La hipotesis H2 (Multiples actores de amenazas oportunistas e independientes) es la mas consistente con el conjunto "
        "de evidencias observadas. La hipotesis H3 (Initial Access Broker que traspasa accesos a diferentes operadores) no puede "
        "descartarse por completo, dada la secuencia temporal de ciertos accesos. La hipotesis H1 queda practicamente refutada "
        "por la redundancia e incompatibilidad de vectores.\n"
        "Nivel de Confianza: BAJO-MEDIO. Esta estimacion se encuentra estrictamente condicionada por las brechas de visibilidad "
        "perimetral (carencia de logs de VPN y firewall) que impiden verificar si existio comparticion de infraestructura a nivel de transporte."
    ),
    "SECTION_2_7_TITLE": "2.7 Calidad de Datos, Telemetria y Brechas de Visibilidad",
    "VISIBILITY_GAPS": [
        (
            "Ausencia de Logs de Firewall Perimetral y VPN",
            "No se dispone de registros de conexiones entrantes perimetrales, imposibilitando correlacionar las sesiones de red "
            "con identidades VPN, factores de doble autenticacion o intentos de intrusion previos a la capa de aplicacion.",
        ),
        (
            "Carencia de Telemetria EDR / Sysmon sobre LSASS (T1003)",
            "No se cuenta con eventos de acceso a procesos (Sysmon Event ID 10) que permitan constatar o descartar intentos de volcado "
            "de memoria del proceso lsass.exe en las estaciones de trabajo comprometidas.",
        ),
        (
            "Falta de Registro de Eventos Kerberos (4768 / 4769)",
            "La ausencia de eventos de emision de TGT (4768) y solicitudes de Ticket de Servicio TGS (4769) genera un punto ciego "
            "critico ante tecnicas avanzadas de Kerberoasting, AS-REP Roasting o Pass-the-Ticket.",
        ),
        (
            "Omision de Eventos de Logon con Credenciales Explicitas (4648)",
            "No se auditan inicios de sesion mediante 'RunAs' o inyeccion de credenciales explicitas, dificultando el rastreo fino "
            "de elevaciones secundarias en contexto interactivo.",
        ),
        (
            "Falta de Integracion con Inteligencia de Amenazas (CTI / MISP)",
            "Se detecta una dependencia exclusiva de telemetria interna sin contraste automatizado contra fuentes de CTI de la industria "
            "energetica europea (recomiendase integracion formal con plataforma MISP y feeds del CSIRT sectorial).",
        ),
    ],
    "NOTE_EVENT_4672": (
        "Aclaracion Tecnica Fundamental sobre Evento 4672 (mgarcia):\n"
        "El registro del Event ID 4672 ('Special privileges assigned to new logon') para la cuenta mgarcia en la maquina WS-031 "
        "NO constituyo una escalada tecnica de privilegios durante la sesion. El analisis forense confirma que la cuenta mgarcia "
        "YA pertenecia previamente al grupo local de Administradores de la estacion de trabajo, representando una violacion directa "
        "del Principio de Menor Privilegio (Least Privilege) en la politica de estaciones de usuario corporativas."
    ),
    "BACKUPSVC_INITIAL_VECTOR": (
        "Vector Inicial de Compromiso de backupsvc:\n"
        "El vector inicial por el cual el adversario obtuvo la credencial de la cuenta 'backupsvc' NO pudo ser determinado "
        "a partir de la telemetria disponible. En los eventos de password spraying (INC-01) dicha cuenta fue objeto de intentos "
        "fallidos sin exito en el log. Por consiguiente, la credencial fue obtenida fuera de banda (volcado previo no registrado, "
        "phishing, reutilizacion de claves o compromiso de repositorio externo)."
    ),
    "SVC_BACKUP_DC01_ANOMALY": (
        "Anomalias de Calidad de Datos (R14) y Hallazgo Negativo en Active Directory:\n"
        "La regla R14 identifico discrepancias estructurales: la presencia del hostname 'DC01' (sin guion, frente al canonico 'DC-01') "
        "y el uso de la identidad 'CORP\\svc_backup' (frente a la cuenta estandar 'CORP\\backupsvc').\n"
        "Hipotesis para Verificacion en Active Directory: Se requiere consultar en el controlador de dominio los atributos "
        "'whenCreated', 'whenChanged', el historial 'sAMAccountName' y el SID del creador del objeto ('objectSid').\n"
        "Hallazgo Negativo Determinante: No existe ningun evento de creacion ni modificacion de cuentas ni de grupos de seguridad "
        "(Event IDs 4720, 4722, 4728, 4732 o 4738) en toda la telemetria provista. Esto confirma que ninguna de estas entidades "
        "fue creada en caliente durante la ventana de investigacion."
    ),
    "SECTION_2_8_TITLE": "2.8 Playbook Operativo de Contencion, Erradicacion y Recuperacion",
    "PLAYBOOK_HEADERS": ["Fase / Incidente", "Objetivo Operativo", "Comando Tecnico / Accion Ejecutable"],
    "CONTAINMENT_PLAYBOOKS": [
        [
            "INC-01 (Spraying / WS-031)",
            "Aislamiento de Endpoint y Mitigacion de Identidad",
            (
                "1. Aislar maquina via Defender for Endpoint:\n"
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
            "Contencion de RDP y Reseteo de Cuenta Administrativa",
            (
                "1. Bloquear IP de origen RDP:\n"
                "   New-NetFirewallRule -DisplayName 'Block-Attacker-198.51.100.77' -Direction Inbound -Action Block -RemoteAddress 198.51.100.77\n"
                "2. Deshabilitar y resetear contraseña de cuenta admin:\n"
                "   Disable-ADAccount -Identity 'admin'; Set-ADAccountPassword -Identity 'admin' -Reset\n"
                "3. Forzar Network Level Authentication (NLA) obligatorio en RDP:\n"
                "   Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1\n"
                "4. Aislar temporalmente APP-SRV01 para inspeccion forense de memoria."
            ),
        ],
        [
            "INC-03 (Pre-Ransomware / FS-SRV01, WS-023)",
            "Proteccion de Almacenamiento y Verificacion de Copias",
            (
                "1. Aislamiento preventivo inmediato de FS-SRV01 y WS-023.\n"
                "2. Deshabilitar cuenta backupsvc:\n"
                "   Disable-ADAccount -Identity 'backupsvc'\n"
                "3. Verificacion offline de copias de seguridad (WORM / cinta inmutable):\n"
                "   Confirmar integridad de respaldos desconectados no alcanzables por vssadmin delete.\n"
                "4. Restringir acceso al binario vssadmin.exe mediante directiva AppLocker / WDAC."
            ),
        ],
        [
            "INC-04 (Exfiltracion Proxy / WS-018)",
            "Interrupcion de Canal de Fuga y Saneamiento de Cuentas",
            (
                "1. Bloquear destino proxy en pasarela perimetral:\n"
                "   Set-ProxyBlockRule -Destination '203.0.113.88' -Action Deny\n"
                "2. Deshabilitar cuenta rrojas y cerrar sesiones activas:\n"
                "   Disable-ADAccount -Identity 'rrojas'; Revoke-MgUserSignInSession -UserId 'rrojas@nordicenergy.se'\n"
                "3. Auditoria forense de archivos accedidos en recursos compartidos Finance y Legal."
            ),
        ],
        [
            "INC-05 (Persistencia C2 / APP-SRV01)",
            "Erradicacion de Mecanismos de Persistencia y Balizamiento",
            (
                "1. Detener y eliminar servicio malicioso:\n"
                "   Stop-Service -Name 'WinUpdateHelper' -Force\n"
                "   sc.exe delete WinUpdateHelper\n"
                "2. Eliminar tarea programada maliciosa:\n"
                "   schtasks /delete /tn '\\Microsoft\\Windows\\UpdateCheck' /f\n"
                "3. Bloquear IP de balizamiento C2:\n"
                "   New-NetFirewallRule -DisplayName 'Block-C2-198.51.100.88' -Direction Outbound -Action Block -RemoteAddress 198.51.100.88"
            ),
        ],
        [
            "INC-06 (Web Shell / WEB-01)",
            "Erradicacion de Web Shell y Blindaje de Servidor Web",
            (
                "1. Aislar de red el servidor web perimetral WEB-01.\n"
                "2. Detener Application Pool de IIS:\n"
                "   Stop-WebAppPool -Name 'DefaultAppPool'\n"
                "3. Eliminar artefacto web shell:\n"
                "   Remove-Item -Path 'C:\\inetpub\\wwwroot\\test.aspx' -Force\n"
                "4. Bloquear direccion IP atacante:\n"
                "   New-NetFirewallRule -DisplayName 'Block-Attacker-192.0.2.91' -Direction Inbound -Action Block -RemoteAddress 192.0.2.91\n"
                "5. Desplegar reglas de inspeccion WAF para impedir carga y ejecucion remota de scripts."
            ),
        ],
    ],
}

# ==============================================================================
# ANEXOS TECNICOS: REGLAS Y GLOSARIO
# ==============================================================================

ANNEX_A = {
    "TITLE": "Anexo A: Reglas de Deteccion y Umbrales Operativos (R1 a R14)",
    "HEADERS": ["Regla", "Nombre Operativo", "Umbral / Criterio Tecnico", "Severidad", "Tactica MITRE"],
    "RULES": [
        ["R1", "Password Spraying", ">= 10 fallos (EID 4625), >= 5 usuarios distintos en ventana de 15 min", "Medio", "Credential Access"],
        ["R2", "Fuerza Bruta RDP / Logon", ">= 3 fallos (EID 4625) en ventana de 10 min sobre el mismo usuario/host", "Medio", "Credential Access"],
        ["R3", "Exito Tras Ataque", "Logon exitoso (EID 4624) dentro de 30 min tras evento R1 o R2", "Alto", "Initial Access"],
        ["R4", "Logon Anomalo / Administrador", "Logon con cuenta de servicio o privilegiada fuera de horario / interactivo", "Medio", "Initial Access"],
        ["R5", "LOLBins y Comandos Sospechosos", "Invocacion de vssadmin delete, tar/zip, whoami, certutil, mimikatz", "Alto", "Execution / Impact"],
        ["R6", "Movimiento Lateral (RDP/SMB)", "Logon Tipo 10 (RDP) o Tipo 3 (SMB) entre estaciones y servidores", "Medio", "Lateral Movement"],
        ["R7", "Acceso a Datos Sensibles", "Acceso a recursos compartidos conteniendo Finance, Legal, HR", "Medio", "Collection"],
        ["R8", "Acceso Masivo a Archivos", ">= 10 eventos de lectura en recursos compartidos en menos de 5 min", "Alto", "Collection"],
        ["R9", "Exfiltracion via Proxy", "Transferencia HTTP POST > 100 MB acumulados en menos de 15 min", "Alto", "Exfiltration"],
        ["R10", "Doble Extension / Nombres Sospechosos", "Ejecucion de archivos con doble extension (.pdf.exe) o nombres aleatorios", "Medio", "Defense Evasion"],
        ["R11", "Persistencia (Servicios / Tareas)", "Creacion de servicios (7045) o tareas programadas (4698) en ProgramData/Temp", "Alto", "Persistence"],
        ["R12", "Balizamiento C2 Periodico", ">= 4 conexiones hacia el mismo destino con fluctuacion (jitter) < 10%", "Alto", "Command and Control"],
        ["R13", "Web Shell y Sondeo Web", "Peticiones a .aspx/.php con parametros cmd= o > 10 sondeos en 5 min", "Alto", "Persistence / Initial Access"],
        ["R14", "Anomalia en Calidad de Datos", "Discrepancias de formato (DC01 vs DC-01, svc_backup) o corrupcion de logs", "Bajo", "Operacional"],
    ],
}

ANNEX_B = {
    "TITLE": "Anexo B: Glosario de Event IDs y Fuentes de Log Utilizadas",
    "HEADERS": ["Event ID", "Fuente de Telemetria", "Nombre del Evento", "Relevancia Operativa SOC L2"],
    "EVENTS": [
        ["4624", "Security Log", "An account was successfully logged on", "Identificacion de inicios de sesion, tipo de logon (3, 10) e IP origen."],
        ["4625", "Security Log", "An account failed to log on", "Deteccion de ataques de password spraying y fuerza bruta remota."],
        ["4672", "Security Log", "Special privileges assigned to new logon", "Asignacion de privilegios administrativos en sesion (least privilege check)."],
        ["4688", "Security Log", "A new process has been created", "Rastreo de ejecucion de procesos interactivos y argumentos LOLBins."],
        ["4698", "Security Log", "A scheduled task was created", "Deteccion de mecanismos de persistencia basados en tareas del sistema."],
        ["4702", "Security Log", "A scheduled task was updated", "Monitoreo de alteraciones en configuraciones de persistencia existentes."],
        ["5140", "Security Log", "A network share object was accessed", "Inspeccion de acceso a carpetas compartidas en servidores de red."],
        ["5145", "Security Log", "A network share object was checked", "Auditoria detallada de archivos accedidos en recursos sensibles."],
        ["7045", "System Log", "A service was installed in the system", "Identificacion de persistencia y elevacion mediante servicios de Windows."],
        ["HTTP_ACCESS", "Web Server (IIS)", "Inbound HTTP Request", "Deteccion de explotacion de vulnerabilidades web y ejecucion de web shells."],
        ["PROXY_LOG", "Proxy Corporativo", "Outbound HTTP/HTTPS Traffic", "Monitoreo de transferencias masivas de datos y balizamiento periodico C2."],
    ],
}
