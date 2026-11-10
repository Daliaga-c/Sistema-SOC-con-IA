# NIST SP 800-61 Rev 2: Guía de Manejo y Respuesta a Incidentes de Seguridad

## 1. Introducción y Marco Operativo
La publicación especial NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide) establece el estándar de referencia global para la estructuración y operación de Equipos de Respuesta a Incidentes de Seguridad de la Información (CSIRT / SOC). Su objetivo es minimizar la pérdida de datos, salvaguardar la continuidad operativa y asegurar la preservación admisible de evidencia forense mediante un ciclo estructurado y continuo.

## 2. Fase 1: Preparación (Preparation)
La preparación es la piedra angular de una defensa eficaz antes de que ocurra cualquier brecha de seguridad.
- **Políticas y Procedimientos:** Definición rigurosa de líneas base de seguridad, políticas de uso aceptable, matrices de escalamiento formal y acuerdos de nivel de servicio (SLA) para triaje.
- **Herramientas de Adquisición y Análisis:** Despliegue de sensores de EDR/SIEM (Wazuh, Sysmon, Auditd), analizadores de tráfico (Zeek, Suricata) y utilidades forenses de memoria y disco.
- **Kit Forense Jump-Bag:** Medios extraíbles de sólo lectura con software de adquisición forense (FTK Imager CLI, LiME para Linux, WinPmem, KAPE, RegRipper), cables bloqueadores de escritura de hardware (write-blockers) y formularios de cadena de custodia.
- **Inventario y Clasificación de Activos:** Mapeo de activos críticos (Crown Jewels), controladores de dominio (Active Directory), bases de datos transaccionales, repositorios de código y buckets en la nube.
- **Entrenamiento y Simulacros:** Ejecución periódica de simulacros en mesa (Tabletop Exercises) y simulaciones de adversarios tipo Purple Team.

## 3. Fase 2: Detección y Análisis (Detection and Analysis)
La detección efectiva requiere distinguir entre precursores (signos de que un ataque puede ocurrir en el futuro) e indicadores (señales de que un ataque ya ocurrió o está en curso).
- **Vectores de Ataque Primarios:** Ataques web (inyecciones SQL, RCE, SSRF), correo electrónico malicioso (phishing, spear-phishing, archivos adjuntos armados), medios extraíbles, suplantación de identidad (spoofing) y compromisos de credenciales válidas.
- **Análisis y Correlación de Señales:** Correlación en SIEM entre registros de autenticación fallidos, conexiones de red anómalas, creación de procesos sospechosos e integridad de archivos modificados (FIM).
- **Matrices de Severidad y Priorización:**
  - *Crítica (P1):* Compromiso de Controlador de Dominio, exfiltración masiva de bases de datos de clientes, propagación activa de ransomware. Tiempo de respuesta objetivo: < 15 minutos.
  - *Alta (P2):* Compromiso de cuenta administrativa, malware activo en servidor de aplicación sin propagación lateral masiva. Tiempo de respuesta objetivo: < 30 minutos.
  - *Media (P3):* Múltiples alertas de fuerza bruta contra servicios expuestos bloqueadas en borde, detección de adware o escaneos de puertos no exitosos. Tiempo de respuesta: < 2 horas.
  - *Baja (P4):* Eventos aislados de escaneo de baja intensidad o anomalías de comportamiento menores. Tiempo de respuesta: < 8 horas.
- **Documentación Temprana:** Registro minucioso de cada hallazgo en el sistema de tickets del SOC con marcas temporales sincronizadas con NTP fiable.

## 4. Fase 3: Contención, Erradicación y Recuperación (Containment, Eradication, and Recovery)
- **Estrategia de Contención:**
  - *Contención a Corto Plazo:* Aislamiento de red del endpoint infectado (mediante reglas iptables locales o comando `host-deny` / `win_route-null` de Wazuh), bloqueo de direcciones IP o dominios maliciosos en firewall perimetral, revocación inmediata de sesiones web activas y deshabilitación provisional de cuentas de usuario comprometidas.
  - *Contención a Largo Plazo:* Segmentación de subredes, establecimiento de listas de control de acceso (ACLs) restrictivas temporales y redirección de tráfico anómalo a honeypots para inteligencia si procede.
- **Erradicación de la Amenaza:**
  - Identificación y neutralización de todos los artefactos del malware (binarios ejecutables, scripts de powershell/bash, tareas programadas de cron/schtasks, claves de registro Run/RunOnce).
  - Eliminación de canales de comando y control (C2), cierre de puertos no esenciales y remediación de vulnerabilidades explotadas (aplicación de parches de día cero o configuración deficiente).
- **Recuperación Segura:**
  - Restauración de sistemas a partir de copias de seguridad limpias e inmutables verificadas previamente contra malware durmiente.
  - Reemplazo masivo de contraseñas de cuentas afectadas y reinicio de llaves maestras de API y certificados TLS.
  - Endurecimiento previo al despliegue en producción (Hardening CIS Benchmarks) y monitorización intensiva por 72 horas para verificar ausencia de re-infección.

## 5. Fase 4: Actividad Post-Incidente (Post-Incident Activity)
- **Reunión de Lecciones Aprendidas:** Convocada en las 48-72 horas posteriores a la resolución con todos los actores involucrados.
- **Preguntas Obligatorias:** ¿Qué ocurrió exactamente y a qué hora? ¿Qué tan bien respondieron el personal y los procedimientos? ¿Qué información faltaba en las bitácoras? ¿Qué pasos correctivos prevendrán incidentes similares?
- **Métricas Clave:**
  - MTTA (Mean Time to Acknowledge): Tiempo promedio de triaje inicial.
  - MTTC (Mean Time to Contain): Tiempo transcurrido hasta aislar el vector.
  - MTTR (Mean Time to Remediate): Tiempo total hasta el restablecimiento normal del servicio.
- **Retención de Evidencias:** Conservación legal de imágenes forenses, registros de auditoría y reportes durante el período estipulado por normativas sectoriales (e.g. ISO 27001, PCI-DSS, GDPR).

## 6. Preservación Forense y Cadena de Custodia
- **Orden de Volatilidad (RFC 3227):** Memoria RAM y buffers de red -> Estado de conexiones -> Almacenamiento en disco -> Medios ópticos y backups.
- **Adquisición Forense de Memoria:** Volcado en vivo utilizando herramientas confiables (`LiME`, `winpmem`, `DumpIt`) antes de reiniciar o apagar el host para preservar inyectables sin archivo (fileless malware) y claves de cifrado en memoria volátil.
- **Copias Bit a Bit e Integridad:** Adquisición de discos con `dd` o `dc3dd` validando de forma inmutable mediante cálculo de hashes dobles SHA-256 y MD5 al momento de la captura y previo al análisis.
- **Formulario de Cadena de Custodia:** Documento formal que certifica quién obtuvo la evidencia, fecha/hora exacta, ubicación física/lógica, motivo del traspaso y custodia ininterrumpida.
- **Human-in-the-Loop:** Cualquier decisión de contención que implique parada de servicios críticos o alteración irreversible de sistemas debe contar con la validación explícita de un analista o comandante del incidente.