# MITRE ATT&CK: Técnicas de Acceso Inicial y Compromiso de Credenciales (T1110 y T1078)

## 1. Técnica T1110 - Brute Force (Fuerza Bruta)
La técnica T1110 engloba los métodos mediante los cuales los adversarios intentan obtener acceso no autorizado adivinando o descifrando sistemáticamente contraseñas de cuentas de usuario.

### Subtécnicas Detalladas
- **T1110.001 - Password Guessing (Adivinación de Contraseñas):** El atacante prueba contraseñas de alta probabilidad contra un conjunto reducido de nombres de usuario conocidos (por ejemplo, `admin`, `root`, `soporte`, `backup`). Utiliza diccionarios específicos basados en el nombre de la empresa, estaciones del año o patrones comunes (`Empresa2024!`).
- **T1110.002 - Password Cracking (Descifrado de Contraseñas):** Descifrado offline de hashes de contraseñas obtenidos previamente a través de volcados de SAM, ntds.dit, Kerberoasting (`T1558.003`) o `/etc/shadow`. Emplea aceleración por GPU (herramientas como Hashcat o John the Ripper) con tablas rainbow o ataques basados en reglas.
- **T1110.003 - Password Spraying (Rociado de Contraseñas):** Técnica evasiva donde el atacante prueba una única contraseña común (`Invierno2024#`) contra miles de cuentas de dominio. Esto evita intencionalmente activar las políticas de bloqueo por intentos fallidos consecutivos en un solo usuario.
- **T1110.004 - Credential Stuffing (Relleno de Credenciales):** Uso automatizado de listas masivas de pares usuario/contraseña filtrados en brechas de seguridad públicas externas, aprovechando que los usuarios reutilizan credenciales en múltiples servicios personales y corporativos.

## 2. Técnica T1078 - Valid Accounts (Cuentas Válidas)
Los adversarios obtienen y usan credenciales legítimas existentes en la organización para acceder a los sistemas, pasar desapercibidos y eludir controles defensivos basados exclusivamente en firmas de malware.

### Subtécnicas Detalladas
- **T1078.001 - Default Accounts (Cuentas por Defecto):** Acceso abusando de credenciales predeterminadas de fábrica en enrutadores, switches, firewalls, dispositivos IoT, bases de datos (`sa`, `postgres`) o software empaquetado no modificado tras su instalación.
- **T1078.002 - Domain Accounts (Cuentas de Dominio):** Compromiso y reutilización de identidades administradas por Active Directory / LDAP. Permite el acceso transversal a recursos de red, carpetas compartidas y aplicaciones corporativas integradas en Kerberos/NTLM.
- **T1078.003 - Local Accounts (Cuentas Locales):** Uso de credenciales de usuario o administrador configuradas localmente en endpoints o servidores (`Administrator`, `LocalAdmin`). Si la contraseña es homogénea en múltiples equipos, permite movimiento lateral sin interactuar con el controlador de dominio.
- **T1078.004 - Cloud Accounts (Cuentas en la Nube):** Uso ilegítimo de credenciales de consolas de gestión en AWS, Azure, Google Cloud o Microsoft 365, así como llaves de acceso de Service Accounts o tokens de infraestructura de nube.

## 3. Indicadores de Compromiso (IoCs) y Detección en Wazuh y SIEM

### Reglas de Wazuh para Entornos Linux / SSH
- **Regla 5710:** Fallo de autenticación SSH individual (`Failed password for invalid user` o `Failed password for accepted user`).
- **Regla 5712:** Detección de ráfaga de intentos fallidos en ventana de tiempo estrecha (típica de T1110.001 o T1110.004). Nivel de alerta 10.
- **Regla 5716:** Autenticación fallida vía módulo PAM en el sistema operativo.
- **Regla 5760:** Detección de autenticación exitosa inmediatamente precedida de múltiples intentos fallidos (patrón de compromiso exitoso post-fuerza bruta). Alerta de máxima prioridad en el SOC.

### Event IDs de Windows Security (Auditoría Avanzada)
- **Event ID 4625 (Logon Failure):** Intento fallido de inicio de sesión.
  - Código Substatus `0xC000006A`: Nombre de usuario correcto pero contraseña errónea.
  - Código Substatus `0xC0000064`: Nombre de usuario inexistente (Password Guessing).
  - Código Substatus `0xC0000234`: La cuenta ha sido bloqueada tras exceder el límite de intentos.
- **Event ID 4624 (Successful Logon):** Inicio de sesión exitoso. Analizar LogonType:
  - *Tipo 2:* Interactivo local.
  - *Tipo 3:* Red (SMB, Kerberos, carpetas compartidas).
  - *Tipo 10:* RemoteInteractive (RDP - escritorio remoto).
- **Event ID 4672 (Special Privileges Assigned):** Inicio de sesión asignando privilegios administrativos (`SeDebugPrivilege`, `SeTcbPrivilege`).
- **Event ID 4776:** Validación de credenciales NTLM en Domain Controller (fallos o éxitos con paquetes NTLM anómalos).

### Patrones de Anomalía Comportamental
- Intentos de inicio de sesión simultáneos desde ubicaciones geográficas incompatibles (viaje imposible / impossible travel).
- Inicios de sesión en horarios no operativos (e.g. 03:00 AM) para usuarios con horario de oficina regular.
- Solicitudes masivas de autenticación originadas desde direcciones IP identificadas como proxies anónimos o nodos de salida Tor.

## 4. Mitigaciones y Contramedidas Defensivas
- **MFA Robusto FIDO2 / WebAuthn:** Obligatoriedad de autenticación multifactor resistente a ataques de intermediario (AiTM) para todos los servicios externos y accesos VPN/RDP.
- **Bloqueo Inteligente y Rate Limiting:** Configuración de Smart Lockout (como en Azure AD) que bloquea intentos del atacante sin bloquear al usuario legítimo basándose en la reputación de la IP y la huella del navegador.
- **Integración con Threat Intelligence:** Bloqueo automatizado en gateway perimetral de IPs con mala reputación reportadas por AbuseIPDB, AlienVault OTX o feeds internos del SOC.
- **Gestión de Cuentas Locales con LAPS:** Despliegue de Windows LAPS para asegurar que cada endpoint mantenga una contraseña de administrador local única, aleatoria y rotada automáticamente.
- **Deshabilitación de Cuentas por Defecto y Cuentas Huérfanas:** Revisión mensual de cuentas de usuarios inactivos por más de 30 días y desactivación estricta de cuentas de servicio no asignadas.