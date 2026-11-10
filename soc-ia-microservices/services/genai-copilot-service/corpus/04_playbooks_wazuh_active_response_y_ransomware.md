# Playbooks Operativos del SOC: Wazuh Active Response, Ransomware y Fuga de Tokens

## 1. Playbook 1: Contención con Wazuh Active Response bajo Supervisión Human-in-the-Loop

### Objetivo y Arquitectura de Respuesta Activa
El módulo Active Response de Wazuh permite la ejecución automatizada o teledirigida de scripts correctivos en endpoints cuando se activan reglas de alerta de alto nivel. Para evitar denegaciones de servicio accidentales en infraestructuras productivas, el SOC opera bajo el principio estricto de **Human-in-the-Loop (HITL)** para toda acción destructiva o aislante.

### Comandos de Contención Estandarizados
- `firewall-drop0` (Linux): Agrega una regla temporal a `iptables` / `nftables` bloqueando todo el tráfico hacia y desde una dirección IP externa hostil identificada.
- `host-deny` (Linux): Añade la dirección IP agresora a `/etc/hosts.deny` impidiendo conexiones hacia servicios que utilicen TCP Wrappers.
- `win_route-null` (Windows): Añade una ruta nula (`route add <IP> mask 255.255.255.255 0.0.0.0`) o una regla en Windows Advanced Firewall para neutralizar la comunicación con la dirección IP atacante.

### Protocolo de Decisión y Aprobación Human-in-the-Loop
1. **Detección y Pre-Validación Automática:**
   - Wazuh alerta de ataque de fuerza bruta o escaneo persistente (Reglas 5712, 5760 o alertas Nivel >= 10).
   - El Copilot de IA consulta la reputación de la IP en el Threat Intelligence Service y presenta el dictamen al analista del SOC con score de abuso y geolocalización.
2. **Evaluación Humana (Gate de Aprobación):**
   - El analista N1 verifica si la IP pertenece a proveedores legítimos, gateways de sucursales o clientes conocidos (lista blanca corporativa).
   - Si la IP es ilegítima y el score es crítico (>80%), el analista aprueba la ejecución de la contención.
3. **Ejecución y Monitoreo:**
   - Se despacha la orden de bloqueo al agente correspondiente fijando un tiempo de expiración estándar (por defecto 600 segundos para bloqueos temporales, o indefinido con confirmación de N2).
   - Verificación de la cesación del tráfico hostil en los logs del firewall.

## 2. Playbook 2: Respuesta y Mitigación ante Brote de Ransomware y Exfiltración

### Detección Temprana e Indicadores de Compromiso
- Modificación masiva y acelerada de extensiones de archivo en múltiples directorios detectada por el módulo FIM de Wazuh.
- Creación de notas de rescate típicas (`README_RESTORE_FILES.txt`, `HOW_TO_DECRYPT.html`) alertadas por Sysmon Event ID 11.
- Ejecución de comandos de eliminación de copias de seguridad de volumen sombra:
  - `vssadmin.exe delete shadows /all /quiet`
  - `wmic shadowcopy delete`
  - `wbadmin delete catalog -quiet`
  - `bcdedit /set {default} recoveryenabled No`

### Fase A: Contención Inmediata y Aislamiento de Red
1. **Aislamiento Físico y Lógico del Endpoint:**
   - Desconectar inmediatamente el cable de red o deshabilitar la interfaz de red virtual en el hipervisor.
   - Si el endpoint cuenta con agente EDR/Wazuh activo, enviar comando de aislamiento de red (aislando todo tráfico excepto la comunicación segura con el servidor del SOC).
2. **Preservación Obligatoria del Estado de Energía (NO APAGAR):**
   - **CRÍTICO:** NO reiniciar ni apagar el equipo. El apagado destruye la memoria volátil donde pueden residir las claves criptográficas simétricas (AES) del ransomware antes de ser eliminadas.
3. **Captura Forense de Memoria Volátil:**
   - Ejecutar adquisición de memoria RAM mediante `WinPmem` o `LiME` hacia un medio de almacenamiento externo estéril para análisis forense y extracción de posibles claves en memoria.

### Fase B: Erradicación y Análisis de Causa Raíz
1. Identificación y terminación del árbol de procesos maliciosos (`taskkill /F /PID <PID>` o `kill -9`).
2. Identificación del Vector de Entrada inicial (Patient Zero): análisis de correos entrantes, logs de conexiones RDP/VPN y vulnerabilidades perimetrales explotadas.
3. Mapeo de alcance: auditar todos los recursos compartidos en red SMB para constatar si el cifrado alcanzó repositorios centrales.

### Fase C: Recuperación Segura
1. Auditoría exhaustiva de la integridad de los backups inmutables (almacenamiento WORM o copias de seguridad aisladas físicamente / air-gapped).
2. Reinstalación desde imagen limpia del sistema operativo en equipos afectados; nunca intentar reparar un sistema infectado por ransomware sin formateo previo verificado.
3. Restauración de datos y cambio universal de credenciales de usuario y cuentas de servicio del dominio.

## 3. Playbook 3: Respuesta ante Ataques de Phishing y Secuestro de Tokens JWT / MFA (AiTM)

### Contexto y Mecánica del Ataque AiTM (Adversary-in-the-Middle)
Los atacantes despliegan proxies inversos transparentes (como `Evilginx`, `Modlishka`) que interceptan el tráfico entre el usuario y el portal de inicio de sesión legítimo (Microsoft 365, Google Workspace, Okta). Una vez que el usuario introduce su usuario, clave y aprueba el token MFA, el proxy captura la cookie de sesión y el Bearer Token JWT resultante, permitiendo al atacante acceder sin requerir la contraseña ni el dispositivo MFA.

### Protocolo de Respuesta de Emergencia
1. **Revocación Inmediata de Tokens de Sesión (Paso 0):**
   - Ejecutar de inmediato la invalidación de todos los Refresh Tokens emitidos para el usuario en el proveedor de identidad.
   - *Azure AD / Entra ID PowerShell:* `Revoke-AzureADUserAllRefreshToken -ObjectId <User_GUID>` o mediante el botón "Cerrar todas las sesiones" en el centro de administración de Entra.
   - *Google Workspace:* Suspender temporalmente la cuenta o invalidar las credenciales de inicio de sesión OAuth desde la consola de administración.
2. **Restablecimiento Forzado de Contraseña y MFA:**
   - Forzar reseteo de la contraseña del usuario afectado.
   - Re-inscripción obligatoria de los métodos de MFA, revocando números telefónicos o aplicaciones autenticadoras registradas recientemente y promoviendo el uso de llaves de hardware FIDO2 / Passkeys.
3. **Auditoría Forense en el Buzón y Aplicaciones:**
   - Inspeccionar reglas de correo en busca de reenviadores automáticos maliciosos:
     - PowerShell Exchange Online: `Get-InboxRule -Mailbox <User> | Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo }`.
     - Eliminar inmediatamente cualquier regla no autorizada.
   - Inspeccionar permisos y aplicaciones empresariales OAuth concedidas recientemente por el usuario que pudieran mantener acceso a buzones o archivos de OneDrive/SharePoint mediante Microsoft Graph API (`Consent to Application`).
4. **Comunicación Fuera de Banda:**
   - Contactar telefónicamente o en persona al usuario para confirmar el incidente, validar que sus dispositivos personales no estén comprometidos y advertirle sobre tácticas de ingeniería social subsiguientes.

## 4. Estándar de Documentación y Cierre de Incidente en el SOC
Todo incidente debe concluir con la generación de un Informe Formal de Incidente que contenga:
- **Resumen Ejecutivo:** Descripción en lenguaje de negocio sobre el alcance, duración e impacto.
- **Línea Temporal de Eventos (Timeline):** Cronología detallada correlacionando alertas de Wazuh, acciones defensivas tomadas y marcas de tiempo UTC.
- **Inventario de Indicadores de Compromiso (IoCs):** Lista de hashes SHA-256, dominios, IPs y cuentas comprometidas para enriquecer las listas de bloqueo permanentes.
- **Plan de Acción de Mejora Continua:** Tareas asignadas para corregir las brechas de seguridad identificadas con responsables y plazos no negociables.