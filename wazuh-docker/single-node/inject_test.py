#!/usr/bin/env python3
import json
import socket
import subprocess
import time
import os

event = {
    "status": "FAILURE",
    "user": "carlos",
    "srcip": "192.168.1.50",
    "source_system": "Portal Web Dummy"
}
json_line = json.dumps(event)

print("=== 1. Probando evento en wazuh-logtest ===")
proc = subprocess.run(
    ["/var/ossec/bin/wazuh-logtest"],
    input=(json_line + "\n").encode("utf-8"),
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)
output = (proc.stdout + proc.stderr).decode("utf-8", errors="replace")
for line in output.splitlines():
    if any(k in line for k in ["Phase", "Rule", "id:", "level:", "description:", "decoded_as", "source_system"]):
        print("  ", line)

print("\n=== 2. Inyectando 8 eventos reales al motor de Wazuh ===")
queue_socket = "/var/ossec/queue/sockets/queue"
log_file = "/var/ossec/logs/soc_ia_events.json"

for i in range(8):
    # Via 1: Socket interno directo de Wazuh analysisd
    if os.path.exists(queue_socket):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            msg = f"1:soc-ia-portal:{json_line}"
            s.sendto(msg.encode("utf-8"), queue_socket)
            s.close()
        except Exception as e:
            print(f"  [Aviso socket]: {e}")

    # Via 2: Archivo JSON monitoreado
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json_line + "\n")

    time.sleep(0.2)

time.sleep(2)

print("\n=== 3. Verificando alertas generadas en /var/ossec/logs/alerts/alerts.json ===")
alerts_file = "/var/ossec/logs/alerts/alerts.json"
found = 0
if os.path.exists(alerts_file):
    with open(alerts_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    for line in lines[-30:]:
        if "100002" in line or "100003" in line:
            found += 1
            try:
                data = json.loads(line)
                rule = data.get("rule", {})
                print(f"  [ALERTA GENERADA] ID: {rule.get('id')} | Nivel: {rule.get('level')} | Desc: {rule.get('description')}")
            except Exception:
                print("  ", line[:120])

if found == 0:
    print("  [!] No se encontraron alertas 100002/100003 aun en alerts.json.")
else:
    print(f"  [OK] Se encontraron {found} alertas recientes en alerts.json.")

print("\n=== 4. Reenviando alerta en vivo a la App Web SOC-IA ===")
import urllib.request

target_hosts = [
    "http://host.docker.internal:8000/api/ingest",
    "http://172.17.0.1:8000/api/ingest",
    "http://soc-ia-api-gateway:8000/api/ingest",
    "http://localhost:8000/api/ingest"
]

canonical_payload = json.dumps({
    "user": "carlos",
    "ip_origen": "192.168.1.50",
    "resultado": "FAILURE",
    "origen": "Wazuh SIEM",
    "dispositivo": "Portal Web Dummy (Wazuh Agent)",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
}).encode("utf-8")

sent = False
last_err = None
for url in target_hosts:
    try:
        req = urllib.request.Request(
            url,
            data=canonical_payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            print(f"  [✓ CONECTOR SOC-IA] Alerta de 'carlos' enviada con exito a {url} -> HTTP {resp.status}")
            sent = True
            break
    except Exception as e:
        last_err = e

if not sent:
    print(f"  [!] Aviso: No se pudo contactar el puerto 8000 del backend ({last_err}).")
    print("      -> Verifica que los microservicios esten activos con: docker-compose up -d")

