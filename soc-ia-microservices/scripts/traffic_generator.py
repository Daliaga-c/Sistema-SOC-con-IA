#!/usr/bin/env python3
"""
Simulador de Tráfico y Ataques de Autenticación para SOC-IA.
Permite inyectar ataques de Fuerza Bruta (T1110) y Accesos Nocturnos Anómalos (T1078)
directamente hacia la API de Ingesta (http://localhost:8000/api/ingest o http://localhost:8001/ingest).
"""

import time
import requests
import sys

API_URL = "http://localhost:8000/api/ingest"

def print_banner():
    print("""
=============================================================
  🚨 SOC-IA: GENERADOR INTERACTIVO DE TRÁFICO Y ATAQUES 🚨
=============================================================
1. Simular Ataque de Fuerza Bruta (MITRE T1110)
   -> Ráfaga de 12 intentos fallidos rápidos contra 'admin'
2. Simular Acceso Nocturno Sospechoso (MITRE T1078)
   -> 1 inicio de sesión exitoso fuera de horario desde IP foránea
3. Simular Tráfico Normal Benigno
   -> Inicios de sesión exitosos en horario corporativo
4. Batería Completa Automatizada
5. Salir
=============================================================
""")

def send_event(user, ip, status, origin="Portal Web Dummy", device="Desktop Chrome"):
    payload = {
        "user": user,
        "ip_origen": ip,
        "resultado": status,
        "origen": origin,
        "dispositivo": device
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=3)
        if r.status_code in [200, 201]:
            print(f"  [✓] Enviado: {user:12} | IP: {ip:15} | Estado: {status:7} | HTTP {r.status_code}")
        else:
            print(f"  [!] Error de API ({r.status_code}): {r.text}")
    except Exception as e:
        print(f"  [✗] No se pudo contactar al API Gateway ({API_URL}): {e}")
        print("      -> Asegúrate de que 'docker-compose up -d' o el gateway estén activos.")

def simulate_brute_force():
    print("\n[!] Lanzando Ataque de Fuerza Bruta (T1110)...")
    attacker_ip = "185.220.101.5"
    passwords = ["123456", "admin", "password", "root", "toor", "12345678", "qwerty", "master", "login", "secret", "pass123", "admin2026"]
    
    for i, _ in enumerate(passwords, start=1):
        print(f" Intento {i:02d}/12 probando credencial (redactada)...")
        send_event(user="admin", ip=attacker_ip, status="FAILURE", origin="Portal Web Dummy", device="Hydra/9.2 BruteForcer")
        time.sleep(0.3)  # Ráfaga rápida

    print("✅ Ataque completado. Revisa tu consola web en http://localhost:5173 o http://localhost:8000\n")

def simulate_night_access():
    print("\n[!] Lanzando Acceso Nocturno Sospechoso (T1078)...")
    print(" Simulando login exitoso a las 03:42 AM desde IP desconocida...")
    send_event(user="daliaga", ip="190.236.14.82", status="SUCCESS", origin="SSH", device="OpenSSH 8.9p1")
    print("✅ Evento enviado. Debería evaluarse por horario inusual.\n")

def simulate_normal_traffic():
    print("\n[i] Enviando eventos normales benignos...")
    users = [("ana.garcia", "192.168.1.10"), ("juan.perez", "192.168.1.15"), ("soporte_ti", "192.168.1.20")]
    for u, ip in users:
        send_event(user=u, ip=ip, status="SUCCESS", origin="Portal Web Dummy", device="Desktop Chrome Windows")
        time.sleep(0.5)
    print("✅ Tráfico normal enviado.\n")

def run_suite():
    print("\n[+] Ejecutando Batería Completa de Pruebas...")
    simulate_normal_traffic()
    time.sleep(1)
    simulate_brute_force()
    time.sleep(1)
    simulate_night_access()
    print("🎉 Batería finalizada exitosamente.\n")

def main():
    while True:
        print_banner()
        choice = input("Selecciona una opción [1-5]: ").strip()
        if choice == "1":
            simulate_brute_force()
        elif choice == "2":
            simulate_night_access()
        elif choice == "3":
            simulate_normal_traffic()
        elif choice == "4":
            run_suite()
        elif choice == "5":
            print("Saliendo...")
            sys.exit(0)
        else:
            print("Opción inválida. Intenta nuevamente.")

if __name__ == "__main__":
    main()
