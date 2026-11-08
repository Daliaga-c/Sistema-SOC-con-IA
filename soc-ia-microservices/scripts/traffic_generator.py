#!/usr/bin/env python3
"""Generador de tráfico simulado para SOC-IA.

Este script envía eventos de autenticación al endpoint /api/ingest del gateway
para probar la detección de anomalías, el scoring de riesgo y la generación de
alertas sin depender de Wazuh o tráfico real.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover - fallback for minimal environments
    httpx = None

DEFAULT_BASE_URL = os.getenv("SOC_IA_API_URL", "http://localhost:8000")
DEFAULT_TIMEOUT = 5.0
PUBLIC_IPS = ["185.220.101.5", "198.51.100.27", "203.0.113.8", "8.8.8.8", "45.142.220.10"]
PRIVATE_IPS = ["192.168.1.10", "192.168.1.25", "192.168.1.42", "192.168.1.77", "10.0.0.12"]
COMMON_USERS = ["admin", "root", "support", "analyst", "ops"]


def build_event(
    user: str,
    ip_origen: str,
    resultado: str,
    origen: str = "Portal Web Dummy",
    dispositivo: str = "Desktop Chrome",
    timestamp: Optional[datetime] = None,
) -> dict:
    return {
        "user": user,
        "ip_origen": ip_origen,
        "resultado": resultado.upper(),
        "origen": origen,
        "dispositivo": dispositivo,
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
    }


def send_event(event: dict, base_url: str) -> bool:
    url = f"{base_url.rstrip('/')}/api/ingest"
    try:
        if httpx is not None:
            response = httpx.post(url, json=event, timeout=DEFAULT_TIMEOUT)
            if response.status_code in (200, 201):
                payload = response.json()
                print(f"[OK] {event['user']} | {event['ip_origen']} | {event['resultado']} -> {payload}")
                return True
            print(f"[WARN] {event['user']} | {event['ip_origen']} | {event['resultado']} -> HTTP {response.status_code}: {response.text}")
            return False

        payload = json.dumps(event).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=DEFAULT_TIMEOUT) as response:
            response_body = response.read().decode("utf-8")
            parsed = json.loads(response_body) if response_body else {}
            print(f"[OK] {event['user']} | {event['ip_origen']} | {event['resultado']} -> {parsed}")
            return True
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = body
        print(f"[WARN] {event['user']} | {event['ip_origen']} | {event['resultado']} -> HTTP {exc.code}: {parsed}")
        return False
    except (urllib.error.URLError, OSError) as exc:
        print(f"[ERROR] No se pudo enviar evento hacia {url}: {exc}")
        return False


def send_events(events: Iterable[dict], base_url: str, delay_seconds: float = 0.0) -> int:
    sent = 0
    for event in events:
        if send_event(event, base_url):
            sent += 1
        if delay_seconds > 0:
            time.sleep(delay_seconds)
    return sent


def run_bruteforce(base_url: str, count: int = 15, delay_seconds: float = 0.25) -> int:
    print(f"\n=== 1) Ataque de Fuerza Bruta (T1110) ===")
    print(f"Enviando {count} intentos fallidos desde IP pública en menos de 10 segundos...\n")
    events = []
    for index in range(count):
        user = COMMON_USERS[index % len(COMMON_USERS)]
        timestamp = datetime.now(timezone.utc) - timedelta(seconds=(count - index) * 2)
        events.append(
            build_event(
                user=user,
                ip_origen=PUBLIC_IPS[index % len(PUBLIC_IPS)],
                resultado="FAILURE",
                origen="SSH",
                dispositivo="VPN Gateway",
                timestamp=timestamp,
            )
        )
    return send_events(events, base_url, delay_seconds=delay_seconds)


def run_night_login(base_url: str, user: str = "admin") -> int:
    print(f"\n=== 2) Acceso Nocturno Privilegiado (T1078) ===")
    print("Generando login exitoso a las 03:30 AM desde IP poco usual...\n")
    event = build_event(
        user=user,
        ip_origen="149.56.21.219",
        resultado="SUCCESS",
        origen="Portal Web Dummy",
        dispositivo="Remote Laptop",
        timestamp=datetime.now().replace(hour=3, minute=30, second=0, microsecond=0),
    )
    return 1 if send_event(event, base_url) else 0


def run_benign(base_url: str, count: int = 5) -> int:
    print(f"\n=== 3) Tráfico Normal Benigno ===")
    print(f"Generando {count} eventos de login exitoso en horario de oficina desde IPs privadas...\n")
    events = []
    now = datetime.now(timezone.utc)
    for index in range(count):
        minute_offset = index * 7
        ts = now.replace(hour=9, minute=30 + minute_offset, second=0, microsecond=0)
        if ts.hour >= 18:
            ts = ts.replace(hour=8, minute=15 + minute_offset)
        events.append(
            build_event(
                user="analyst",
                ip_origen=PRIVATE_IPS[index % len(PRIVATE_IPS)],
                resultado="SUCCESS",
                origen="Portal Web Dummy",
                dispositivo="Office Desktop",
                timestamp=ts,
            )
        )
    return send_events(events, base_url)


def run_full_suite(base_url: str, count: int = 15) -> dict:
    print("\n=== 4) Lote de Pruebas Automatizadas ===")
    print(f"Base URL objetivo: {base_url}\n")
    summary = {
        "bruteforce": run_bruteforce(base_url, count=count, delay_seconds=0.25),
        "night_login": run_night_login(base_url),
        "benign": run_benign(base_url, count=5),
    }
    print("\n==== Resumen Final ====")
    for key, value in summary.items():
        print(f"- {key}: {value} eventos enviados")
    return summary


def print_menu() -> None:
    print("\n=== Generador de Tráfico SOC-IA ===")
    print("1. Ataque por Fuerza Bruta (T1110)")
    print("2. Acceso Nocturno Privilegiado (T1078)")
    print("3. Tráfico Normal Benigno")
    print("4. Lote de Pruebas Automatizadas")
    print("5. Salir")


def handle_choice(choice: str, base_url: str) -> bool:
    if choice in {"5", "q", "quit", "exit"}:
        print("Cerrando generador de tráfico...")
        return False

    if choice == "1":
        run_bruteforce(base_url)
    elif choice == "2":
        run_night_login(base_url)
    elif choice == "3":
        run_benign(base_url)
    elif choice == "4":
        run_full_suite(base_url)
    else:
        print("Opción no reconocida. Selecciona una opción válida.")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generador de tráfico simulado para probar SOC-IA.")
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="URL del gateway, por ejemplo http://localhost:8000",
    )
    parser.add_argument(
        "--scenario",
        choices=["bruteforce", "night", "benign", "full"],
        default=None,
        help="Ejecuta un escenario sin mostrar el menú interactivo.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=15,
        help="Cantidad de eventos para la ráfaga de fuerza bruta.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_url = args.base_url
    if args.scenario == "bruteforce":
        run_bruteforce(base_url, count=args.count)
        return 0
    if args.scenario == "night":
        run_night_login(base_url)
        return 0
    if args.scenario == "benign":
        run_benign(base_url, count=max(1, min(10, args.count)))
        return 0
    if args.scenario == "full":
        run_full_suite(base_url, count=args.count)
        return 0

    print(f"Objetivo del gateway: {base_url}")
    while True:
        print_menu()
        try:
            choice = input("Selecciona una opción [1-5]: ").strip().lower()
        except KeyboardInterrupt:
            print("\nInterrupción del usuario. Cerrando...")
            return 0

        if not handle_choice(choice, base_url):
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
