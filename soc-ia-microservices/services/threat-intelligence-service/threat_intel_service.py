import ipaddress
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

try:
    import geoip2.database
except Exception:
    geoip2 = None

app = FastAPI(title="SOC-IA Threat Intelligence Service (Real-Time)", version="2.0.0")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
GEOLITE2_DB_PATH = os.getenv("GEOLITE2_DB_PATH", "/app/GeoLite2-City.mmdb")
CACHE_TTL_SECONDS = int(os.getenv("THREAT_INTEL_CACHE_TTL", "3600"))

# Cache en memoria con indicadores enriquecidos conocidos + TTL dinámico
CACHE: Dict[str, Dict[str, Any]] = {
    "185.220.101.5": {
        "ip": "185.220.101.5",
        "country": "Alemania (DE)",
        "country_code": "DE",
        "city": "Frankfurt am Main",
        "abuse_score": 98,
        "is_tor": True,
        "is_vpn_or_proxy": True,
        "isp": "Tor Exit Node Network (Zwiebelfreunde e.V.)",
        "asn": "AS205100",
        "source": "ThreatFeed + TorProject",
        "cached_at": time.time(),
    },
    "190.236.14.82": {
        "ip": "190.236.14.82",
        "country": "Perú (PE)",
        "country_code": "PE",
        "city": "Lima",
        "abuse_score": 5,
        "is_tor": False,
        "is_vpn_or_proxy": False,
        "isp": "Telefónica del Perú S.A.A.",
        "asn": "AS6147",
        "source": "ISP Baseline",
        "cached_at": time.time(),
    },
    "45.142.122.9": {
        "ip": "45.142.122.9",
        "country": "Países Bajos (NL)",
        "country_code": "NL",
        "city": "Ámsterdam",
        "abuse_score": 91,
        "is_tor": False,
        "is_vpn_or_proxy": True,
        "isp": "Bulletproof Hosting / Scanner Network",
        "asn": "AS209605",
        "source": "ThreatFeed",
        "cached_at": time.time(),
    },
    "194.26.29.112": {
        "ip": "194.26.29.112",
        "country": "Rusia (RU)",
        "country_code": "RU",
        "city": "San Petersburgo",
        "abuse_score": 94,
        "is_tor": False,
        "is_vpn_or_proxy": True,
        "isp": "Chang Way Technologies Co. Limited",
        "asn": "AS57523",
        "source": "ThreatFeed",
        "cached_at": time.time(),
    },
}


class BatchIPRequest(BaseModel):
    ips: List[str]


def _is_private_or_loopback(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        return ip_str.startswith(("10.", "192.168.", "172.16.", "127."))


def _lookup_geolite2_local(ip_str: str) -> Optional[Dict[str, Any]]:
    """Consulta local ultra-rápida si el archivo GeoLite2-City.mmdb está montado."""
    if not geoip2 or not Path(GEOLITE2_DB_PATH).is_file():
        return None
    try:
        with geoip2.database.Reader(GEOLITE2_DB_PATH) as reader:
            resp = reader.city(ip_str)
            country_name = resp.country.names.get("es") or resp.country.name or "Desconocido"
            iso = resp.country.iso_code or "N/A"
            city_name = resp.city.name or "N/A"
            return {
                "country": f"{country_name} ({iso})",
                "country_code": iso,
                "city": city_name,
            }
    except Exception:
        return None


async def _query_abuseipdb(ip_str: str) -> Optional[Dict[str, Any]]:
    """Consulta en vivo a la API oficial de AbuseIPDB v2 cuando ABUSEIPDB_API_KEY está configurada."""
    if not ABUSEIPDB_API_KEY or ABUSEIPDB_API_KEY in ("tu_api_key_aqui", "None"):
        return None
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip_str, "maxAgeInDays": "90"},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
            if r.status_code == 200:
                data = r.json().get("data", {})
                cc = data.get("countryCode") or "N/A"
                return {
                    "ip": ip_str,
                    "country": f"{data.get('countryName', cc)} ({cc})",
                    "country_code": cc,
                    "city": "Verificado por AbuseIPDB",
                    "abuse_score": int(data.get("abuseConfidenceScore", 0)),
                    "total_reports": int(data.get("totalReports", 0)),
                    "is_tor": bool(data.get("isTor", False)),
                    "is_vpn_or_proxy": bool(data.get("isTor", False) or data.get("usageType") == "Data Center/Web Hosting/Transit"),
                    "isp": data.get("isp") or "Desconocido",
                    "domain": data.get("domain") or "",
                    "source": "AbuseIPDB Live API v2",
                }
    except Exception:
        pass
    return None


async def _query_live_geoip_and_reputation(ip_str: str) -> Optional[Dict[str, Any]]:
    """Consulta geolocalización, ASN y banderas de Proxy/Hosting en tiempo real sin requerir API Key."""
    try:
        async with httpx.AsyncClient(timeout=3.5) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip_str}",
                params={"fields": "status,country,countryCode,city,isp,org,as,proxy,hosting"},
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    cc = data.get("countryCode", "N/A")
                    is_proxy = bool(data.get("proxy", False))
                    is_hosting = bool(data.get("hosting", False))
                    isp_name = data.get("isp") or data.get("org") or "Proveedor Público"
                    is_tor = "tor" in isp_name.lower()

                    # Cálculo dinámico de score de riesgo basado en telemetría de red real
                    calculated_score = 15
                    if is_tor:
                        calculated_score = 95
                    elif is_proxy and is_hosting:
                        calculated_score = 80
                    elif is_proxy:
                        calculated_score = 72
                    elif is_hosting:
                        calculated_score = 55

                    return {
                        "ip": ip_str,
                        "country": f"{data.get('country', 'Desconocido')} ({cc})",
                        "country_code": cc,
                        "city": data.get("city") or "N/A",
                        "abuse_score": calculated_score,
                        "is_tor": is_tor,
                        "is_vpn_or_proxy": is_proxy or is_hosting,
                        "isp": isp_name,
                        "asn": data.get("as", ""),
                        "source": "Live GeoIP & ASN Network Intelligence",
                    }
    except Exception:
        pass
    return None


@app.get("/reputation/{ip}")
async def get_ip_reputation(ip: str):
    clean_ip = ip.strip()

    # 1. Verificar IPs de red privada / corporativa (RFC 1918)
    if _is_private_or_loopback(clean_ip):
        return {
            "ip": clean_ip,
            "country": "Red Corporativa Interna (LAN)",
            "country_code": "LAN",
            "city": "Segmento Local",
            "abuse_score": 0,
            "is_tor": False,
            "is_vpn_or_proxy": False,
            "isp": "Red Privada RFC1918",
            "asn": "INTERNAL",
            "source": "RFC1918 Classifier",
        }

    # 2. Verificar Cache con TTL
    cached = CACHE.get(clean_ip)
    if cached and (time.time() - cached.get("cached_at", 0) < CACHE_TTL_SECONDS):
        return cached

    # 3. Intentar AbuseIPDB oficial si hay API Key
    abuse_res = await _query_abuseipdb(clean_ip)
    local_geo = _lookup_geolite2_local(clean_ip)

    if abuse_res:
        if local_geo:
            abuse_res["city"] = local_geo["city"]
            abuse_res["country"] = local_geo["country"]
        abuse_res["cached_at"] = time.time()
        CACHE[clean_ip] = abuse_res
        return abuse_res

    # 4. Consultar Inteligencia de Red y GeoIP en Vivo (ip-api + MaxMind local)
    live_res = await _query_live_geoip_and_reputation(clean_ip)
    if live_res:
        if local_geo:
            live_res["city"] = local_geo["city"]
            live_res["country"] = local_geo["country"]
        live_res["cached_at"] = time.time()
        CACHE[clean_ip] = live_res
        return live_res

    # 5. Fallback con GeoLite2 local o heurística determinista
    fallback = {
        "ip": clean_ip,
        "country": local_geo["country"] if local_geo else "Externo / No Catalogado",
        "country_code": local_geo["country_code"] if local_geo else "EXT",
        "city": local_geo["city"] if local_geo else "N/A",
        "abuse_score": 45,
        "is_tor": False,
        "is_vpn_or_proxy": False,
        "isp": "ISP Externo",
        "asn": "N/A",
        "source": "GeoLite2 / Fallback Heurístico",
        "cached_at": time.time(),
    }
    CACHE[clean_ip] = fallback
    return fallback


@app.post("/reputation/batch")
async def get_batch_reputation(req: BatchIPRequest):
    results = {}
    for ip in req.ips[:25]:
        results[ip] = await get_ip_reputation(ip)
    return {"total": len(results), "results": results}


    if not address.is_global:
        result["sources"] = {"abuseipdb": "not_public", "geoip2": "not_public"}
        return result

    geoip = await asyncio.to_thread(_lookup_geoip, address)
    abuse = await _lookup_abuseipdb(address)
    result["sources"] = {"abuseipdb": abuse["status"], "geoip2": geoip["status"]}

    for field in ("country", "country_code", "isp"):
        result[field] = abuse.get(field) or geoip.get(field)
    result["city"] = geoip.get("city")
    result["latitude"] = geoip.get("latitude")
    result["longitude"] = geoip.get("longitude")
    result["abuse_score"] = abuse.get("abuse_confidence_score")
    result["abuse_confidence_score"] = abuse.get("abuse_confidence_score")
    result["total_reports"] = abuse.get("total_reports")
    result["last_reported_at"] = abuse.get("last_reported_at")
    result["is_tor"] = abuse.get("is_tor", False)
    result["is_tor_or_proxy"] = result["is_tor"] or geoip.get("is_anonymous_proxy", False)

    async with CACHE_LOCK:
        cache_time = asyncio.get_running_loop().time()
        expired_keys = [key for key, (expires_at, _) in CACHE.items() if expires_at <= cache_time]
        for key in expired_keys:
            CACHE.pop(key, None)
        if len(CACHE) >= MAX_CACHE_ENTRIES:
            oldest_key = min(CACHE, key=lambda key: CACHE[key][0])
            CACHE.pop(oldest_key)
        CACHE[normalized_ip] = (cache_time + CACHE_TTL_SECONDS, result)
    return result


@app.get("/health")
async def health():
    return {
        "status": "UP",
        "service": "threat-intelligence-service",
        "version": "2.0.0",
        "abuseipdb_configured": bool(ABUSEIPDB_API_KEY),
        "geolite2_local_ready": bool(geoip2 and Path(GEOLITE2_DB_PATH).is_file()),
        "cached_iocs": len(CACHE),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("threat_intel_service:app", host="0.0.0.0", port=8005, reload=True)
