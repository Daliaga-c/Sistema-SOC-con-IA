import asyncio
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
from typing import Any, Dict, Optional

import geoip2.database
import geoip2.errors
import httpx
from fastapi import FastAPI, HTTPException

app = FastAPI(title="SOC-IA Threat Intelligence Service", version="2.0.0")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
GEOIP2_CITY_DB = Path(
    os.getenv("GEOIP2_CITY_DB", "/data/geoip/GeoLite2-City.mmdb")
)
CACHE_TTL_SECONDS = 3600
MAX_CACHE_ENTRIES = 10000
CACHE: Dict[str, tuple[float, dict]] = {}
CACHE_LOCK = asyncio.Lock()


def _lookup_geoip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Dict[str, Any]:
    if not GEOIP2_CITY_DB.is_file():
        return {"status": "database_not_configured"}

    try:
        with geoip2.database.Reader(str(GEOIP2_CITY_DB)) as reader:
            response = reader.city(str(ip))
    except geoip2.errors.AddressNotFoundError:
        return {"status": "not_found"}

    traits = response.traits
    return {
        "status": "ok",
        "country": response.country.name,
        "country_code": response.country.iso_code,
        "city": response.city.name,
        "latitude": response.location.latitude,
        "longitude": response.location.longitude,
        "isp": None,
        "is_anonymous_proxy": bool(
            getattr(traits, "is_anonymous_proxy", False)
            or getattr(traits, "is_anonymous_vpn", False)
            or getattr(traits, "is_public_proxy", False)
            or getattr(traits, "is_tor_exit_node", False)
        ),
    }


async def _lookup_abuseipdb(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Dict[str, Any]:
    if not ABUSEIPDB_API_KEY:
        return {"status": "not_configured"}

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": str(ip), "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            )
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        status_code = 503 if exc.response.status_code == 429 else 502
        detail = "AbuseIPDB rate limit reached" if status_code == 503 else "AbuseIPDB request failed"
        raise HTTPException(status_code=status_code, detail=detail) from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="AbuseIPDB is unavailable") from exc

    try:
        payload = response.json()
        data = payload["data"]
        score = int(data["abuseConfidenceScore"])
        total_reports = int(data.get("totalReports", 0))
        if not 0 <= score <= 100:
            raise ValueError("abuseConfidenceScore is outside its valid range")
        if total_reports < 0:
            raise ValueError("totalReports cannot be negative")
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(status_code=502, detail="AbuseIPDB returned an invalid response") from exc

    return {
        "status": "ok",
        "abuse_confidence_score": score,
        "total_reports": total_reports,
        "last_reported_at": data.get("lastReportedAt"),
        "country": data.get("countryName"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "is_tor": bool(data.get("isTor", False)),
    }


@app.get("/reputation/{ip}")
async def get_ip_reputation(ip: str):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid IP address") from exc

    normalized_ip = str(address)
    now = asyncio.get_running_loop().time()
    async with CACHE_LOCK:
        cached = CACHE.get(normalized_ip)
        if cached and cached[0] > now:
            return cached[1]
        CACHE.pop(normalized_ip, None)

    result: Dict[str, Any] = {
        "ip": normalized_ip,
        "country": None,
        "country_code": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "abuse_score": None,
        "abuse_confidence_score": None,
        "total_reports": None,
        "last_reported_at": None,
        "is_tor": False,
        "is_tor_or_proxy": False,
        "isp": None,
        "sources": {},
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

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
        "sources": {
            "abuseipdb": "configured" if ABUSEIPDB_API_KEY else "not_configured",
            "geoip2": "configured" if GEOIP2_CITY_DB.is_file() else "not_configured",
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("threat_intel_service:app", host="0.0.0.0", port=8005, reload=True)
