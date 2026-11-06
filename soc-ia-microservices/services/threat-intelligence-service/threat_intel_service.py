from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, Dict

app = FastAPI(title="SOC-IA Threat Intelligence Service", version="1.0.0")

# Cache local en memoria para no saturar APIs externas (T-17)
CACHE: Dict[str, dict] = {
    "185.220.101.5": {
        "ip": "185.220.101.5",
        "country": "Alemania (DE)",
        "city": "Frankfurt",
        "abuse_score": 98,
        "is_tor": True,
        "isp": "Tor Exit Node Network"
    },
    "190.236.14.82": {
        "ip": "190.236.14.82",
        "country": "Perú (PE)",
        "city": "Lima",
        "abuse_score": 5,
        "is_tor": False,
        "isp": "Telefónica del Perú"
    }
}

@app.get("/reputation/{ip}")
async def get_ip_reputation(ip: str):
    if ip in CACHE:
        return CACHE[ip]
    # Fallback genérico para IPs no cacheadas
    return {
        "ip": ip,
        "country": "Desconocido (N/A)",
        "city": "N/A",
        "abuse_score": 15,
        "is_tor": False,
        "isp": "ISP Local / Red Privada"
    }

@app.get("/health")
async def health():
    return {"status": "UP", "service": "threat-intelligence-service"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("threat_intel_service:app", host="0.0.0.0", port=8005, reload=True)
