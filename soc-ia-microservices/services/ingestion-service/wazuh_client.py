import os
import time
import httpx
from typing import Optional, Dict, Any, List

class WazuhAPIClient:
    """
    Cliente para la API REST de Wazuh Manager (puerto 55000).
    Maneja autenticación JWT, renovación de token, consultas y despacho de Active Response.
    """
    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = False
    ):
        self.host = host or os.getenv("WAZUH_API_HOST", "localhost")
        self.port = int(port or os.getenv("WAZUH_API_PORT", 55000))
        self.username = username or os.getenv("WAZUH_API_USER", "wazuh-wui")
        self.password = password or os.getenv("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")
        self.base_url = f"https://{self.host}:{self.port}"
        self.verify_ssl = verify_ssl
        self.token: Optional[str] = None
        self.token_expiry: float = 0.0

    async def get_token(self, force_refresh: bool = False) -> str:
        """
        Obtiene un token JWT de la API de Wazuh con caché y renovación automática.
        El token dura típicamente 900 segundos (15 minutos).
        """
        now = time.time()
        if self.token and (self.token_expiry - now > 60) and not force_refresh:
            return self.token

        url = f"{self.base_url}/security/user/authenticate"
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10.0) as client:
            try:
                response = await client.post(
                    url,
                    auth=(self.username, self.password),
                    headers={"Content-Type": "application/json"}
                )
                if response.status_code == 200:
                    data = response.json()
                    self.token = data.get("data", {}).get("token")
                    self.token_expiry = now + 840  # Refrescar a los 14 minutos
                    return self.token
                else:
                    raise RuntimeError(f"Error de autenticación Wazuh: HTTP {response.status_code} - {response.text}")
            except httpx.ConnectError as e:
                raise ConnectionError(f"No se pudo conectar a Wazuh API en {self.base_url}: {e}")

    async def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        token = await self.get_token()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        url = f"{self.base_url}{path}"

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15.0) as client:
            response = await client.request(method, url, headers=headers, **kwargs)
            if response.status_code == 401:
                # Token expirado, reintentar una vez
                token = await self.get_token(force_refresh=True)
                headers["Authorization"] = f"Bearer {token}"
                response = await client.request(method, url, headers=headers, **kwargs)

            if response.is_success:
                return response.json()
            else:
                raise RuntimeError(f"Wazuh API Error [{response.status_code}]: {response.text}")

    async def test_connection(self) -> Dict[str, Any]:
        """Verifica conectividad y credenciales con el endpoint /manager/info"""
        return await self._request("GET", "/manager/info")

    async def get_agents(self, limit: int = 10) -> Dict[str, Any]:
        """Lista los agentes conectados a Wazuh"""
        return await self._request("GET", f"/agents?limit={limit}")

    async def dispatch_active_response(
        self,
        command: str = "firewall-drop0",
        target_ip: str = "",
        agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Ejecuta Active Response en Wazuh para mitigar una amenaza (ej. bloquear IP en firewall).
        Requiere aprobación previa de analista (Human-in-the-loop).
        """
        payload = {
            "command": command,
            "custom": False,
            "arguments": ["-", target_ip]
        }
        query_param = f"?agents_list={agent_id}" if agent_id else ""
        return await self._request("PUT", f"/active-response{query_param}", json=payload)
