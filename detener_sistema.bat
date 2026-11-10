@echo off
title SOC-IA Platform - Detener Servicios
echo ===================================================================
echo   DETENIENDO TODOS LOS SERVICIOS DE SOC-IA Y WAZUH SIEM
echo ===================================================================
echo.

echo [1/2] Deteniendo Microservicios de SOC-IA...
docker-compose -f "soc-ia-microservices\docker-compose.yml" down

echo [2/2] Deteniendo Cluster de Wazuh SIEM...
docker-compose -f "wazuh-docker\single-node\docker-compose.yml" down

echo.
echo [OK] Todos los contenedores han sido apagados y la memoria RAM liberada.
pause
