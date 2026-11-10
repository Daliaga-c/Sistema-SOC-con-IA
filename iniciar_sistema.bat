@echo off
title SOC-IA Platform - Orquestador Global
echo ===================================================================
echo   INICIANDO PLATAFORMA COMPLETA SOC-IA (ENTORNO MULTI-SERVICIO)
echo ===================================================================
echo.

echo [1/3] Iniciando cluster de Wazuh SIEM en segundo plano...
docker-compose -f "wazuh-docker\single-node\docker-compose.yml" up -d
echo [OK] Wazuh SIEM iniciado correctamente.
echo.

echo [2/3] Iniciando los 6 Microservicios con Inteligencia Artificial...
docker-compose -f "soc-ia-microservices\docker-compose.yml" up -d
echo [OK] Microservicios y API Gateway activos en puerto 8000.
echo.

echo [3/3] Iniciando la Consola Web del Analista (React + Vite)...
start "SOC-IA Frontend" /D "soc-ia-microservices\frontend\analyst-console" cmd /k "npm.cmd run dev"

echo.
echo ===================================================================
echo   PLATAFORMA SOC-IA LISTA Y OPERANDO
echo ===================================================================
echo   - Consola Web del Analista (React): http://localhost:5173
echo   - API Gateway y Backend API:        http://localhost:8000
echo   - Wazuh SIEM Dashboard:             https://localhost:443
echo ===================================================================
echo Abriendo consola en tu navegador en 3 segundos...
timeout /t 3 /nobreak >nul
start http://localhost:5173
exit /b 0
