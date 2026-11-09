@echo off
setlocal
title SOC-IA Platform - Orquestador Global
echo ===================================================================
echo   INICIANDO PLATAFORMA COMPLETA SOC-IA (ENTORNO MULTI-SERVICIO)
echo ===================================================================
echo.

REM Verificar si Docker Desktop esta en ejecucion
docker info >nul 2>&1
if errorlevel 1 goto error_docker

echo [1/3] Iniciando cluster de Wazuh SIEM en segundo plano...
docker-compose -f "wazuh-docker\single-node\docker-compose.yml" up -d
echo [OK] Wazuh SIEM procesado.
echo.

echo [2/3] Iniciando los 6 Microservicios con Inteligencia Artificial...
docker-compose -f "soc-ia-microservices\docker-compose.yml" up -d
echo [OK] Microservicios procesados.
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

:error_docker
echo [ERROR CRITICO] Docker Desktop no esta iniciado o no responde.
echo.
echo Por favor sigue estos pasos:
echo  - Abre la aplicacion Docker Desktop en Windows.
echo  - Espera a que el icono inferior este en verde (Engine running).
echo  - Vuelve a ejecutar este archivo iniciar_sistema.bat
echo.
pause
exit /b 1
