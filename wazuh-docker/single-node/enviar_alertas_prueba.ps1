# Script para sincronizar reglas/configuracion y generar alertas de prueba en Wazuh Docker
Write-Host "1. Copiando configuracion, reglas y script de inyeccion al contenedor..." -ForegroundColor Cyan
docker cp .\config\wazuh_cluster\wazuh_manager.conf single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf
docker cp .\local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker cp .\inject_test.py single-node-wazuh.manager-1:/tmp/inject_test.py

Write-Host "2. Inicializando archivo de ingesta JSON..." -ForegroundColor Cyan
docker exec single-node-wazuh.manager-1 bash -c "touch /var/ossec/logs/soc_ia_events.json && chmod 666 /var/ossec/logs/soc_ia_events.json"

Write-Host "3. Validando sintaxis de reglas en Wazuh..." -ForegroundColor Cyan
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t

Write-Host "4. Reiniciando Wazuh Manager para aplicar cambios..." -ForegroundColor Cyan
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
Start-Sleep -Seconds 3

Write-Host "5. Ejecutando inyeccion directa en Python dentro del contenedor..." -ForegroundColor Yellow
docker exec single-node-wazuh.manager-1 /var/ossec/framework/python/bin/python3 /tmp/inject_test.py

Write-Host "`nListo! Ya puedes hacer clic en Refresh en el Dashboard (https://localhost)." -ForegroundColor Green
