@echo off
echo ===================================================================
echo   SIMULACION DE FUERZA BRUTA EN WAZUH SIEM (SIN REINICIOS)
echo ===================================================================
echo.

echo [1/2] Sincronizando script de prueba en caliente al contenedor...
docker cp .\inject_test.py single-node-wazuh.manager-1:/tmp/inject_test.py

echo [2/2] Inyectando rafaga de fuerza bruta contra usuario 'carlos'...
docker exec single-node-wazuh.manager-1 /var/ossec/framework/python/bin/python3 /tmp/inject_test.py

echo.
echo [OK] Prueba completada en caliente sin interrumpir el SIEM.
