import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import KpiMetrics from './components/KpiMetrics';
import AlertsTable from './components/AlertsTable';
import CopilotDrawer from './components/CopilotDrawer';
import { getAlerts, mitigateAlert, checkHealth } from './services/api';

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [gatewayOnline, setGatewayOnline] = useState(false);

  const fetchStatusAndAlerts = async () => {
    setIsRefreshing(true);
    try {
      await checkHealth();
      setGatewayOnline(true);
    } catch {
      setGatewayOnline(false);
    }

    try {
      const data = await getAlerts();
      setAlerts(data);
      if (data.length > 0 && !selectedAlert) {
        setSelectedAlert(data[0]);
      }
    } catch (err) {
      console.error('Error cargando alertas:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStatusAndAlerts();
    // Polling reactivo cada 5 segundos para actualizar el estado del SOC en tiempo real
    const interval = setInterval(fetchStatusAndAlerts, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleMitigate = async (alert) => {
    const ip = alert.raw_event?.source_ip;
    const confirmAction = window.confirm(
      `[Human-in-the-Loop]\n¿Confirmas la orden de Active Response para bloquear la IP ${ip} en Wazuh SIEM?`
    );
    if (!confirmAction) return;

    try {
      const result = await mitigateAlert(alert.alert_id, ip);
      alert(`✅ Bloqueo despachado exitosamente:\nComando: ${result.command_dispatched}`);
      fetchStatusAndAlerts();
    } catch (err) {
      alert(`❌ Error al ejecutar mitigación: ${err.message}`);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0a0e17]">
      <Navbar
        onRefresh={fetchStatusAndAlerts}
        isRefreshing={isRefreshing}
        gatewayOnline={gatewayOnline}
      />

      <main className="flex-1 p-6 max-w-[1600px] w-full mx-auto">
        <KpiMetrics alerts={alerts} />

        <div className="flex flex-col lg:flex-row gap-6 items-start">
          <div className="flex-1 w-full">
            <AlertsTable
              alerts={alerts}
              selectedAlert={selectedAlert}
              onSelectAlert={(a) => setSelectedAlert(a)}
              onMitigate={handleMitigate}
            />
          </div>

          {selectedAlert && (
            <CopilotDrawer
              alert={selectedAlert}
              onClose={() => setSelectedAlert(null)}
              onMitigate={handleMitigate}
            />
          )}
        </div>
      </main>
    </div>
  );
}

