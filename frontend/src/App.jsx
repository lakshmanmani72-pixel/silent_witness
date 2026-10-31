import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Topbar from './components/Topbar';

// Pages
import Dashboard from './pages/Dashboard';
import LiveThreats from './pages/LiveThreats';
import Analytics from './pages/Analytics';
import ThreatIntelligence from './pages/ThreatIntelligence';
import BlockedIPs from './pages/BlockedIPs';
import Incidents from './pages/Incidents';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import DetectionExplainer from './pages/DetectionExplainer';

import { endpoints } from './services/api';

function App() {
  const [isConnected, setIsConnected] = useState(true);
  const [monitoringMode, setMonitoringMode] = useState('simulation');
  const [notificationsCount, setNotificationsCount] = useState(0);

  // Periodic health check
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await endpoints.getHealth();
        setIsConnected(true);
        if (res.data.monitoring?.mode) {
          setMonitoringMode(res.data.monitoring.mode);
        }
      } catch (err) {
        setIsConnected(false);
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <Router>
      <div className="flex min-h-screen bg-mist text-ink blueprint-grid">
        {/* Fixed Left Navigation Sidebar */}
        <Sidebar isConnected={isConnected} mode={monitoringMode} />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0">
          <Topbar
            isConnected={isConnected}
            mode={monitoringMode}
            notificationsCount={notificationsCount}
          />

          {/* Backend offline warning banner */}
          {!isConnected && (
            <div className="bg-bad/15 border-b border-bad/40 text-bad-ink px-6 py-2 text-xs font-mono-code flex items-center justify-between shadow-sm">
              <span>
                <strong>ALERT:</strong> Cannot connect to Silent Witness Python backend on http://127.0.0.1:8000. Ensure Uvicorn is running.
              </span>
              <span className="animate-pulse font-bold">RETRYING LINK...</span>
            </div>
          )}

          {/* Page Routing */}
          <main className="flex-1 overflow-y-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/explainer" element={<DetectionExplainer />} />
              <Route path="/threats" element={<LiveThreats />} />
              <Route path="/analytics" element={<Analytics />} />
              <Route path="/intelligence" element={<ThreatIntelligence />} />
              <Route path="/blocked" element={<BlockedIPs />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
