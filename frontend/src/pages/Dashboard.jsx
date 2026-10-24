import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  AlertOctagon,
  Flame,
  Ban,
  Activity,
  Clock,
  Play,
  Square,
  Pause,
  RotateCcw,
  Sparkles,
  Wifi,
  Radio,
  ExternalLink,
} from 'lucide-react';
import StatCard from '../components/StatCard';
import TrafficChart from '../components/TrafficChart';
import { ThreatDonutChart, SeverityBarChart } from '../components/ThreatChart';
import ThreatTable from '../components/ThreatTable';
import ConfirmationModal from '../components/ConfirmationModal';
import { endpoints } from '../services/api';

const Dashboard = () => {
  const navigate = useNavigate();

  // State
  const [summary, setSummary] = useState({
    total_threats: 0,
    critical_threats: 0,
    high_threats: 0,
    active_blocked_ips: 0,
    packets_analyzed: 0,
    uptime_seconds: 0,
    monitoring_mode: 'simulation',
    monitoring_active: true,
    last_detection: null,
  });

  const [trafficData, setTrafficData] = useState([]);
  const [trafficRange, setTrafficRange] = useState('5m');
  const [threatTypes, setThreatTypes] = useState([]);
  const [severityDist, setSeverityDist] = useState([]);
  const [recentEvents, setRecentEvents] = useState([]);
  const [networkActivity, setNetworkActivity] = useState(null);
  const [simStatus, setSimStatus] = useState(null);

  // Selected threat for inspection modal
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);

  // Fetch all dashboard data
  const loadDashboardData = async () => {
    try {
      const [sumRes, trafRes, typesRes, sevRes, eventsRes, netRes, simRes] = await Promise.all([
        endpoints.getDashboardSummary(),
        endpoints.getTrafficStats(trafficRange),
        endpoints.getThreatTypes(),
        endpoints.getSeverityDistribution(),
        endpoints.getRecentEvents(8),
        endpoints.getNetworkActivity(),
        endpoints.getSimulationStatus(),
      ]);

      setSummary(sumRes.data);
      setTrafficData(trafRes.data || []);
      setThreatTypes(typesRes.data || []);
      setSeverityDist(sevRes.data || []);
      setRecentEvents(eventsRes.data || []);
      setNetworkActivity(netRes.data || {});
      setSimStatus(simRes.data || {});
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 3000); // Polling every 3s
    return () => clearInterval(interval);
  }, [trafficRange]);

  // Format uptime
  const formatUptime = (seconds) => {
    if (!seconds) return '0s';
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    if (hrs > 0) return `${hrs}h ${mins}m`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
  };

  // Toggle monitoring start/stop
  const handleToggleMonitoring = async () => {
    try {
      if (summary.monitoring_active) {
        await endpoints.stopMonitoring();
      } else {
        await endpoints.startSimulation(1.0);
      }
      await loadDashboardData();
    } catch (err) {
      console.error('Failed to toggle monitoring:', err);
    }
  };

  // Simulation controls
  const handleSimPause = async () => {
    try {
      if (simStatus?.paused) {
        await endpoints.resumeSimulation();
      } else {
        await endpoints.pauseSimulation();
      }
      await loadDashboardData();
    } catch (err) {
      console.error('Sim pause toggle failed:', err);
    }
  };

  const handleSwitchToLive = async () => {
    try {
      await endpoints.startMonitoring();
      await loadDashboardData();
    } catch (err) {
      console.error('Failed to switch to live monitoring:', err);
    }
  };

  const handleSwitchToSimulation = async () => {
    try {
      await endpoints.startSimulation(1.0);
      await loadDashboardData();
    } catch (err) {
      console.error('Failed to switch to simulation:', err);
    }
  };

  const handleSimSpeed = async (speed) => {
    try {
      await endpoints.startSimulation(speed);
      await loadDashboardData();
    } catch (err) {
      console.error('Speed change failed:', err);
    }
  };

  const handleConfirmReset = async () => {
    try {
      await endpoints.resetSimulation();
      await endpoints.startSimulation(1.0);
      await loadDashboardData();
    } catch (err) {
      console.error('Reset simulation failed:', err);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* ── A. Welcome & Control Section ───────────────────────────────────── */}
      <div className="relative bg-cyber-card border border-cyber-border rounded-xl p-6 shadow-xl overflow-hidden flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        {/* Glow corner accent */}
        <div className="absolute top-0 right-0 w-64 h-64 bg-cyber-cyan/5 rounded-full blur-3xl pointer-events-none" />

        <div className="space-y-1 z-10">
          <div className="flex items-center gap-2">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-mono-code">
              Security Operations Center
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono-code font-bold bg-cyber-panel border border-cyber-border/60 text-cyber-cyan">
              SOC TIER-1
            </span>
          </div>
          <p className="text-xs sm:text-sm text-cyber-muted italic font-sans">
            "Monitor. Detect. Respond. Protect."
          </p>
        </div>

        {/* Master Control Buttons */}
        <div className="flex flex-wrap items-center gap-3 z-10">
          {/* Real-Time Live Wi-Fi vs. Demo Simulation Switcher */}
          <div className="flex items-center gap-1 bg-cyber-panel border border-cyber-border/40 p-1 rounded-lg text-xs font-mono-code">
            <button
              onClick={handleSwitchToLive}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition-all font-bold ${
                summary.monitoring_mode === 'live'
                  ? 'bg-cyber-green text-black shadow-green-glow'
                  : 'text-cyber-muted hover:text-white'
              }`}
              title="Capture and analyze real network packets from your active Wi-Fi interface"
            >
              <Wifi className="w-3.5 h-3.5" />
              <span>Real-Time Live (Wi-Fi)</span>
            </button>
            <button
              onClick={handleSwitchToSimulation}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition-all font-bold ${
                summary.monitoring_mode === 'simulation'
                  ? 'bg-cyber-cyan text-black shadow-cyan-glow'
                  : 'text-cyber-muted hover:text-white'
              }`}
              title="Run synthetic attack demonstration scenarios"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Demo Mode</span>
            </button>
          </div>

          <button
            onClick={handleToggleMonitoring}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono-code font-bold transition-all shadow-md ${
              summary.monitoring_active
                ? 'bg-cyber-red/10 border border-cyber-red/50 text-cyber-red hover:bg-cyber-red hover:text-white shadow-red-glow'
                : 'bg-cyber-green/10 border border-cyber-green/50 text-cyber-green hover:bg-cyber-green hover:text-black shadow-green-glow'
            }`}
          >
            {summary.monitoring_active ? (
              <>
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>Stop Engine</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Start Engine</span>
              </>
            )}
          </button>

          {/* Simulation fast control pills */}
          <div className="flex items-center gap-1 bg-cyber-panel border border-cyber-border/40 p-1 rounded-lg text-xs font-mono-code">
            <button
              onClick={handleSimPause}
              className={`p-1.5 rounded hover:bg-cyber-card transition-colors ${
                simStatus?.paused ? 'text-cyber-amber font-bold' : 'text-cyber-muted'
              }`}
              title={simStatus?.paused ? 'Resume Simulation' : 'Pause Simulation'}
            >
              {simStatus?.paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            </button>
            <div className="h-4 w-px bg-cyber-border/40 mx-0.5" />
            <button
              onClick={() => handleSimSpeed(1.0)}
              className={`px-2 py-0.5 rounded ${simStatus?.speed === 1.0 ? 'bg-cyber-cyan text-black font-bold' : 'text-cyber-muted'}`}
            >
              1×
            </button>
            <button
              onClick={() => handleSimSpeed(2.5)}
              className={`px-2 py-0.5 rounded ${simStatus?.speed === 2.5 ? 'bg-cyber-cyan text-black font-bold' : 'text-cyber-muted'}`}
            >
              2.5×
            </button>
            <button
              onClick={() => handleSimSpeed(5.0)}
              className={`px-2 py-0.5 rounded ${simStatus?.speed === 5.0 ? 'bg-cyber-cyan text-black font-bold' : 'text-cyber-muted'}`}
            >
              5×
            </button>
            <div className="h-4 w-px bg-cyber-border/40 mx-0.5" />
            <button
              onClick={() => setIsResetModalOpen(true)}
              className="p-1.5 rounded hover:bg-cyber-card text-cyber-muted hover:text-cyber-red transition-colors"
              title="Reset Simulation Data"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* ── B. 6 KPI Cards ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          title="Total Threats"
          value={summary.total_threats?.toLocaleString()}
          subtitle="Events recorded"
          icon={ShieldAlert}
          color="cyan"
          trend={{ direction: 'up', value: 'Live' }}
        />
        <StatCard
          title="Critical Threats"
          value={summary.critical_threats?.toLocaleString()}
          subtitle="Immediate triage"
          icon={AlertOctagon}
          color="red"
          trend={{ direction: 'up', value: 'High priority' }}
        />
        <StatCard
          title="High Severity"
          value={summary.high_threats?.toLocaleString()}
          subtitle="SYN / Port scans"
          icon={Flame}
          color="amber"
        />
        <StatCard
          title="Active Blocks"
          value={summary.active_blocked_ips?.toLocaleString()}
          subtitle="Mitigated source IPs"
          icon={Ban}
          color="green"
        />
        <StatCard
          title="Packets Analyzed"
          value={summary.packets_analyzed?.toLocaleString()}
          subtitle="Inspected headers"
          icon={Activity}
          color="blue"
        />
        <StatCard
          title="System Uptime"
          value={formatUptime(summary.uptime_seconds)}
          subtitle="Continuous monitoring"
          icon={Clock}
          color="cyan"
        />
      </div>

      {/* ── C. Traffic Area Chart & Network Activity Panel ───────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3">
          <TrafficChart
            data={trafficData}
            timeRange={trafficRange}
            onTimeRangeChange={setTrafficRange}
          />
        </div>

        {/* G. Network Activity Panel */}
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2">
              <Radio className="w-4 h-4 text-cyber-cyan animate-pulse" />
              Network Telemetry
            </h3>
            <p className="text-xs text-cyber-muted mt-0.5">
              Host sensor health & activity
            </p>

            <div className="mt-5 space-y-3.5 font-mono-code text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-cyber-border/20">
                <span className="text-cyber-muted">Status:</span>
                <span className={`font-bold ${summary.monitoring_active ? 'text-cyber-green' : 'text-cyber-red'}`}>
                  {summary.monitoring_active ? 'ACTIVE' : 'STOPPED'}
                </span>
              </div>

              <div className="flex items-center justify-between pb-2 border-b border-cyber-border/20">
                <span className="text-cyber-muted">Packets Observed:</span>
                <span className="text-cyber-text font-bold">
                  {(networkActivity?.packets_observed || 0).toLocaleString()}
                </span>
              </div>

              <div className="flex items-center justify-between pb-2 border-b border-cyber-border/20">
                <span className="text-cyber-muted">Unique Source IPs:</span>
                <span className="text-cyber-cyan font-bold">
                  {networkActivity?.unique_sources || 0}
                </span>
              </div>

              <div className="flex items-center justify-between pb-2 border-b border-cyber-border/20">
                <span className="text-cyber-muted">Suspicious Sources:</span>
                <span className="text-cyber-amber font-bold">
                  {(networkActivity?.suspicious_packets || 0).toLocaleString()}
                </span>
              </div>

              <div className="flex items-center justify-between pb-1">
                <span className="text-cyber-muted">Last Incident:</span>
                <span className="text-cyber-text text-[11px] truncate max-w-[130px]">
                  {summary.last_detection
                    ? new Date(summary.last_detection).toLocaleTimeString()
                    : 'None'}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-cyber-border/30">
            <button
              onClick={() => navigate('/threats')}
              className="w-full py-2 px-3 rounded-lg bg-cyber-panel hover:bg-cyber-cyan hover:text-black border border-cyber-border/40 text-cyber-text text-xs font-mono-code font-semibold flex items-center justify-center gap-1.5 transition-all shadow-sm"
            >
              <span>Inspect Live Threat Stream</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* ── D & E. Threat Donut and Severity Bar Charts ─────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <ThreatDonutChart data={threatTypes} />
        <SeverityBarChart data={severityDist} />
      </div>

      {/* ── F. Recent Security Events Table ─────────────────────────────────── */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-semibold uppercase tracking-wider text-cyber-text font-mono-code flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyber-cyan" />
              Recent Security Events
            </h3>
            <p className="text-xs text-cyber-muted mt-0.5">
              Near-real-time triage log of incoming detections
            </p>
          </div>

          <button
            onClick={() => navigate('/threats')}
            className="text-xs font-mono-code text-cyber-cyan hover:underline flex items-center gap-1"
          >
            <span>View All In Live Monitor</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        <ThreatTable
          threats={recentEvents}
          onViewDetails={setSelectedThreat}
          onInvestigateIP={(ip) => navigate(`/intelligence?ip=${ip}`)}
        />
      </div>

      {/* ── Event Details Inspection Modal ─────────────────────────────────── */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-lg bg-cyber-card border border-cyber-border rounded-xl shadow-2xl p-6">
            <div className="flex items-center justify-between pb-3 border-b border-cyber-border/40 mb-4">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyber-red animate-ping" />
                <h3 className="text-base font-bold text-cyber-text font-mono-code">
                  Incident #{selectedThreat.id} Details
                </h3>
              </div>
              <button
                onClick={() => setSelectedThreat(null)}
                className="text-cyber-muted hover:text-white"
              >
                &times;
              </button>
            </div>

            <div className="space-y-3 font-mono-code text-xs">
              <div className="grid grid-cols-2 gap-2 bg-cyber-panel/60 p-3 rounded-lg border border-cyber-border/30">
                <div>
                  <span className="text-cyber-muted">Source IP:</span>
                  <p className="text-cyber-cyan font-bold text-sm mt-0.5">{selectedThreat.src_ip}</p>
                </div>
                <div>
                  <span className="text-cyber-muted">Destination IP:</span>
                  <p className="text-cyber-text text-sm mt-0.5">{selectedThreat.dst_ip || 'Host System'}</p>
                </div>
                <div>
                  <span className="text-cyber-muted">Threat Vector:</span>
                  <p className="text-white font-bold mt-0.5">{selectedThreat.threat_type}</p>
                </div>
                <div>
                  <span className="text-cyber-muted">Packet Count:</span>
                  <p className="text-cyber-text font-bold mt-0.5">{selectedThreat.count || 1}</p>
                </div>
              </div>

              <div>
                <span className="text-cyber-muted block mb-1">Detection Logic / Rule Triggered:</span>
                <p className="p-3 rounded-lg bg-cyber-bg border border-cyber-border/40 text-cyber-muted leading-relaxed font-sans">
                  {selectedThreat.detection_reason || 'Threshold-based packet inspection triggered alert.'}
                </p>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-cyber-muted">Event Source:</span>
                <span className="px-2 py-0.5 rounded bg-cyber-panel border border-cyber-border/40 text-cyber-cyan">
                  {selectedThreat.event_source === 'simulation' ? 'DEMO SIMULATION' : 'LIVE CAPTURE'}
                </span>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3 pt-3 border-t border-cyber-border/30">
              <button
                onClick={() => navigate(`/intelligence?ip=${selectedThreat.src_ip}`)}
                className="px-3.5 py-1.5 rounded-lg bg-cyber-panel border border-cyber-border/60 hover:bg-cyber-cyan hover:text-black text-xs font-mono-code text-cyber-text font-semibold transition-all"
              >
                Investigate Source IP
              </button>
              <button
                onClick={() => setSelectedThreat(null)}
                className="px-4 py-1.5 rounded-lg bg-cyber-card border border-cyber-border/40 hover:bg-cyber-panel text-xs font-mono-code text-cyber-muted hover:text-cyber-text"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Modal for Reset */}
      <ConfirmationModal
        isOpen={isResetModalOpen}
        title="Reset Demonstration Data"
        message="This will clear all in-memory detector state and restart demonstration traffic from zero. Database audit records are preserved."
        confirmText="Reset Now"
        isDanger={true}
        onConfirm={handleConfirmReset}
        onClose={() => setIsResetModalOpen(false)}
      />
    </div>
  );
};

export default Dashboard;
