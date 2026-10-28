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
  Server,
  Laptop,
  Cpu,
  Layers,
  Shield,
  ArrowRight,
  Lock,
  Unlock,
  CheckCircle2,
  ChevronRight,
  Terminal,
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
  const [selectedNode, setSelectedNode] = useState('gateway');
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

  // Extract observed attacker IPs from live data
  const observedAttackers = Array.from(
    new Set(recentEvents.map((e) => e.src_ip).filter(Boolean))
  ).slice(0, 3);

  const activeAttackerIP = observedAttackers[0] || '10.0.0.99';

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-sans">
      {/* ── BENTO 1: Executive Master Control Bar ─────────────────────────────── */}
      <div className="relative bg-surface border border-bluegrey/40 rounded-2xl p-6 shadow-soft overflow-hidden">
        {/* Subtle Aurora Ambient Radial Glow */}
        <div className="absolute -bottom-10 -left-10 w-64 h-64 bg-bluegrey/5 rounded-full blur-2xl pointer-events-none" />

        {/* Blueprint corner crosshairs */}
        <div className="absolute top-2 left-2 w-2 h-2 border-t border-l border-forest/40" />
        <div className="absolute top-2 right-2 w-2 h-2 border-t border-r border-forest/40" />
        <div className="absolute bottom-2 left-2 w-2 h-2 border-b border-l border-forest/40" />
        <div className="absolute bottom-2 right-2 w-2 h-2 border-b border-r border-forest/40" />

        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 z-10 relative">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-ink font-mono-code">
                Security Operations Center
              </h1>
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-mono-code font-bold bg-sage border border-bluegrey/35 text-forest shadow-neumorph-sm">
                SOC TIER-1 WORKBENCH
              </span>
            </div>
            <p className="text-xs sm:text-sm text-muted flex items-center gap-2">
              <span className="text-forest">&bull;</span>
              <span>Autonomous Network Intrusion Detection, Telemetry & Mitigation Matrix</span>
            </p>
          </div>

          {/* Master Control Suite with Soft Neumorphism */}
          <div className="flex flex-wrap items-center gap-3">
            {/* Real-Time Live Wi-Fi vs. Demo Simulation Switcher */}
            <div className="flex items-center gap-1 bg-sage border border-bluegrey/40 p-1 rounded-xl text-xs font-mono-code shadow-neumorph-inset">
              <button
                onClick={handleSwitchToLive}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all text-xs font-semibold ${
                  summary.monitoring_mode === 'live'
                    ? 'bg-good text-ink shadow-soft font-bold'
                    : 'text-muted hover:text-ink hover:bg-sage'
                }`}
                title="Capture and analyze real network packets from active network adapter"
              >
                <Wifi className="w-3.5 h-3.5" />
                <span>Live Sniffer</span>
              </button>

              <button
                onClick={handleSwitchToSimulation}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all text-xs font-semibold ${
                  summary.monitoring_mode === 'simulation'
                    ? 'bg-forest text-white shadow-soft font-bold'
                    : 'text-muted hover:text-ink hover:bg-sage'
                }`}
                title="Run synthetic attack demonstration scenarios"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Demo Mode</span>
              </button>
            </div>

            {/* Engine Start/Stop Button */}
            <button
              onClick={handleToggleMonitoring}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono-code font-bold transition-all shadow-md ${
                summary.monitoring_active
                  ? 'bg-bad/15 border border-bad/40 text-bad-ink hover:bg-bad hover:text-white shadow-soft'
                  : 'bg-good/15 border border-good/40 text-good-ink hover:bg-good hover:text-ink shadow-soft'
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

            {/* Simulation Speed & Controls Pill */}
            <div className="flex items-center gap-1 bg-sage border border-bluegrey/40 p-1 rounded-xl text-xs font-mono-code shadow-neumorph-inset">
              <button
                onClick={handleSimPause}
                className={`p-1.5 rounded-lg hover:bg-sage transition-colors ${
                  simStatus?.paused ? 'text-amber-ink font-bold' : 'text-muted'
                }`}
                title={simStatus?.paused ? 'Resume Simulation' : 'Pause Simulation'}
              >
                {simStatus?.paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
              </button>
              <div className="h-4 w-px bg-bluegrey/60 mx-0.5" />
              <button
                onClick={() => handleSimSpeed(1.0)}
                className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-colors ${
                  simStatus?.speed === 1.0 ? 'bg-forest text-white font-bold' : 'text-muted hover:text-ink'
                }`}
              >
                1×
              </button>
              <button
                onClick={() => handleSimSpeed(2.5)}
                className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-colors ${
                  simStatus?.speed === 2.5 ? 'bg-forest text-white font-bold' : 'text-muted hover:text-ink'
                }`}
              >
                2.5×
              </button>
              <button
                onClick={() => handleSimSpeed(5.0)}
                className={`px-2 py-0.5 rounded text-[11px] font-semibold transition-colors ${
                  simStatus?.speed === 5.0 ? 'bg-forest text-white font-bold' : 'text-muted hover:text-ink'
                }`}
              >
                5×
              </button>
              <div className="h-4 w-px bg-bluegrey/60 mx-0.5" />
              <button
                onClick={() => setIsResetModalOpen(true)}
                className="p-1.5 rounded-lg hover:bg-sage text-muted hover:text-bad-ink transition-colors"
                title="Reset Simulation Data"
              >
                <RotateCcw className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ── BENTO 2: Bento Grid Key Performance Telemetry (6 Cards) ─────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          title="Total Threats"
          value={summary.total_threats?.toLocaleString()}
          subtitle="Events recorded"
          icon={ShieldAlert}
          color="cyan"
          trend={{ direction: 'up', value: 'Live Feed' }}
        />
        <StatCard
          title="Critical Alerts"
          value={summary.critical_threats?.toLocaleString()}
          subtitle="Immediate triage tier"
          icon={AlertOctagon}
          color="red"
          trend={{ direction: 'up', value: 'Priority' }}
        />
        <StatCard
          title="High Severity"
          value={summary.high_threats?.toLocaleString()}
          subtitle="SYN Floods / Port scans"
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
          color="purple"
        />
      </div>

      {/* ── BENTO 3: Visual Centerpiece — Blueprint Network Topology Visualizer ─── */}
      <div className="bg-surface border border-bluegrey/40 rounded-2xl p-6 shadow-soft relative overflow-hidden">
        {/* Top subtle aurora gradient accent */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-bluegrey via-forest to-bluegrey" />

        {/* Header with technical workbench coordinates */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-6 pb-4 border-b border-bluegrey/25">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-bluegrey/15 border border-bluegrey/30 text-forest shadow-neumorph-sm">
              <Layers className="w-5 h-5 text-forest" />
            </div>
            <div>
              <h3 className="text-sm sm:text-base font-bold text-ink font-mono-code flex items-center gap-2">
                Blueprint-Style Network Topology & Real-Time Flow Visualizer
              </h3>
              <p className="text-xs text-muted mt-0.5">
                Physical sensor observation point, ingress traffic routing, containment barrier, and protected server endpoints
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono-code">
            <span className="px-2.5 py-1 rounded-lg bg-sage border border-bluegrey/50 text-muted">
              LAT: <span className="text-good-ink">0.38 ms</span>
            </span>
            <span className="px-2.5 py-1 rounded-lg bg-sage border border-bluegrey/50 text-muted">
              FILTER: <span className="text-bluegrey-ink">STRICT</span>
            </span>
          </div>
        </div>

        {/* Blueprint Engineering Canvas */}
        <div className="blueprint-canvas rounded-xl border border-bluegrey/40 p-6 relative overflow-x-auto min-h-[300px] flex flex-col justify-between shadow-inner">
          {/* Subtle Technical Grid Overlay & Coordinate Labels */}
          <div className="absolute top-2 left-3 text-[10px] font-mono-code text-bluegrey-ink/50 tracking-widest pointer-events-none">
            TOPOLOGY GRID: SEC-ZONE-01 // COORD [37.7749, -122.4194]
          </div>
          <div className="absolute top-2 right-3 text-[10px] font-mono-code text-forest/50 tracking-widest pointer-events-none">
            PROTOCOL: TCP/IP STACK &bull; ICMP &bull; UDP
          </div>

          {/* Interactive Node Pipeline */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 relative z-10 my-4 items-center">
            {/* Node 1: Ingress / Attacker Sources */}
            <div
              onClick={() => setSelectedNode('attacker')}
              className={`p-4 rounded-xl border transition-all cursor-pointer relative ${
                selectedNode === 'attacker'
                  ? 'bg-sage border-bad shadow-soft ring-1 ring-bad/50'
                  : 'bg-sage/80 hover:bg-sage border-bluegrey/40 hover:border-bad/40'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] uppercase font-mono-code font-bold text-bad-ink flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-bad animate-ping" />
                  Ingress Attacker
                </span>
                <Laptop className="w-4 h-4 text-bad-ink" />
              </div>
              <p className="font-mono-code text-xs font-bold text-ink truncate">
                {activeAttackerIP}
              </p>
              <p className="text-[10px] text-muted mt-1 font-mono-code">
                Recon / SYN Flood Source
              </p>
              <div className="mt-3 pt-2 border-t border-bluegrey/25 flex items-center justify-between text-[10px] font-mono-code">
                <span className="text-muted">Threat Count:</span>
                <span className="text-bad-ink font-bold">{summary.total_threats || 0}</span>
              </div>
            </div>

            {/* Connection Arrow 1 */}
            <div className="hidden md:flex flex-col items-center justify-center text-forest font-mono-code text-[10px]">
              <div className="w-full flex items-center justify-center relative">
                <div className="h-[2px] w-full bg-gradient-to-r from-bad to-forest opacity-60" />
                <ArrowRight className="w-4 h-4 text-forest absolute right-0 -top-2 animate-pulse" />
              </div>
              <span className="text-[9px] text-muted mt-1">Raw Ingress</span>
            </div>

            {/* Node 2: Sensor / Sniffer Gateway */}
            <div
              onClick={() => setSelectedNode('gateway')}
              className={`p-4 rounded-xl border transition-all cursor-pointer relative ${
                selectedNode === 'gateway'
                  ? 'bg-sage border-forest shadow-soft ring-1 ring-forest/50'
                  : 'bg-sage/80 hover:bg-sage border-bluegrey/40 hover:border-forest/40'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] uppercase font-mono-code font-bold text-forest flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-forest animate-pulse" />
                  Sensor Sniffer
                </span>
                <Radio className="w-4 h-4 text-forest" />
              </div>
              <p className="font-mono-code text-xs font-bold text-ink">
                192.168.1.100
              </p>
              <p className="text-[10px] text-muted mt-1 font-mono-code">
                Promiscuous Wi-Fi Monitor
              </p>
              <div className="mt-3 pt-2 border-t border-bluegrey/25 flex items-center justify-between text-[10px] font-mono-code">
                <span className="text-muted">Mode:</span>
                <span className="text-good-ink font-bold uppercase">{summary.monitoring_mode}</span>
              </div>
            </div>

            {/* Connection Arrow 2 */}
            <div className="hidden md:flex flex-col items-center justify-center text-bluegrey-ink font-mono-code text-[10px]">
              <div className="w-full flex items-center justify-center relative">
                <div className="h-[2px] w-full bg-gradient-to-r from-forest to-bluegrey opacity-60" />
                <ArrowRight className="w-4 h-4 text-bluegrey-ink absolute right-0 -top-2 animate-pulse" />
              </div>
              <span className="text-[9px] text-muted mt-1">Inspection</span>
            </div>

            {/* Node 3: Automated Containment Firewall */}
            <div
              onClick={() => setSelectedNode('firewall')}
              className={`p-4 rounded-xl border transition-all cursor-pointer relative ${
                selectedNode === 'firewall'
                  ? 'bg-sage border-bluegrey shadow-soft ring-1 ring-bluegrey/50'
                  : 'bg-sage/80 hover:bg-sage border-bluegrey/40 hover:border-bluegrey/40'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] uppercase font-mono-code font-bold text-bluegrey-ink flex items-center gap-1">
                  <Shield className="w-3.5 h-3.5" />
                  Defense Barrier
                </span>
                <Lock className="w-4 h-4 text-bluegrey-ink" />
              </div>
              <p className="font-mono-code text-xs font-bold text-ink">
                iptables Engine
              </p>
              <p className="text-[10px] text-muted mt-1 font-mono-code">
                Automated Containment
              </p>
              <div className="mt-3 pt-2 border-t border-bluegrey/25 flex items-center justify-between text-[10px] font-mono-code">
                <span className="text-muted">Blocks Enforced:</span>
                <span className="text-good-ink font-bold">{summary.active_blocked_ips || 0}</span>
              </div>
            </div>
          </div>

          {/* Blueprint Node Inspection Tray */}
          <div className="mt-4 pt-4 border-t border-bluegrey/25 flex flex-wrap items-center justify-between gap-4 text-xs font-mono-code">
            <div className="flex flex-wrap items-center gap-3 text-[11px]">
              <span className="text-muted">Target Host:</span>
              <span className="px-2 py-0.5 rounded bg-sage text-ink border border-bluegrey/50">
                127.0.0.1 (Loopback Protected)
              </span>
              <span className="text-muted ml-2">Monitored Ports:</span>
              <span className="px-2 py-0.5 rounded bg-sage text-forest border border-bluegrey/50">
                80 (HTTP) &bull; 443 (HTTPS) &bull; 22 (SSH)
              </span>
            </div>

            <button
              onClick={() => navigate('/intelligence?ip=' + activeAttackerIP)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sage hover:bg-forest hover:text-white border border-bluegrey/40 text-ink text-xs transition-all shadow-neumorph-sm"
            >
              <span>Investigate Observed Source</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* ── BENTO 4: Traffic Volume Chart & Network Telemetry Panel ──────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3">
          <TrafficChart
            data={trafficData}
            timeRange={trafficRange}
            onTimeRangeChange={setTrafficRange}
          />
        </div>

        {/* Telemetry Sensor Activity Panel */}
        <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft flex flex-col justify-between relative overflow-hidden">
          {/* Top subtle aurora gradient line */}
          <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-forest to-bluegrey opacity-60" />

          {/* Blueprint technical corner markers */}
          <div className="absolute top-1.5 left-1.5 w-1.5 h-1.5 border-t border-l border-bluegrey/25 pointer-events-none" />
          <div className="absolute bottom-1.5 right-1.5 w-1.5 h-1.5 border-b border-r border-bluegrey/25 pointer-events-none" />

          <div>
            <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-ink font-mono-code flex items-center gap-2">
              <Radio className="w-4 h-4 text-forest animate-pulse" />
              Network Telemetry
            </h3>
            <p className="text-xs text-muted mt-0.5">
              Host sniffer sensor health & activity
            </p>

            <div className="mt-5 space-y-3.5 font-mono-code text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-bluegrey/25">
                <span className="text-muted">Engine Status:</span>
                <span className={`font-bold ${summary.monitoring_active ? 'text-good-ink' : 'text-bad-ink'}`}>
                  {summary.monitoring_active ? 'ACTIVE' : 'STOPPED'}
                </span>
              </div>

              <div className="flex items-center justify-between pb-2 border-b border-bluegrey/25">
                <span className="text-muted">Packets Observed:</span>
                <span className="text-ink font-bold">
                  {(networkActivity?.packets_observed || 0).toLocaleString()}
                </span>
              </div>

              <div className="flex items-center justify-between pb-2 border-b border-bluegrey/25">
                <span className="text-muted">Unique Source IPs:</span>
                <span className="text-forest font-bold">
                  {networkActivity?.unique_sources || 0}
                </span>
              </div>

              <div className="flex items-center justify-between pb-2 border-b border-bluegrey/25">
                <span className="text-muted">Suspicious Packets:</span>
                <span className="text-amber-ink font-bold">
                  {(networkActivity?.suspicious_packets || 0).toLocaleString()}
                </span>
              </div>

              <div className="flex items-center justify-between pb-1">
                <span className="text-muted">Last Incident:</span>
                <span className="text-ink text-[11px] truncate max-w-[130px]">
                  {summary.last_detection
                    ? new Date(summary.last_detection).toLocaleTimeString()
                    : 'None'}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-bluegrey/25">
            <button
              onClick={() => navigate('/threats')}
              className="w-full py-2.5 px-3 rounded-lg bg-sage hover:bg-forest hover:text-white border border-bluegrey/40 text-ink text-xs font-mono-code font-semibold flex items-center justify-center gap-1.5 transition-all shadow-neumorph-sm"
            >
              <span>Inspect Live Threat Stream</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* ── BENTO 5: Threat Vector Distribution & Severity Classification ────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <ThreatDonutChart data={threatTypes} />
        <SeverityBarChart data={severityDist} />
      </div>

      {/* ── BENTO 6: Recent Security Events Table ────────────────────────────── */}
      <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft relative overflow-hidden">
        {/* Top subtle aurora gradient line */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-bluegrey via-forest to-bluegrey opacity-60" />

        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-ink font-mono-code flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-forest shadow-soft" />
              Recent Security Events
            </h3>
            <p className="text-xs text-muted mt-0.5">
              Near-real-time triage log of incoming detections
            </p>
          </div>

          <button
            onClick={() => navigate('/threats')}
            className="text-xs font-mono-code text-forest hover:text-bluegrey-ink hover:underline flex items-center gap-1"
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

      {/* ── Event Details Inspection Modal (Hybrid Aurora Frosted Glass) ──────── */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/40 animate-fadeIn">
          <div className="relative w-full max-w-lg bg-surface border border-bluegrey/40 rounded-2xl shadow-soft p-6 overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-bad to-bluegrey" />

            <div className="flex items-center justify-between pb-3 border-b border-bluegrey/25 mb-4">
              <div className="flex items-center gap-2.5">
                <span className="w-2.5 h-2.5 rounded-full bg-bad animate-ping" />
                <h3 className="text-base font-bold text-ink font-mono-code">
                  Incident #{selectedThreat.id} Telemetry Dossier
                </h3>
              </div>
              <button
                onClick={() => setSelectedThreat(null)}
                className="text-muted hover:text-ink text-lg font-bold p-1 rounded-lg hover:bg-sage"
              >
                &times;
              </button>
            </div>

            <div className="space-y-3 font-mono-code text-xs">
              <div className="grid grid-cols-2 gap-2 bg-sage p-3.5 rounded-xl border border-bluegrey/50 shadow-neumorph-inset">
                <div>
                  <span className="text-muted text-[11px]">Source IP:</span>
                  <p className="text-forest font-bold text-sm mt-0.5">{selectedThreat.src_ip}</p>
                </div>
                <div>
                  <span className="text-muted text-[11px]">Destination IP:</span>
                  <p className="text-ink text-sm mt-0.5">{selectedThreat.dst_ip || 'Host System'}</p>
                </div>
                <div>
                  <span className="text-muted text-[11px]">Threat Vector:</span>
                  <p className="text-bad-ink font-bold mt-0.5">{selectedThreat.threat_type}</p>
                </div>
                <div>
                  <span className="text-muted text-[11px]">Packet Count:</span>
                  <p className="text-ink font-bold mt-0.5">{selectedThreat.count || 1}</p>
                </div>
              </div>

              <div>
                <span className="text-muted block mb-1">Detection Logic / Rule Triggered:</span>
                <p className="p-3 rounded-xl bg-mist border border-bluegrey/50 text-muted leading-relaxed font-sans text-xs">
                  {selectedThreat.detection_reason || 'Threshold-based packet inspection triggered alert.'}
                </p>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-muted">Event Source:</span>
                <span className="px-2.5 py-0.5 rounded-md bg-sage border border-bluegrey/50 text-forest">
                  {selectedThreat.event_source === 'simulation' ? 'DEMO SIMULATION' : 'LIVE WI-FI CAPTURE'}
                </span>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3 pt-3 border-t border-bluegrey/25">
              <button
                onClick={() => navigate(`/intelligence?ip=${selectedThreat.src_ip}`)}
                className="px-4 py-2 rounded-lg bg-forest hover:bg-forest/90 text-white text-xs font-mono-code font-semibold transition-all shadow-soft"
              >
                Investigate Source IP
              </button>
              <button
                onClick={() => setSelectedThreat(null)}
                className="px-4 py-2 rounded-lg bg-sage border border-bluegrey/50 hover:bg-sage text-xs font-mono-code text-muted hover:text-ink shadow-neumorph-sm"
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
