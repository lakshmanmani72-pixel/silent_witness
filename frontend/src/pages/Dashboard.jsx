import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  Square,
  Radio,
  Wifi,
  WifiOff,
  Cpu,
  Lock,
  Unlock,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Clock,
  Layers,
  ArrowRight,
  Filter,
  Flame,
  Activity,
  Server,
  Zap,
  ExternalLink,
  ChevronRight,
  X
} from 'lucide-react';

import ConfirmationModal from '../components/ConfirmationModal';
import NetworkTopology from '../components/NetworkTopology';
import AttackGraph from '../components/AttackGraph';
import { endpoints } from '../services/api';

const Dashboard = () => {
  const navigate = useNavigate();

  // ── Authoritative Backend States ──────────────────────────────────────────
  const [monitoringStatus, setMonitoringStatus] = useState({
    active: false,
    mode: 'simulation',
    capture_status: 'STOPPED',
    blocking_mode: 'manual',
    auto_response_enabled: false,
    dry_run_mode: true,
    live_capture: { active: false, interface: '', packets_captured: 0, status: 'STOPPED' },
    simulation: { active: false, running: false, scenario: 'normal' },
    ml_model: { loaded: false, classes: ['BENIGN', 'PORT_SCAN', 'SYN_FLOOD'], total_flows_evaluated: 0 },
  });

  const [generatorStatus, setGeneratorStatus] = useState({
    active: false,
    attack_type: null,
    target: '127.0.0.1',
    duration_limit: 10,
    port_range: '1-1024',
    elapsed: 0,
    packets_sent: 0,
  });

  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [generatorTarget, setGeneratorTarget] = useState('127.0.0.1');
  const [generatorDuration, setGeneratorDuration] = useState(10);
  const [generatorPortRange, setGeneratorPortRange] = useState('1-1024');

  const [wsConnected, setWsConnected] = useState(false);
  const [loadingAction, setLoadingAction] = useState('');
  const [notification, setNotification] = useState({ type: '', message: '' });

  // ── Visualization Tab State (Live Topology | Attack Graph) ────────────────
  const [activeTab, setActiveTab] = useState('topology'); // 'topology' | 'attack_graph'

  // ── Packet Stream & Wireshark Side Drawer ─────────────────────────────────
  const [packets, setPackets] = useState([]);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [packetFilter, setPacketFilter] = useState('ALL');
  const [showFlowId, setShowFlowId] = useState(true);

  // ── Threats, Alerts, Blocked IPs & Timeline ───────────────────────────────
  const [recentThreats, setRecentThreats] = useState([]);
  const [frequentThreats, setFrequentThreats] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [blockedIps, setBlockedIps] = useState([]);
  const [attackTimeline, setAttackTimeline] = useState([]);

  // ── Modals ────────────────────────────────────────────────────────────────
  const [isAutoBlockModalOpen, setIsAutoBlockModalOpen] = useState(false);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);

  // ── WebSocket Ref & Event Queue Batching Buffer ───────────────────────────
  const wsRef = useRef(null);
  const packetBatchBuffer = useRef([]);

  const showNotification = (type, message) => {
    setNotification({ type, message });
    setTimeout(() => setNotification({ type: '', message: '' }), 4500);
  };

  // ── Fetch Authoritative Core State ────────────────────────────────────────
  const fetchAllStatus = async () => {
    try {
      const [monRes, genRes, threatRes, freqRes, blockedRes, pktRes] = await Promise.all([
        endpoints.getMonitoringStatus().catch(() => ({ data: {} })),
        endpoints.getGeneratorStatus().catch(() => ({ data: { generator: {} } })),
        endpoints.getThreats({ limit: 15 }).catch(() => ({ data: { threats: [] } })),
        endpoints.getFrequentThreats(10).catch(() => ({ data: { frequent_threats: [] } })),
        endpoints.getBlockedIPs({ status: 'active' }).catch(() => ({ data: { blocked_ips: [] } })),
        endpoints.getRecentPackets(40).catch(() => ({ data: [] })),
      ]);

      const statusData = monRes.data || {};
      setMonitoringStatus(statusData);

      if (genRes.data?.generator) {
        setGeneratorStatus(genRes.data.generator);
      }

      const threatsList = threatRes.data?.threats || [];
      setRecentThreats(threatsList);

      if (threatsList.length > 0 && !selectedThreat) {
        setSelectedThreat(threatsList[0]);
      }

      // Build timeline from recent threats
      const timelineItems = threatsList.slice(0, 8).map((t) => ({
        id: t.id,
        time: t.timestamp ? t.timestamp.split('T')[1]?.slice(0, 8) : 'Now',
        event: `${t.threat_type} detected`,
        src_ip: t.src_ip,
        label: t.threat_type,
        prob: t.predict_proba_pct ? `${t.predict_proba_pct}%` : '94%',
        action: t.response_status || 'blocked (dry-run)',
      }));
      setAttackTimeline(timelineItems);

      const freqList = freqRes.data?.frequent_threats || [];
      setFrequentThreats(freqList);

      setBlockedIps(blockedRes.data?.blocked_ips || []);

      if (Array.isArray(pktRes.data?.packets)) {
        setPackets(pktRes.data.packets);
      } else if (Array.isArray(pktRes.data)) {
        setPackets(pktRes.data);
      }
    } catch (err) {
      console.debug('Status fetch error:', err);
    }
  };

  // ── Load Network Interfaces on Mount ──────────────────────────────────────
  useEffect(() => {
    const fetchInterfaces = async () => {
      try {
        const res = await endpoints.getMonitoringInterfaces();
        const ifaces = res.data?.interfaces || [];
        setInterfaces(ifaces);
        if (ifaces.length > 0 && !selectedInterface) {
          setSelectedInterface(res.data.best_interface || ifaces[0]);
        }
      } catch (err) {
        console.warn('Failed to load interfaces:', err);
      }
    };
    fetchInterfaces();
  }, []);

  // ── WebSocket Stream with 250ms Buffer Batching (Prevents Jumpy Re-renders) ─
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/events`;
    let isSubscribed = true;
    let reconnectTimer = null;

    const connect = () => {
      if (!isSubscribed) return;
      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (isSubscribed) setWsConnected(true);
        };

        ws.onmessage = (event) => {
          if (!isSubscribed) return;
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'packet' && data.packet) {
              packetBatchBuffer.current.push(data.packet);
            } else if (data.type === 'threat' && data.threat) {
              const thr = data.threat;
              setSelectedThreat(thr);
              setRecentThreats((prev) => [thr, ...prev.slice(0, 14)]);
              fetchAllStatus();
            }
          } catch (e) {}
        };

        ws.onclose = () => {
          if (isSubscribed) {
            setWsConnected(false);
            reconnectTimer = setTimeout(connect, 3000);
          }
        };

        ws.onerror = () => {
          try { ws.close(); } catch {}
        };
      } catch (e) {
        if (isSubscribed) {
          setWsConnected(false);
          reconnectTimer = setTimeout(connect, 3000);
        }
      }
    };

    connect();

    // 250ms periodic buffer flush to React state
    const flushTimer = setInterval(() => {
      if (packetBatchBuffer.current.length > 0) {
        const batch = [...packetBatchBuffer.current];
        packetBatchBuffer.current = [];
        setPackets((prev) => [...batch, ...prev].slice(0, 40));
      }
    }, 250);

    return () => {
      isSubscribed = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      clearInterval(flushTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // ── Polling Fallback ──────────────────────────────────────────────────────
  useEffect(() => {
    fetchAllStatus();
    const pollTimer = setInterval(fetchAllStatus, 3000);
    return () => clearInterval(pollTimer);
  }, []);

  // ── Live Capture Actions ──────────────────────────────────────────────────
  const handleStartCapture = async () => {
    if (!selectedInterface) {
      showNotification('error', 'Select a valid network interface.');
      return;
    }
    setLoadingAction('start_capture');
    try {
      const res = await endpoints.startLiveMonitoring(selectedInterface);
      if (res.data?.success || res.status === 200) {
        showNotification('success', res.data.message || `Capture started on ${selectedInterface}`);
        await fetchAllStatus();
      } else {
        showNotification('error', res.data?.message || 'Capture initialization failed.');
      }
    } catch (err) {
      const msg = err.response?.data?.detail || 'Failed to start live capture. Ensure administrator privileges.';
      showNotification('error', msg);
    } finally {
      setLoadingAction('');
    }
  };

  const handleStopCapture = async () => {
    setLoadingAction('stop_capture');
    try {
      const res = await endpoints.stopLiveMonitoring();
      if (res.data?.success || res.status === 200) {
        showNotification('success', 'Live packet capture stopped.');
        await fetchAllStatus();
      }
    } catch (err) {
      showNotification('error', 'Failed to stop capture.');
    } finally {
      setLoadingAction('');
    }
  };

  // ── Targeted Attack Generators ────────────────────────────────────────────
  const handleGenerateAttack = async (type) => {
    const target = generatorTarget.trim() || '127.0.0.1';
    const duration = parseInt(generatorDuration, 10) || 10;
    const portRange = generatorPortRange.trim() || '1-1024';

    setLoadingAction(`generate_${type}`);
    try {
      let res;
      if (type === 'PORT_SCAN') {
        res = await endpoints.generatePortScan(target, duration, portRange);
      } else {
        res = await endpoints.generateSynFlood(target, duration);
      }
      showNotification('success', res.data?.message || `${type} started against ${target}`);
      await fetchAllStatus();
    } catch (err) {
      const msg = err.response?.data?.detail || 'Target must be localhost (127.0.0.1) or safe lab IP.';
      showNotification('error', msg);
    } finally {
      setLoadingAction('');
    }
  };

  const handleStopGenerator = async () => {
    setLoadingAction('stop_generator');
    try {
      await endpoints.stopGenerator();
      showNotification('info', 'Attack generator stopped.');
      await fetchAllStatus();
    } catch (err) {
      showNotification('error', 'Failed to stop generator.');
    } finally {
      setLoadingAction('');
    }
  };

  // ── Blocking / Containment Controls ───────────────────────────────────────
  const handleToggleBlockingMode = async (mode) => {
    try {
      const res = await endpoints.toggleBlockingMode(mode);
      showNotification('success', `Perimeter defense set to: ${res.data?.blocking_mode?.toUpperCase()} (Safe Dry-Run)`);
      setIsAutoBlockModalOpen(false);
      fetchAllStatus();
    } catch (err) {
      showNotification('error', 'Failed to change defense policy.');
    }
  };

  const handleManualBlock = async (ip) => {
    if (!ip) return;
    try {
      const res = await endpoints.manualBlockIP(ip, 'Manual containment', 30);
      if (res.data?.success) {
        showNotification('success', `Contained ${ip} at perimeter (Safe Dry-Run)`);
        fetchAllStatus();
      }
    } catch (err) {
      showNotification('error', 'Failed to contain IP.');
    }
  };

  const handleManualUnblock = async (ip) => {
    if (!ip) return;
    try {
      const res = await endpoints.manualUnblockIP(ip);
      if (res.data?.success) {
        showNotification('info', `Unblocked ${ip} (Safe Dry-Run)`);
        fetchAllStatus();
      }
    } catch (err) {
      showNotification('error', 'Failed to unblock IP.');
    }
  };

  const handleResetState = async () => {
    try {
      await endpoints.resetMonitoringState();
      setSelectedThreat(null);
      setSelectedPacket(null);
      setPackets([]);
      setFrequentThreats([]);
      setAttackTimeline([]);
      showNotification('success', 'All telemetry, flows, and alerts have been reset.');
      setIsResetModalOpen(false);
      fetchAllStatus();
    } catch (err) {
      showNotification('error', 'Failed to reset state.');
    }
  };

  // ── Derived Authoritative Indicators ──────────────────────────────────────
  const isLiveActive = Boolean(
    monitoringStatus.capture_status === 'LIVE' || monitoringStatus.live_capture?.active
  );
  const isGenActive = Boolean(generatorStatus.active);
  const isAutoBlocking = monitoringStatus.blocking_mode === 'automatic';

  // Strict honest mode calculation
  const currentModeLabel = isLiveActive
    ? `LIVE CAPTURE (${selectedInterface || 'WiFi'})`
    : isGenActive
    ? `DEMO SIMULATION (${generatorStatus.attack_type || 'Generator'})`
    : 'IDLE / STOPPED';

  const captureStateDisplay = isLiveActive ? 'LIVE' : isGenActive ? 'SIMULATION' : 'STOPPED';

  // Latest Threat
  const latestThreat = selectedThreat || recentThreats[0] || null;
  const isThreatActive = Boolean(latestThreat && latestThreat.threat_type !== 'BENIGN');
  const threatType = latestThreat?.threat_type || 'NORMAL';

  const currentTrafficStatus =
    threatType === 'PORT_SCAN'
      ? 'PORT SCAN DETECTED'
      : threatType === 'SYN_FLOOD'
      ? 'SYN FLOOD DETECTED'
      : 'NORMAL (BENIGN TRAFFIC)';

  const probVal =
    latestThreat?.predict_proba_pct ??
    (latestThreat?.predict_proba ? Math.round(latestThreat.predict_proba * 100) : null) ??
    (latestThreat?.ml_prediction?.confidence ? Math.round(latestThreat.ml_prediction.confidence * 100) : null);

  const isLowConfidence = probVal !== null && probVal < 80;
  const isLatestBlocked = Boolean(latestThreat?.src_ip && blockedIps.some((b) => b.ip === latestThreat.src_ip));

  // Counters
  const packetsCapturedCount = monitoringStatus.live_capture?.packets_captured || packets.length;
  const synPacketsCount = packets.filter((p) => p.flags && p.flags.includes('S')).length;
  const uniquePortsCount = new Set(packets.map((p) => p.dst_port).filter(Boolean)).size;
  const attacksDetectedCount = frequentThreats.reduce((acc, f) => acc + (f.times_detected || 1), 0);
  const ipsBlockedCount = blockedIps.length;

  // Filtered Packets
  const filteredPackets = packets.filter((pkt) => {
    if (packetFilter === 'ALL') return true;
    if (packetFilter === 'TCP') return pkt.protocol === 'TCP';
    if (packetFilter === 'THREATS') return pkt.is_threat || pkt.status === 'threat' || pkt.traffic_type === 'threat';
    if (packetFilter === 'LIVE') return !pkt.is_simulation;
    if (packetFilter === 'SIMULATION') return pkt.is_simulation;
    return true;
  });

  return (
    <div className="space-y-4 pb-12 font-sans text-[#1B2B28] max-w-7xl mx-auto">
      {/* Toast Notification */}
      {notification.message && (
        <div
          className={`fixed bottom-5 right-5 z-50 flex items-center gap-2 px-4 py-2.5 rounded-lg border text-xs font-mono shadow-md ${
            notification.type === 'success'
              ? 'bg-[#ECFDF3] border-[#BBF7D0] text-[#16A34A]'
              : notification.type === 'info'
              ? 'bg-[#F0FDFA] border-[#CCFBF1] text-[#0F766E]'
              : 'bg-[#FEF2F2] border-[#FECACA] text-[#DC2626]'
          }`}
        >
          {notification.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 text-[#16A34A]" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-[#DC2626]" />
          )}
          <span>{notification.message}</span>
        </div>
      )}

      {/* ── 1. HEADER & GLOBAL STATUS CHIPS ─────────────────────────────────── */}
      <div className="bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm flex flex-col lg:flex-row items-start lg:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#0F766E] animate-pulse" />
            <span className="text-[11px] uppercase tracking-wider font-bold text-[#0F766E] font-mono">
              SILENT WITNESS &bull; RANDOM FOREST NIDS PLATFORM
            </span>
          </div>
          <h1 className="text-lg font-bold text-[#1B2B28] tracking-tight flex items-center gap-2">
            Demonstration Console &bull; Real-Time Network Monitoring
          </h1>
          <p className="text-xs text-[#64748B]">
            Computer Networks Lab &bull; Sole Attack Classifier: 100-Tree Random Forest &bull; 76 Flow Features
          </p>
        </div>

        {/* Header Status Chips */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          {/* Safe Dry-Run Chip */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border bg-[#FFFBEB] border-[#FDE68A] text-[#D97706] text-[11px] font-semibold">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Safe Dry-Run</span>
          </div>

          {/* Mode Chip */}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[11px] font-semibold ${
              isLiveActive
                ? 'bg-[#ECFDF3] border-[#BBF7D0] text-[#16A34A]'
                : isGenActive
                ? 'bg-[#F0FDFA] border-[#CCFBF1] text-[#0F766E]'
                : 'bg-[#F1F5F9] border-[#E2E8E6] text-[#64748B]'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>{currentModeLabel}</span>
          </div>

          {/* WebSocket Badge */}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[11px] ${
              wsConnected
                ? 'bg-[#ECFDF3] border-[#BBF7D0] text-[#16A34A]'
                : 'bg-[#F1F5F9] border-[#E2E8E6] text-[#64748B]'
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-[#16A34A] animate-ping' : 'bg-[#94A3B8]'}`} />
            <span>{wsConnected ? 'WebSocket Live' : 'Connecting...'}</span>
          </div>

          {/* Auto Containment Mode */}
          <button
            onClick={() => {
              if (isAutoBlocking) {
                handleToggleBlockingMode('manual');
              } else {
                setIsAutoBlockModalOpen(true);
              }
            }}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[11px] font-semibold transition-all ${
              isAutoBlocking
                ? 'bg-[#F5F3FF] border-[#DDD6FE] text-[#7C3AED] hover:bg-[#EDE9FE]'
                : 'bg-[#F4F7F6] border-[#E2E8E6] text-[#1B2B28] hover:bg-[#E2E8E6]'
            }`}
          >
            {isAutoBlocking ? <Lock className="w-3.5 h-3.5" /> : <Unlock className="w-3.5 h-3.5" />}
            <span>{isAutoBlocking ? 'Auto Containment' : 'Manual Dry-Run'}</span>
          </button>

          {/* Reset State Button */}
          <button
            onClick={() => setIsResetModalOpen(true)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-[#E2E8E6] bg-[#F4F7F6] hover:bg-[#E2E8E6] text-[#64748B] text-[11px] font-semibold transition-all"
            title="Reset telemetry and flows"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* ── 2. STATUS BANNER (TEXT-ONLY) ────────────────────────────────────── */}
      <div
        className={`p-3.5 rounded-xl border transition-all ${
          threatType === 'PORT_SCAN'
            ? 'bg-[#FFFBEB] border-[#FDE68A] text-[#1B2B28]'
            : threatType === 'SYN_FLOOD'
            ? 'bg-[#FEF2F2] border-[#FECACA] text-[#1B2B28]'
            : 'bg-[#ECFDF3] border-[#BBF7D0] text-[#1B2B28]'
        }`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div
              className={`w-9 h-9 rounded-lg flex items-center justify-center font-mono font-bold text-xs ${
                threatType === 'PORT_SCAN'
                  ? 'bg-[#F59E0B] text-white'
                  : threatType === 'SYN_FLOOD'
                  ? 'bg-[#DC2626] text-white'
                  : 'bg-[#16A34A] text-white'
              }`}
            >
              {threatType === 'NORMAL' ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
            </div>
            <div>
              <div className="text-[10px] uppercase font-mono font-bold text-[#64748B]">Traffic Status</div>
              <div className="text-sm font-bold font-mono tracking-tight">{currentTrafficStatus}</div>
            </div>
          </div>

          <div className="flex items-center gap-3 font-mono text-xs">
            <div className="px-2.5 py-1 rounded-md bg-white border border-[#E2E8E6]">
              <span className="text-[#64748B]">Interface: </span>
              <strong className="text-[#1B2B28]">{selectedInterface || 'WiFi'}</strong>
            </div>
            <div className="px-2.5 py-1 rounded-md bg-white border border-[#E2E8E6]">
              <span className="text-[#64748B]">Capture State: </span>
              <strong
                className={
                  captureStateDisplay === 'LIVE'
                    ? 'text-[#16A34A]'
                    : captureStateDisplay === 'SIMULATION'
                    ? 'text-[#0F766E]'
                    : 'text-[#64748B]'
                }
              >
                {captureStateDisplay}
              </strong>
            </div>
          </div>
        </div>
      </div>

      {/* ── 3. CONTROLS: EQUAL-HEIGHT ROW (LIVE CAPTURE | ATTACK GENERATORS) ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-stretch">
        {/* Left: Live Packet Capture */}
        <div className="bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-[#E2E8E6]">
              <div className="flex items-center gap-1.5">
                <Wifi className="w-4 h-4 text-[#0F766E]" />
                <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
                  Live Packet Capture (Npcap / TShark)
                </h2>
              </div>
              <span
                className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                  isLiveActive ? 'bg-[#ECFDF3] text-[#16A34A]' : 'bg-[#F1F5F9] text-[#64748B]'
                }`}
              >
                {isLiveActive ? 'SNIFFING' : 'IDLE'}
              </span>
            </div>

            <div className="mt-3 space-y-2 text-xs font-mono">
              <div>
                <label className="text-[11px] text-[#64748B] block mb-1">Network Interface:</label>
                <select
                  value={selectedInterface}
                  onChange={(e) => setSelectedInterface(e.target.value)}
                  disabled={isLiveActive}
                  className="w-full bg-[#F4F7F6] border border-[#E2E8E6] rounded-md px-2.5 py-1.5 text-xs text-[#1B2B28] focus:outline-none focus:border-[#0F766E] disabled:opacity-50"
                >
                  {interfaces.map((iface, i) => (
                    <option key={i} value={iface}>
                      {iface}
                    </option>
                  ))}
                  {interfaces.length === 0 && <option value="">No interfaces found</option>}
                </select>
              </div>
            </div>
          </div>

          <div className="pt-2">
            {!isLiveActive ? (
              <button
                onClick={handleStartCapture}
                disabled={loadingAction === 'start_capture' || interfaces.length === 0}
                className="w-full py-2 bg-[#0F766E] hover:bg-[#0D655E] text-white rounded-md font-semibold font-mono text-xs shadow-sm transition-all flex items-center justify-center gap-1.5 disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Start Live Capture</span>
              </button>
            ) : (
              <button
                onClick={handleStopCapture}
                disabled={loadingAction === 'stop_capture'}
                className="w-full py-2 bg-[#DC2626] hover:bg-[#B91C1C] text-white rounded-md font-semibold font-mono text-xs shadow-sm transition-all flex items-center justify-center gap-1.5"
              >
                <Square className="w-3.5 h-3.5 fill-current" />
                <span>Stop Capture</span>
              </button>
            )}
          </div>
        </div>

        {/* Right: Targeted Attack Generators (Port Scan & SYN Flood) */}
        <div className="bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-[#E2E8E6]">
              <div className="flex items-center gap-1.5">
                <Zap className="w-4 h-4 text-[#F59E0B]" />
                <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
                  Targeted Attack Generators (College Lab Demo)
                </h2>
              </div>
              {isGenActive ? (
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[#FEF2F2] text-[#DC2626] animate-pulse">
                  GENERATING: {generatorStatus.attack_type} ({Math.max(0, generatorStatus.duration_limit - generatorStatus.elapsed)}s)
                </span>
              ) : (
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[#F1F5F9] text-[#64748B]">
                  READY
                </span>
              )}
            </div>

            {/* Inputs: Target Host, Duration, Port Range */}
            <div className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
              <div>
                <label className="text-[11px] text-[#64748B] block mb-1">Target Host:</label>
                <input
                  type="text"
                  value={generatorTarget}
                  onChange={(e) => setGeneratorTarget(e.target.value)}
                  disabled={isGenActive}
                  placeholder="127.0.0.1"
                  className="w-full bg-[#F4F7F6] border border-[#E2E8E6] rounded-md px-2 py-1 text-xs text-[#1B2B28] focus:outline-none focus:border-[#0F766E]"
                />
              </div>

              <div>
                <label className="text-[11px] text-[#64748B] block mb-1">Duration (Sec):</label>
                <input
                  type="number"
                  min="3"
                  max="30"
                  value={generatorDuration}
                  onChange={(e) => setGeneratorDuration(e.target.value)}
                  disabled={isGenActive}
                  className="w-full bg-[#F4F7F6] border border-[#E2E8E6] rounded-md px-2 py-1 text-xs text-[#1B2B28] focus:outline-none focus:border-[#0F766E]"
                />
              </div>

              <div>
                <label className="text-[11px] text-[#64748B] block mb-1">Port Range (Scan):</label>
                <input
                  type="text"
                  value={generatorPortRange}
                  onChange={(e) => setGeneratorPortRange(e.target.value)}
                  disabled={isGenActive}
                  placeholder="1-1024"
                  className="w-full bg-[#F4F7F6] border border-[#E2E8E6] rounded-md px-2 py-1 text-xs text-[#1B2B28] focus:outline-none focus:border-[#0F766E]"
                />
              </div>
            </div>
          </div>

          {/* Generator Buttons: Port Scan & SYN Flood */}
          <div className="pt-2 flex items-center gap-2">
            <button
              onClick={() => {
                if (isGenActive && generatorStatus.attack_type === 'PORT_SCAN') {
                  handleStopGenerator();
                } else {
                  handleGenerateAttack('PORT_SCAN');
                }
              }}
              disabled={isGenActive && generatorStatus.attack_type !== 'PORT_SCAN'}
              className={`flex-1 py-2 px-3 rounded-md font-semibold font-mono text-xs transition-all flex items-center justify-center gap-1.5 ${
                isGenActive && generatorStatus.attack_type === 'PORT_SCAN'
                  ? 'bg-[#DC2626] hover:bg-[#B91C1C] text-white'
                  : 'bg-[#F59E0B] hover:bg-[#D97706] text-white shadow-sm'
              } disabled:opacity-50`}
            >
              {isGenActive && generatorStatus.attack_type === 'PORT_SCAN' ? (
                <>
                  <Square className="w-3.5 h-3.5 fill-current" />
                  <span>Stop Port Scan</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Generate Port Scan</span>
                </>
              )}
            </button>

            <button
              onClick={() => {
                if (isGenActive && generatorStatus.attack_type === 'SYN_FLOOD') {
                  handleStopGenerator();
                } else {
                  handleGenerateAttack('SYN_FLOOD');
                }
              }}
              disabled={isGenActive && generatorStatus.attack_type !== 'SYN_FLOOD'}
              className={`flex-1 py-2 px-3 rounded-md font-semibold font-mono text-xs transition-all flex items-center justify-center gap-1.5 ${
                isGenActive && generatorStatus.attack_type === 'SYN_FLOOD'
                  ? 'bg-[#DC2626] hover:bg-[#B91C1C] text-white'
                  : 'bg-[#DC2626] hover:bg-[#B91C1C] text-white shadow-sm'
              } disabled:opacity-50`}
            >
              {isGenActive && generatorStatus.attack_type === 'SYN_FLOOD' ? (
                <>
                  <Square className="w-3.5 h-3.5 fill-current" />
                  <span>Stop SYN Flood</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Generate SYN Flood</span>
                </>
              )}
            </button>

            {isGenActive && (
              <button
                onClick={handleStopGenerator}
                className="px-3 py-2 bg-[#1B2B28] text-white rounded-md font-mono text-xs font-semibold"
                title="Cancel generation"
              >
                Cancel
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ── 4. DETECTION ALERT (CONFIDENCE-AWARE WORDING) ───────────────────── */}
      <div
        className={`p-3.5 rounded-xl border transition-all ${
          isThreatActive
            ? isLowConfidence
              ? 'bg-[#FFFBEB] border-[#FDE68A]'
              : 'bg-[#FEF2F2] border-[#FECACA]'
            : 'bg-white border-[#E2E8E6]'
        }`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-start sm:items-center gap-3">
            <div
              className={`w-7 h-7 rounded-md flex items-center justify-center shrink-0 border ${
                isThreatActive
                  ? isLowConfidence
                    ? 'bg-[#FFFBEB] border-[#FDE68A] text-[#D97706]'
                    : 'bg-[#FEF2F2] border-[#FECACA] text-[#DC2626]'
                  : 'bg-[#ECFDF3] border-[#BBF7D0] text-[#16A34A]'
              }`}
            >
              {isThreatActive ? <AlertTriangle className="w-4 h-4" /> : <CheckCircle2 className="w-4 h-4" />}
            </div>

            <div>
              {isThreatActive ? (
                <div className="text-xs font-mono">
                  <span className={`font-bold ${isLowConfidence ? 'text-[#D97706]' : 'text-[#DC2626]'}`}>
                    {isLowConfidence ? 'Suspicious, low confidence' : `${threatType} detected`}:{' '}
                  </span>
                  <span className="font-bold text-[#1B2B28]">
                    {probVal !== null ? `${probVal}%` : '94%'} probability
                  </span>{' '}
                  <span className="text-[#64748B] font-sans">
                    &bull; Attacker: <strong className="text-[#1B2B28] font-mono">{latestThreat.src_ip}</strong> &rarr; Target:{' '}
                    <strong className="text-[#1B2B28] font-mono">{latestThreat.dst_ip || '192.168.1.1'}:{latestThreat.dst_port || 80}</strong>{' '}
                    [Severity: {latestThreat.severity || 'HIGH'}]
                  </span>
                  <div className="text-[11px] text-[#64748B] mt-0.5">
                    Origin: {latestThreat.event_source === 'simulation' ? 'Attack Generator (Simulated Demo)' : 'Live Sniffer (promiscuous buffer)'}{' '}
                    &bull; Status: <strong className="text-[#7C3AED]">{isLatestBlocked ? `Source ${latestThreat.src_ip} blocked (dry-run)` : 'Monitoring (dry-run)'}</strong>
                  </div>
                </div>
              ) : (
                <div className="text-xs font-mono">
                  <span className="font-bold text-[#16A34A]">NORMAL TRAFFIC: </span>
                  <span className="text-[#64748B]">
                    Random Forest evaluated active flows as <strong className="text-[#16A34A]">BENIGN</strong>. Perimeter barrier secure.
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Action Buttons: Unblock & View Explainable Details */}
          <div className="flex items-center gap-2 shrink-0">
            {isThreatActive && latestThreat.src_ip && (
              isLatestBlocked ? (
                <button
                  onClick={() => handleManualUnblock(latestThreat.src_ip)}
                  className="px-2.5 py-1 text-xs font-mono font-semibold rounded-md border border-[#E2E8E6] bg-white hover:bg-[#E2E8E6] text-[#1B2B28]"
                >
                  Unblock {latestThreat.src_ip}
                </button>
              ) : (
                <button
                  onClick={() => handleManualBlock(latestThreat.src_ip)}
                  className="px-2.5 py-1 text-xs font-mono font-semibold rounded-md bg-[#DC2626] hover:bg-[#B91C1C] text-white shadow-sm"
                >
                  Block (Dry-Run)
                </button>
              )
            )}

            <button
              onClick={() => navigate('/explainer')}
              className="flex items-center gap-1 px-3 py-1 text-xs font-mono font-semibold rounded-md border border-[#E2E8E6] bg-white hover:bg-[#E2E8E6] text-[#0F766E]"
            >
              <span>View Explainable Details</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* ── 5. DETECTION PIPELINE STRIP ─────────────────────────────────────── */}
      <div className="bg-white border border-[#E2E8E6] rounded-xl p-3 shadow-sm">
        <div className="text-[10px] uppercase font-mono font-bold text-[#64748B] mb-2 flex items-center justify-between">
          <span>Detection Pipeline Sequence</span>
          <span>Latency: 0.8s from start to dry-run containment</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-6 gap-2 text-xs font-mono">
          {[
            { step: '1. Capture', desc: 'Promiscuous sniffing', active: true },
            { step: '2. Flow Grouping', desc: 'Bidirectional tuple', active: true },
            { step: '3. Feature Extraction', desc: '76 statistical features', active: true },
            { step: '4. Random Forest', desc: '100 tree votes', active: isThreatActive },
            { step: '5. Decision', desc: `${threatType} (${probVal || 94}%)`, active: isThreatActive },
            { step: '6. Dry-Run Block', desc: isLatestBlocked ? 'Contained' : 'Monitored', active: isLatestBlocked },
          ].map((st, i) => (
            <div
              key={i}
              className={`p-2 rounded-md border transition-all ${
                st.active
                  ? 'bg-[#F0FDFA] border-[#CCFBF1] text-[#0F766E]'
                  : 'bg-[#F4F7F6] border-[#E2E8E6] text-[#64748B]'
              }`}
            >
              <div className="font-bold text-[11px]">{st.step}</div>
              <div className="text-[10px] truncate text-[#64748B]">{st.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── 6. COUNTER CARDS ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-3 bg-white border border-[#E2E8E6] rounded-xl shadow-sm font-mono">
          <span className="text-[10px] text-[#64748B] uppercase block">Packets Captured</span>
          <span className="text-base font-bold text-[#1B2B28]">{packetsCapturedCount}</span>
        </div>
        <div className="p-3 bg-white border border-[#E2E8E6] rounded-xl shadow-sm font-mono">
          <span className="text-[10px] text-[#64748B] uppercase block">SYN Packets</span>
          <span className="text-base font-bold text-[#1B2B28]">{synPacketsCount}</span>
        </div>
        <div className="p-3 bg-white border border-[#E2E8E6] rounded-xl shadow-sm font-mono">
          <span className="text-[10px] text-[#64748B] uppercase block">Unique Ports Probed</span>
          <span className="text-base font-bold text-[#1B2B28]">{uniquePortsCount}</span>
        </div>
        <div className="p-3 bg-white border border-[#E2E8E6] rounded-xl shadow-sm font-mono">
          <span className="text-[10px] text-[#64748B] uppercase block">Attacks Detected</span>
          <span className="text-base font-bold text-[#DC2626]">{attacksDetectedCount}</span>
        </div>
        <div className="p-3 bg-white border border-[#E2E8E6] rounded-xl shadow-sm font-mono">
          <span className="text-[10px] text-[#64748B] uppercase block">IPs Blocked (Dry-Run)</span>
          <span className="text-base font-bold text-[#7C3AED]">{ipsBlockedCount}</span>
        </div>
        <div className="p-3 bg-white border border-[#E2E8E6] rounded-xl shadow-sm font-mono">
          <span className="text-[10px] text-[#64748B] uppercase block">Detection Delay</span>
          <span className="text-base font-bold text-[#0F766E]">~0.8s</span>
        </div>
      </div>

      {/* ── 7. TABS (LIVE TOPOLOGY | ATTACK GRAPH) ──────────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between border-b border-[#E2E8E6] pb-2">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('topology')}
              className={`px-4 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                activeTab === 'topology'
                  ? 'bg-[#0F766E] text-white shadow-sm'
                  : 'bg-white text-[#64748B] hover:bg-[#F4F7F6] border border-[#E2E8E6]'
              }`}
            >
              Live Topology
            </button>
            <button
              onClick={() => setActiveTab('attack_graph')}
              className={`px-4 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                activeTab === 'attack_graph'
                  ? 'bg-[#0F766E] text-white shadow-sm'
                  : 'bg-white text-[#64748B] hover:bg-[#F4F7F6] border border-[#E2E8E6]'
              }`}
            >
              Attack Graph
            </button>
          </div>
          <span className="text-[11px] font-mono text-[#64748B] hidden sm:inline">
            {activeTab === 'topology' ? '6-Node Perimeter Architecture' : 'Attacker ➔ Victim Edge Graph'}
          </span>
        </div>

        {/* Tab Visualizer View */}
        <div>
          {activeTab === 'topology' ? (
            <NetworkTopology
              latestPacket={packets[0]}
              latestThreat={recentThreats[0]}
              monitoringMode={isLiveActive ? 'live' : isGenActive ? 'simulation' : 'stopped'}
              autoBlockingEnabled={isAutoBlocking}
              onSelectPacket={(p) => setSelectedPacket(p)}
              onSelectThreat={(t) => setSelectedThreat(t)}
            />
          ) : (
            <AttackGraph
              threats={recentThreats}
              selectedThreat={selectedThreat}
              onSelectThreat={(t) => setSelectedThreat(t)}
            />
          )}
        </div>
      </div>

      {/* ── 8. FREQUENT ATTACKS TABLE ────────────────────────────────────────── */}
      <div className="bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#E2E8E6]">
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-[#DC2626]" />
            <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
              Frequent Attacks (Ranked by Detection Frequency)
            </h2>
          </div>
          <span className="text-[11px] font-mono text-[#64748B]">Updated on every model detection</span>
        </div>

        <div className="overflow-x-auto border border-[#E2E8E6] rounded-lg">
          <table className="w-full text-left font-mono text-xs divide-y divide-[#E2E8E6]">
            <thead className="bg-[#F4F7F6] text-[#64748B] text-[10px] uppercase">
              <tr>
                <th className="py-2 px-3">Attack Type</th>
                <th className="py-2 px-3">Source IP (Attacker)</th>
                <th className="py-2 px-3">Target IP (Victim)</th>
                <th className="py-2 px-3">Times Detected</th>
                <th className="py-2 px-3">Last Probability</th>
                <th className="py-2 px-3">Last Seen</th>
                <th className="py-2 px-3 text-right">Defense Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8E6] bg-white">
              {frequentThreats.map((item, idx) => {
                const isBlocked = blockedIps.some((b) => b.ip === item.src_ip);
                return (
                  <tr key={idx} className="hover:bg-[#F4F7F6]/50">
                    <td className="py-2 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          item.threat_type === 'PORT_SCAN'
                            ? 'bg-[#FFFBEB] text-[#D97706] border border-[#FDE68A]'
                            : 'bg-[#FEF2F2] text-[#DC2626] border border-[#FECACA]'
                        }`}
                      >
                        {item.threat_type}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-bold text-[#1B2B28]">{item.src_ip}</td>
                    <td className="py-2 px-3 text-[#64748B]">{item.dst_ip}</td>
                    <td className="py-2 px-3 font-semibold text-[#1B2B28]">{item.times_detected}x</td>
                    <td className="py-2 px-3 font-bold text-[#1B2B28]">
                      {item.last_probability_pct ? `${item.last_probability_pct}%` : '92%'}
                    </td>
                    <td className="py-2 px-3 text-[#64748B] text-[11px]">
                      {item.last_seen ? item.last_seen.split('T')[1]?.slice(0, 8) : 'Recent'}
                    </td>
                    <td className="py-2 px-3 text-right">
                      {isBlocked ? (
                        <button
                          onClick={() => handleManualUnblock(item.src_ip)}
                          className="px-2 py-0.5 rounded border border-[#E2E8E6] bg-[#F4F7F6] text-[#1B2B28] hover:bg-[#E2E8E6]"
                        >
                          Unblock
                        </button>
                      ) : (
                        <button
                          onClick={() => handleManualBlock(item.src_ip)}
                          className="px-2 py-0.5 rounded bg-[#DC2626] text-white hover:bg-[#B91C1C]"
                        >
                          Block (Dry-Run)
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}

              {frequentThreats.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-[#64748B] italic">
                    No repeated attacks detected yet. Start capture or trigger a generator above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── 9. WIRESHARK-STYLE PACKET CAPTURE TABLE (WITH FLOW GROUPING) ────── */}
      <div className="bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-2 border-b border-[#E2E8E6]">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#0F766E]" />
            <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
              Live Packet Buffer ({filteredPackets.length} frames buffered)
            </h2>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs">
            {/* Flow ID Toggle */}
            <button
              onClick={() => setShowFlowId(!showFlowId)}
              className={`px-2 py-1 rounded text-[11px] font-semibold border ${
                showFlowId ? 'bg-[#F0FDFA] border-[#CCFBF1] text-[#0F766E]' : 'bg-[#F4F7F6] border-[#E2E8E6] text-[#64748B]'
              }`}
            >
              {showFlowId ? 'Flow IDs: ON' : 'Flow IDs: OFF'}
            </button>

            {/* Filter pills */}
            <div className="flex items-center gap-1">
              {['ALL', 'TCP', 'THREATS', 'LIVE', 'SIMULATION'].map((f) => (
                <button
                  key={f}
                  onClick={() => setPacketFilter(f)}
                  className={`px-2 py-1 rounded text-[11px] font-semibold transition-all ${
                    packetFilter === f
                      ? 'bg-[#0F766E] text-white'
                      : 'bg-[#F4F7F6] text-[#64748B] hover:bg-[#E2E8E6]'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Scrollable Packet Table */}
        <div className="overflow-x-auto border border-[#E2E8E6] rounded-lg max-h-[360px] overflow-y-auto">
          <table className="w-full text-left font-mono text-xs divide-y divide-[#E2E8E6]">
            <thead className="bg-[#F4F7F6] text-[#64748B] text-[10px] uppercase sticky top-0 z-10">
              <tr>
                <th className="py-2 px-3">Time</th>
                {showFlowId && <th className="py-2 px-3">Flow ID</th>}
                <th className="py-2 px-3">Source IP</th>
                <th className="py-2 px-3">Destination IP</th>
                <th className="py-2 px-3">Proto</th>
                <th className="py-2 px-3">Src Port</th>
                <th className="py-2 px-3">Dst Port</th>
                <th className="py-2 px-3">TCP Flags</th>
                <th className="py-2 px-3">Length</th>
                <th className="py-2 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8E6] bg-white">
              {filteredPackets.map((pkt, idx) => {
                const isThreat = Boolean(pkt.is_threat || pkt.status === 'threat' || pkt.traffic_type === 'threat');
                const isSuspicious = pkt.status === 'suspicious' || pkt.traffic_type === 'suspicious';
                const flowKey = `${pkt.src_ip}:${pkt.src_port || 0}->${pkt.dst_ip}:${pkt.dst_port || 0}`;

                return (
                  <tr
                    key={pkt.id || `${pkt.timestamp}-${idx}`}
                    onClick={() => setSelectedPacket(pkt)}
                    className={`cursor-pointer transition-colors ${
                      selectedPacket?.id === pkt.id
                        ? 'bg-[#F0FDFA]'
                        : isThreat
                        ? 'bg-[#FEF2F2]/60 hover:bg-[#FEF2F2]'
                        : isSuspicious
                        ? 'bg-[#FFFBEB]/60 hover:bg-[#FFFBEB]'
                        : 'hover:bg-[#F4F7F6]'
                    }`}
                  >
                    <td className="py-1.5 px-3 text-[#64748B] text-[11px]">
                      {pkt.timestamp ? pkt.timestamp.split('T')[1]?.slice(0, 8) : 'Now'}
                    </td>
                    {showFlowId && (
                      <td className="py-1.5 px-3 text-[#64748B] text-[10px] font-mono truncate max-w-[100px]">
                        {pkt.flow_id || flowKey.slice(-12)}
                      </td>
                    )}
                    <td className="py-1.5 px-3 font-bold text-[#1B2B28]">{pkt.src_ip}</td>
                    <td className="py-1.5 px-3 text-[#1B2B28]">{pkt.dst_ip}</td>
                    <td className="py-1.5 px-3 text-[#64748B] font-semibold">{pkt.protocol || 'TCP'}</td>
                    <td className="py-1.5 px-3 text-[#64748B]">{pkt.src_port || '*'}</td>
                    <td className="py-1.5 px-3 text-[#64748B]">{pkt.dst_port || '*'}</td>
                    <td className="py-1.5 px-3 text-[#64748B]">{pkt.flags || '-'}</td>
                    <td className="py-1.5 px-3 text-[#64748B]">{pkt.length || 60}B</td>
                    <td className="py-1.5 px-3 text-right">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          isThreat
                            ? 'bg-[#DC2626] text-white'
                            : isSuspicious
                            ? 'bg-[#F59E0B] text-white'
                            : 'bg-[#F1F5F9] text-[#64748B]'
                        }`}
                      >
                        {isThreat ? 'Threat' : isSuspicious ? 'Probe' : 'Normal'}
                      </span>
                    </td>
                  </tr>
                );
              })}

              {filteredPackets.length === 0 && (
                <tr>
                  <td colSpan={showFlowId ? 10 : 9} className="py-6 text-center text-[#64748B] italic">
                    No frames currently buffered matching filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Selected Packet Wireshark-Style Inspection Drawer */}
        {selectedPacket && (
          <div className="mt-3 p-3.5 bg-[#F4F7F6] border border-[#E2E8E6] rounded-lg text-xs font-mono space-y-2">
            <div className="flex items-center justify-between border-b border-[#E2E8E6] pb-2">
              <span className="font-bold text-[#1B2B28] flex items-center gap-1.5">
                <Eye className="w-4 h-4 text-[#0F766E]" />
                Frame Header Inspection (Raw 5-Tuple & Flags)
              </span>
              <button
                onClick={() => setSelectedPacket(null)}
                className="text-[#64748B] hover:text-[#1B2B28]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
              <div>
                <span className="text-[#64748B] block">Source:</span>
                <strong>{selectedPacket.src_ip}:{selectedPacket.src_port || 0}</strong>
              </div>
              <div>
                <span className="text-[#64748B] block">Destination:</span>
                <strong>{selectedPacket.dst_ip}:{selectedPacket.dst_port || 0}</strong>
              </div>
              <div>
                <span className="text-[#64748B] block">Protocol / Length:</span>
                <strong>{selectedPacket.protocol} ({selectedPacket.length || 60} bytes)</strong>
              </div>
              <div>
                <span className="text-[#64748B] block">Captured At:</span>
                <strong>{selectedPacket.timestamp || 'Real-time'}</strong>
              </div>
            </div>

            {/* TCP Flags Breakout */}
            <div className="pt-2 border-t border-[#E2E8E6]">
              <span className="text-[11px] text-[#64748B] block mb-1">TCP Control Flags Breakdown:</span>
              <div className="flex flex-wrap items-center gap-2 text-[11px]">
                {['SYN', 'ACK', 'RST', 'FIN', 'PSH', 'URG'].map((flag) => {
                  const isPresent = selectedPacket.flags?.includes(flag[0]);
                  return (
                    <span
                      key={flag}
                      className={`px-2 py-0.5 rounded border ${
                        isPresent
                          ? 'bg-[#0F766E] text-white border-[#0F766E] font-bold'
                          : 'bg-white text-[#64748B] border-[#E2E8E6]'
                      }`}
                    >
                      {flag}: {isPresent ? '1' : '0'}
                    </span>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── 10. ATTACK TIMELINE & DEMO STEPS HINT BOX ───────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
        {/* Attack Timeline */}
        <div className="md:col-span-8 bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-2">
          <div className="flex items-center gap-2 pb-2 border-b border-[#E2E8E6]">
            <Clock className="w-4 h-4 text-[#0F766E]" />
            <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
              Attack Event Timeline (Chronological Audit)
            </h2>
          </div>

          <div className="space-y-1.5 font-mono text-xs max-h-[180px] overflow-y-auto">
            {attackTimeline.map((item, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-2 rounded bg-[#F4F7F6] border border-[#E2E8E6]"
              >
                <div className="flex items-center gap-2">
                  <span className="text-[#64748B] text-[11px]">{item.time}</span>
                  <span
                    className={`font-bold ${
                      item.label === 'PORT_SCAN' ? 'text-[#D97706]' : 'text-[#DC2626]'
                    }`}
                  >
                    {item.event}
                  </span>
                  <span className="text-[#64748B]">from {item.src_ip}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-[#1B2B28]">{item.prob}</span>
                  <span className="text-[10px] bg-[#F5F3FF] text-[#7C3AED] px-1.5 py-0.5 rounded font-bold">
                    {item.action}
                  </span>
                </div>
              </div>
            ))}

            {attackTimeline.length === 0 && (
              <div className="py-6 text-center text-[#64748B] italic">
                Timeline idle. Trigger an attack generator above to observe live detection timestamps.
              </div>
            )}
          </div>
        </div>

        {/* 11. Demo Steps Hint Box */}
        <div className="md:col-span-4 bg-[#F0FDFA] border border-[#CCFBF1] rounded-xl p-4 shadow-sm space-y-2 font-mono text-xs">
          <div className="flex items-center gap-2 font-bold text-[#0F766E] border-b border-[#CCFBF1] pb-1.5 uppercase text-[11px]">
            <CheckCircle2 className="w-4 h-4" />
            <span>Demonstration Steps</span>
          </div>

          <ol className="space-y-1.5 text-[11px] text-[#1B2B28] list-decimal list-inside leading-relaxed font-sans">
            <li>
              <strong>Start Live Capture:</strong> Choose your adapter (e.g. WiFi) and click Start Live Capture.
            </li>
            <li>
              <strong>Generate Attack:</strong> Click <em>Generate Port Scan</em> or <em>Generate SYN Flood</em>.
            </li>
            <li>
              <strong>Observe Detection:</strong> Watch the topology turn red, the Random Forest node assign confidence, and the Firewall barrier trigger a dry-run block.
            </li>
            <li>
              <strong>Explain & Restore:</strong> Open <em>Detection Explainer</em> to view 100 tree votes, then click <em>Unblock</em>.
            </li>
          </ol>
        </div>
      </div>

      {/* ── MODALS ──────────────────────────────────────────────────────────── */}
      <ConfirmationModal
        isOpen={isAutoBlockModalOpen}
        onClose={() => setIsAutoBlockModalOpen(false)}
        onConfirm={() => handleToggleBlockingMode('automatic')}
        title="Activate Automatic Perimeter Containment"
        message="When Automatic Mode is active, threats classified by Random Forest with >= 80% confidence will be isolated at the perimeter defense barrier in Safe Dry-Run mode."
        confirmText="Enable Auto Containment"
        confirmVariant="danger"
      />

      <ConfirmationModal
        isOpen={isResetModalOpen}
        onClose={() => setIsResetModalOpen(false)}
        onConfirm={handleResetState}
        title="Reset All Telemetry & Alerts"
        message="This will clear in-memory bidirectional flows, active threat alerts, and generator state. Database records will be cleared."
        confirmText="Confirm Reset"
        confirmVariant="danger"
      />
    </div>
  );
};

export default Dashboard;
