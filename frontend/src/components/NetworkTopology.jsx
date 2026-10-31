import React, { useState, useEffect, useRef } from 'react';
import {
  Shield,
  Server,
  Laptop,
  Flame,
  Radio,
  Cpu,
  Lock,
  Unlock,
  AlertTriangle,
  Eye,
  CheckCircle2
} from 'lucide-react';

/**
 * 6 Core Architecture Nodes with balanced coordinates in a 1200x460 viewBox.
 * Column 1: External Clients (top-left) & Simulated Attacker (bottom-left)
 * Column 2: Network Sensor / Packet Capture (x=360, y=230)
 * Column 3: Random Forest Detection (x=600, y=230)
 * Column 4: Firewall / Defense Barrier (x=840, y=230) [PERIMETER BARRIER line passes here]
 * Column 5: Protected Server (x=1080, y=230)
 * Equal spacing: exactly 240px between every column. Node sizes: 164x82px.
 */
const NODES = {
  external: {
    id: 'external',
    label: 'External Clients',
    sublabel: 'Legitimate Web/App Users',
    ip: '198.51.100.x',
    x: 120,
    y: 130,
    icon: Laptop,
    color: '#0F766E', // primary accent
    bg: '#F4F7F6',
    border: '#E2E8E6',
    role: 'Origin of legitimate enterprise traffic (HTTP, TLS, DNS queries). Evaluated as BENIGN by Random Forest.',
  },
  attacker: {
    id: 'attacker',
    label: 'Simulated Attacker',
    sublabel: 'Adversary Threat Node',
    ip: '10.0.0.99 / 198.51.100.77',
    x: 120,
    y: 330,
    icon: Flame,
    color: '#DC2626', // red
    bg: '#FEF2F2',
    border: '#FECACA',
    role: 'Threat source conducting automated SYN floods (exhaustion) or multi-port sweeps (reconnaissance).',
  },
  sensor: {
    id: 'sensor',
    label: 'Network Sensor / Packet Capture',
    sublabel: 'Passive Npcap / Sniffer',
    ip: 'eth0 / Promiscuous Buffer',
    x: 360,
    y: 230,
    icon: Radio,
    color: '#0F766E', // teal
    bg: '#F0FDFA',
    border: '#CCFBF1',
    role: 'Sniffs raw frame headers in real-time, extracts 5-tuples, and passes them to the bidirectional flow aggregator.',
  },
  rf_detector: {
    id: 'rf_detector',
    label: 'Random Forest Detection',
    sublabel: '100 Trees, 76 Flow Features',
    ip: 'Sole Attack Classifier',
    x: 600,
    y: 230,
    icon: Cpu,
    color: '#6D28D9', // purple RF highlight
    bg: '#F5F3FF',
    border: '#DDD6FE',
    role: 'Extracts 76 statistical features (durations, IATs, flag ratios, window sizes). Strictly scores flows as BENIGN, SYN_FLOOD, or PORT_SCAN.',
  },
  barrier: {
    id: 'barrier',
    label: 'Firewall / Defense Barrier',
    sublabel: 'Perimeter Containment',
    ip: 'Dry-Run Containment Barrier',
    x: 840,
    y: 230,
    icon: Shield,
    color: '#D97706', // amber/orange
    bg: '#FFFBEB',
    border: '#FDE68A',
    role: 'Enforces perimeter defense policies. In manual mode it provides dry-run containment; in auto mode it blocks high-confidence threats.',
  },
  server: {
    id: 'server',
    label: 'Protected Server',
    sublabel: 'Enterprise Web & Core DB',
    ip: '192.168.1.1:80/443',
    x: 1080,
    y: 230,
    icon: Server,
    color: '#16A34A', // green
    bg: '#ECFDF3',
    border: '#BBF7D0',
    role: 'Target protected infrastructure hosting corporate services. Shielded from resource exhaustion by upstream Random Forest detection.',
  },
};

// Exact cubic bezier connection paths between the 6 nodes
const PATHS = [
  { id: 'ext-to-sensor', from: NODES.external, to: NODES.sensor, cp1: { x: 220, y: 130 }, cp2: { x: 260, y: 230 } },
  { id: 'att-to-sensor', from: NODES.attacker, to: NODES.sensor, cp1: { x: 220, y: 330 }, cp2: { x: 260, y: 230 } },
  { id: 'sensor-to-rf', from: NODES.sensor, to: NODES.rf_detector, cp1: { x: 480, y: 230 }, cp2: { x: 480, y: 230 } },
  { id: 'rf-to-barrier', from: NODES.rf_detector, to: NODES.barrier, cp1: { x: 720, y: 230 }, cp2: { x: 720, y: 230 } },
  { id: 'barrier-to-server', from: NODES.barrier, to: NODES.server, cp1: { x: 960, y: 230 }, cp2: { x: 960, y: 230 } },
];

function getCubicBezierPoint(p0, p1, p2, p3, t) {
  const u = 1 - t;
  const tt = t * t;
  const uu = u * u;
  const uuu = uu * u;
  const ttt = tt * t;

  return {
    x: uuu * p0.x + 3 * uu * t * p1.x + 3 * u * tt * p2.x + ttt * p3.x,
    y: uuu * p0.y + 3 * uu * t * p1.y + 3 * u * tt * p2.y + ttt * p3.y,
  };
}

const NetworkTopology = ({
  latestPacket,
  latestThreat,
  monitoringMode = 'stopped', // 'live' | 'simulation' | 'starting' | 'error' | 'stopped'
  autoBlockingEnabled = false,
  packetsPerSec = 0,
  onSelectPacket,
  onSelectThreat,
}) => {
  const [particles, setParticles] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [inspectedPacket, setInspectedPacket] = useState(null);
  const [barrierFlash, setBarrierFlash] = useState(false);
  const particleIdCounter = useRef(0);
  const animFrameRef = useRef(null);

  const isRecentAttack = Boolean(
    latestThreat &&
    latestThreat.threat_type &&
    latestThreat.threat_type !== 'BENIGN'
  );

  const probVal =
    latestThreat?.predict_proba_pct ??
    (latestThreat?.predict_proba ? Math.round(latestThreat.predict_proba * 100) : null) ??
    (latestThreat?.ml_prediction?.confidence ? Math.round(latestThreat.ml_prediction.confidence * 100) : 92);

  const isBarrierBlocked = Boolean(
    autoBlockingEnabled ||
    (latestThreat?.response_status && latestThreat.response_status.toLowerCase().includes('block'))
  );

  // Spawn new animated particle when a new packet arrives
  useEffect(() => {
    if (!latestPacket) return;

    const isThreat = Boolean(
      latestPacket.is_threat ||
      latestPacket.status === 'threat' ||
      latestPacket.traffic_type === 'threat' ||
      (latestThreat && latestPacket.src_ip === latestThreat.src_ip)
    );
    const isSuspicious = latestPacket.status === 'suspicious' || latestPacket.traffic_type === 'suspicious';
    const isBlocked = Boolean(latestPacket.blocked || latestPacket.status === 'blocked');

    // Determine particle route across the 6 nodes
    let route = [];
    if (isThreat || isSuspicious || isBlocked) {
      // Threat route: Attacker -> Sensor -> RF Detection -> Barrier
      route = [
        { from: NODES.attacker, to: NODES.sensor, cp1: { x: 220, y: 330 }, cp2: { x: 260, y: 230 } },
        { from: NODES.sensor, to: NODES.rf_detector, cp1: { x: 480, y: 230 }, cp2: { x: 480, y: 230 } },
        { from: NODES.rf_detector, to: NODES.barrier, cp1: { x: 720, y: 230 }, cp2: { x: 720, y: 230 } },
      ];
      // If not blocked, reaches server
      if (!isBlocked && !autoBlockingEnabled) {
        route.push({
          from: NODES.barrier,
          to: NODES.server,
          cp1: { x: 960, y: 230 },
          cp2: { x: 960, y: 230 },
        });
      }
    } else {
      // Normal route: External Clients -> Sensor -> RF Detection -> Barrier -> Server
      route = [
        { from: NODES.external, to: NODES.sensor, cp1: { x: 220, y: 130 }, cp2: { x: 260, y: 230 } },
        { from: NODES.sensor, to: NODES.rf_detector, cp1: { x: 480, y: 230 }, cp2: { x: 480, y: 230 } },
        { from: NODES.rf_detector, to: NODES.barrier, cp1: { x: 720, y: 230 }, cp2: { x: 720, y: 230 } },
        { from: NODES.barrier, to: NODES.server, cp1: { x: 960, y: 230 }, cp2: { x: 960, y: 230 } },
      ];
    }

    let color = '#64748B'; // Neutral grey for normal
    if (isBlocked) color = '#7C3AED'; // Purple for blocked dry-run
    else if (isThreat) color = '#DC2626'; // Red for attack
    else if (isSuspicious) color = '#F59E0B'; // Amber for suspicious

    particleIdCounter.current += 1;
    const newParticle = {
      id: particleIdCounter.current,
      route,
      segmentIndex: 0,
      segmentProgress: 0,
      speed: isThreat ? 0.05 : 0.035,
      color,
      isThreat,
      isBlocked,
      packet: latestPacket,
      currentPos: { x: route[0].from.x, y: route[0].from.y },
    };

    setParticles((prev) => [...prev.slice(-12), newParticle]);

    if (isBlocked || isThreat) {
      setBarrierFlash(true);
      setTimeout(() => setBarrierFlash(false), 350);
    }
  }, [latestPacket, autoBlockingEnabled, latestThreat]);

  // Smooth requestAnimationFrame particle update loop
  useEffect(() => {
    const updateParticles = () => {
      setParticles((prev) => {
        const next = [];
        for (const p of prev) {
          const seg = p.route[p.segmentIndex];
          if (!seg) continue;

          const nextProgress = p.segmentProgress + p.speed;
          if (nextProgress < 1.0) {
            const pos = getCubicBezierPoint(seg.from, seg.cp1, seg.cp2, seg.to, nextProgress);
            next.push({
              ...p,
              segmentProgress: nextProgress,
              currentPos: pos,
            });
          } else {
            const nextSegIdx = p.segmentIndex + 1;
            if (nextSegIdx < p.route.length) {
              const nextSeg = p.route[nextSegIdx];
              const pos = getCubicBezierPoint(nextSeg.from, nextSeg.cp1, nextSeg.cp2, nextSeg.to, 0);
              next.push({
                ...p,
                segmentIndex: nextSegIdx,
                segmentProgress: 0,
                currentPos: pos,
              });
            }
          }
        }
        return next;
      });

      animFrameRef.current = requestAnimationFrame(updateParticles);
    };

    animFrameRef.current = requestAnimationFrame(updateParticles);
    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, []);

  const handleParticleClick = (pkt) => {
    setInspectedPacket(pkt);
    if (onSelectPacket) onSelectPacket(pkt);
  };

  return (
    <div className="bg-white rounded-xl border border-[#E2E8E6] p-4 shadow-sm space-y-3">
      {/* Topology Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-[#E2E8E6]">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#0F766E] animate-pulse" />
            <h2 className="text-sm font-bold text-[#1B2B28] uppercase tracking-wider font-mono">
              Interactive Network Topology (Primary Visualizer)
            </h2>
          </div>
          <p className="text-xs text-[#64748B] mt-0.5">
            Single unified network view: packets transit through the sensor, Random Forest classifier, and perimeter barrier.
          </p>
        </div>

        {/* Status Chips */}
        <div className="flex items-center gap-2 font-mono text-xs">
          <div
            className={`px-2.5 py-1 rounded-md font-semibold flex items-center gap-1.5 border text-[11px] ${
              monitoringMode === 'live'
                ? 'bg-[#ECFDF3] text-[#16A34A] border-[#BBF7D0]'
                : monitoringMode === 'simulation'
                ? 'bg-[#F0FDFA] text-[#0F766E] border-[#CCFBF1]'
                : 'bg-[#F1F5F9] text-[#64748B] border-[#E2E8E6]'
            }`}
          >
            <span
              className={`w-2 h-2 rounded-full ${
                monitoringMode === 'live' ? 'bg-[#16A34A] animate-ping' : 'bg-[#64748B]'
              }`}
            />
            <span>{monitoringMode === 'live' ? 'LIVE' : monitoringMode === 'simulation' ? 'SIMULATION' : 'STOPPED'}</span>
          </div>

          <div
            className={`px-2.5 py-1 rounded-md font-semibold flex items-center gap-1.5 border text-[11px] ${
              autoBlockingEnabled
                ? 'bg-[#F5F3FF] text-[#7C3AED] border-[#DDD6FE]'
                : 'bg-[#FFFBEB] text-[#D97706] border-[#FDE68A]'
            }`}
          >
            {autoBlockingEnabled ? <Lock className="w-3 h-3 text-[#7C3AED]" /> : <Unlock className="w-3 h-3 text-[#D97706]" />}
            <span>{autoBlockingEnabled ? 'Auto-Block Active' : 'Safe Dry-Run'}</span>
          </div>
        </div>
      </div>

      {/* SVG Canvas with fixed 1200x460 viewBox */}
      <div className="w-full overflow-hidden bg-[#F4F7F6]/60 rounded-lg border border-[#E2E8E6] p-2">
        <svg
          viewBox="0 0 1200 460"
          className="w-full h-auto select-none"
          style={{ display: 'block', maxHeight: '460px' }}
        >
          {/* Paths connecting nodes */}
          {PATHS.map((path) => {
            const isAttackPath =
              isRecentAttack &&
              (path.id === 'att-to-sensor' || path.id === 'sensor-to-rf' || path.id === 'rf-to-barrier');
            return (
              <path
                key={path.id}
                d={`M ${path.from.x} ${path.from.y} C ${path.cp1.x} ${path.cp1.y}, ${path.cp2.x} ${path.cp2.y}, ${path.to.x} ${path.to.y}`}
                fill="none"
                stroke={isAttackPath ? '#DC2626' : '#CBD5E1'}
                strokeWidth={isAttackPath ? '3' : '2'}
                strokeDasharray={isAttackPath ? '6,4' : '4,4'}
                className="transition-all duration-300"
              />
            );
          })}

          {/* Vertical PERIMETER BARRIER line passing through Firewall node (x=840) */}
          <line
            x1="840"
            y1="35"
            x2="840"
            y2="425"
            stroke={barrierFlash ? '#DC2626' : '#D97706'}
            strokeWidth={barrierFlash ? '4' : '2'}
            strokeDasharray="6,4"
            className="transition-all duration-200"
          />
          <text
            x="840"
            y="25"
            textAnchor="middle"
            fill="#D97706"
            fontSize="10"
            fontWeight="bold"
            letterSpacing="1.2"
            fontFamily="monospace"
          >
            PERIMETER BARRIER
          </text>

          {/* Traveling Packet Dots */}
          {particles.map((p) => (
            <g
              key={p.id}
              className="cursor-pointer"
              onClick={() => handleParticleClick(p.packet)}
            >
              <circle
                cx={p.currentPos.x}
                cy={p.currentPos.y}
                r={p.isThreat ? 6 : 4}
                fill={p.color}
                opacity={0.9}
              />
            </g>
          ))}

          {/* The 6 Architecture Nodes */}
          {Object.values(NODES).map((node) => {
            const Icon = node.icon;
            const isSelected = selectedNode?.id === node.id;
            const isNodeAttacker = node.id === 'attacker';
            const isNodeThreatened = isRecentAttack && (isNodeAttacker || node.id === 'rf_detector');

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                className="cursor-pointer transition-transform duration-150 hover:scale-105"
                onClick={() => setSelectedNode(node)}
              >
                {/* Node Box (164x82) */}
                <rect
                  x="-82"
                  y="-41"
                  width="164"
                  height="82"
                  rx="10"
                  fill="#FFFFFF"
                  stroke={
                    isSelected
                      ? '#0F766E'
                      : isNodeThreatened
                      ? '#DC2626'
                      : node.border
                  }
                  strokeWidth={isSelected || isNodeThreatened ? '2.5' : '1.5'}
                />

                {/* Node Icon Circle */}
                <circle
                  cx="0"
                  cy="-15"
                  r="14"
                  fill={node.bg}
                  stroke={isNodeThreatened ? '#DC2626' : node.color}
                  strokeWidth="1.5"
                />

                {/* Lucide Icon */}
                <foreignObject x="-9" y="-24" width="18" height="18">
                  <div className="flex items-center justify-center w-full h-full">
                    <Icon size={14} color={isNodeThreatened ? '#DC2626' : node.color} />
                  </div>
                </foreignObject>

                {/* Node Title */}
                <text
                  x="0"
                  y="13"
                  textAnchor="middle"
                  fill="#1B2B28"
                  fontSize="11"
                  fontWeight="600"
                >
                  {node.label}
                </text>

                {/* Node Subtitle / Dynamic Real-Time Text */}
                <text
                  x="0"
                  y="26"
                  textAnchor="middle"
                  fill={
                    isRecentAttack && node.id === 'rf_detector'
                      ? '#DC2626'
                      : isRecentAttack && node.id === 'barrier' && isBarrierBlocked
                      ? '#7C3AED'
                      : '#64748B'
                  }
                  fontSize={isRecentAttack && (node.id === 'rf_detector' || node.id === 'barrier') ? '9.5' : '8.5'}
                  fontWeight={isRecentAttack && (node.id === 'rf_detector' || node.id === 'barrier') ? '700' : '400'}
                  fontFamily="monospace"
                >
                  {node.id === 'rf_detector' && isRecentAttack
                    ? `${latestThreat.threat_type} (${probVal}%)`
                    : node.id === 'barrier'
                    ? (isBarrierBlocked ? 'blocked (dry-run)' : 'unblocked (dry-run)')
                    : node.ip}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Legend */}
        <div className="flex flex-wrap items-center justify-center gap-6 pt-2 pb-1 border-t border-[#E2E8E6] text-xs text-[#64748B]">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#64748B]" />
            <span>Normal Traffic (Neutral dot &bull; Path to Server)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#F59E0B]" />
            <span>Suspicious Probes / Port Scan (Amber)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#DC2626]" />
            <span>Detected Attack / SYN Flood (Red &bull; Contained at Barrier)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded bg-[#D97706]" />
            <span>Perimeter Barrier (Safe Dry-Run)</span>
          </div>
        </div>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="p-3 bg-[#F4F7F6] rounded-lg border border-[#E2E8E6] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-start gap-2.5">
            <div
              className="p-1.5 rounded-md"
              style={{ backgroundColor: selectedNode.bg, border: `1px solid ${selectedNode.border}` }}
            >
              {React.createElement(selectedNode.icon, { size: 16, color: selectedNode.color })}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-[#1B2B28]">{selectedNode.label}</span>
                <span className="font-mono text-[#64748B] text-[11px]">({selectedNode.ip})</span>
              </div>
              <p className="text-[#64748B] text-[11px] mt-0.5 max-w-2xl">
                {selectedNode.role}
              </p>
            </div>
          </div>
          <button
            onClick={() => setSelectedNode(null)}
            className="text-xs text-[#64748B] hover:text-[#1B2B28] px-2.5 py-1 border border-[#E2E8E6] rounded bg-white font-mono self-end sm:self-auto"
          >
            Dismiss
          </button>
        </div>
      )}
    </div>
  );
};

export default NetworkTopology;
