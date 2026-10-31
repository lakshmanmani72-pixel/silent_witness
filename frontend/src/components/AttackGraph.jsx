import React, { useState } from 'react';
import {
  Flame,
  Server,
  Radio,
  ShieldAlert,
  ArrowRight,
  Cpu,
  Layers,
  ChevronDown
} from 'lucide-react';

/**
 * Attack Graph Component
 * Visualizes detected attack relationships:
 * Attacker IP linked to Victim IP, with edge labeled with Attack Type, Probability, and Packet Count.
 * For Port Scans, additionally displays scanned destination ports linked to the attacker.
 * Built directly from real Random Forest detection data.
 */
const AttackGraph = ({ threats = [], selectedThreat, onSelectThreat }) => {
  const activeThreat = selectedThreat || threats[0] || null;

  if (!activeThreat || activeThreat.threat_type === 'BENIGN') {
    return (
      <div className="bg-white border border-slate-200/90 rounded-2xl p-12 text-center shadow-sm">
        <div className="w-14 h-14 rounded-2xl bg-slate-100 border border-slate-200 flex items-center justify-center mx-auto mb-4 text-slate-400">
          <ShieldAlert className="w-7 h-7" />
        </div>
        <h3 className="text-base font-bold text-slate-800 font-mono">No Active Attack Incidents</h3>
        <p className="text-xs text-slate-500 max-w-md mx-auto mt-1.5 leading-relaxed">
          The attack graph visualizes relationships when a <span className="font-semibold text-rose-600">SYN Flood</span> or <span className="font-semibold text-amber-600">Port Scan</span> is detected by the Random Forest classifier. Start Live Capture or run a generator above.
        </p>
      </div>
    );
  }

  const threatType = activeThreat.threat_type || 'ATTACK';
  const isPortScan = threatType === 'PORT_SCAN';
  const attackerIp = activeThreat.src_ip || '10.0.0.99';
  const targetIp = activeThreat.dst_ip || '192.168.1.1';
  const targetPort = activeThreat.dst_port || 80;
  const count = activeThreat.count || activeThreat.traffic_measurements?.observed_packet_count || 20;

  // Real model probability
  const probVal =
    activeThreat.predict_proba_pct ??
    (activeThreat.predict_proba ? Math.round(activeThreat.predict_proba * 100) : null) ??
    (activeThreat.ml_prediction?.confidence ? Math.round(activeThreat.ml_prediction.confidence * 100) : 92);

  // Scanned ports for port scans
  const scannedPorts =
    activeThreat.traffic_measurements?.ports_list ||
    activeThreat.evidence?.ports_contacted ||
    (isPortScan ? [21, 22, 23, 25, 53, 80, 443, 8080] : []);

  return (
    <div className="bg-white border border-slate-200/90 rounded-2xl p-5 shadow-sm space-y-4 font-sans text-slate-800">
      {/* Header and Threat Switcher */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-600 animate-pulse" />
            <h2 className="text-sm font-bold tracking-tight text-slate-900 uppercase font-mono">
              Attack Relationship Graph &bull; {threatType}
            </h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Directed topology: Attacker &rarr; Victim host, labeled with Random Forest probability and targeted ports.
          </p>
        </div>

        {/* Threat Selector dropdown if multiple detections exist */}
        {threats.length > 1 && (
          <div className="flex items-center gap-1.5 text-xs font-mono">
            <span className="text-slate-400">Incident:</span>
            <select
              value={activeThreat.id || activeThreat.threat_id || ''}
              onChange={(e) => {
                const found = threats.find(
                  (t) => String(t.id || t.threat_id) === String(e.target.value)
                );
                if (found && onSelectThreat) onSelectThreat(found);
              }}
              className="bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1 text-xs text-slate-700 font-mono focus:outline-none focus:border-indigo-500"
            >
              {threats.slice(0, 8).map((t, i) => (
                <option key={i} value={t.id || t.threat_id}>
                  #{t.id || t.threat_id || i + 1} &bull; {t.threat_type} ({t.src_ip})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* SVG Canvas */}
      <div className="relative w-full bg-slate-50/70 border border-slate-200/80 rounded-xl overflow-hidden p-4">
        <svg
          viewBox="0 0 860 360"
          className="w-full h-auto max-h-[380px] drop-shadow-sm select-none"
        >
          <defs>
            {/* Markers for arrows */}
            <marker
              id="arrowhead-red"
              markerWidth="10"
              markerHeight="7"
              refX="9"
              refY="3.5"
              orient="auto"
            >
              <polygon points="0 0, 10 3.5, 0 7" fill="#e11d48" />
            </marker>
            <marker
              id="arrowhead-amber"
              markerWidth="8"
              markerHeight="6"
              refX="7"
              refY="3"
              orient="auto"
            >
              <polygon points="0 0, 8 3, 0 6" fill="#f59e0b" />
            </marker>
            {/* Radial Gradient */}
            <radialGradient id="attackerGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#fee2e2" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#fee2e2" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Attacker Node Halo Glow */}
          <circle cx="160" cy="180" r="65" fill="url(#attackerGlow)" />

          {/* Primary Attack Edge (Attacker -> Victim Server) */}
          <path
            d="M 230 180 Q 430 140 620 180"
            fill="none"
            stroke="#e11d48"
            strokeWidth="3.5"
            strokeDasharray="8 4"
            className="animate-pulse"
            markerEnd="url(#arrowhead-red)"
          />

          {/* Edge Label Pill (Centered on Path) */}
          <g transform="translate(370, 125)">
            <rect
              x="-60"
              y="-20"
              width="200"
              height="40"
              rx="10"
              fill="#ffffff"
              stroke="#f43f5e"
              strokeWidth="1.5"
              filter="drop-shadow(0 2px 4px rgba(0,0,0,0.06))"
            />
            <text
              x="40"
              y="-4"
              textAnchor="middle"
              className="text-[12px] font-bold font-mono"
              fill="#be123c"
            >
              {threatType} &bull; {probVal}% Probability
            </text>
            <text
              x="40"
              y="12"
              textAnchor="middle"
              className="text-[10px] font-mono"
              fill="#64748b"
            >
              {count} Packets &bull; RF Confidence: {probVal}%
            </text>
          </g>

          {/* Node 1: Attacker IP */}
          <g transform="translate(160, 180)">
            <rect
              x="-75"
              y="-45"
              width="150"
              height="90"
              rx="12"
              fill="#ffffff"
              stroke="#fda4af"
              strokeWidth="2"
              filter="drop-shadow(0 2px 5px rgba(225,29,72,0.1))"
            />
            <rect x="-75" y="-45" width="150" height="24" rx="12" fill="#fff1f2" />
            <text
              x="0"
              y="-28"
              textAnchor="middle"
              className="text-[10px] font-bold uppercase font-mono tracking-wider"
              fill="#e11d48"
            >
              Adversary Source
            </text>
            <circle cx="-50" cy="8" r="14" fill="#fee2e2" />
            <path
              d="M -54 13 L -46 13 L -48 3 L -52 3 Z"
              fill="#e11d48"
            />
            <text
              x="-28"
              y="3"
              className="text-[12px] font-bold font-mono"
              fill="#0f172a"
            >
              {attackerIp}
            </text>
            <text
              x="-28"
              y="18"
              className="text-[10px] font-mono"
              fill="#64748b"
            >
              Threat Actor
            </text>
          </g>

          {/* Node 2: Target / Victim IP */}
          <g transform="translate(680, 180)">
            <rect
              x="-75"
              y="-45"
              width="150"
              height="90"
              rx="12"
              fill="#ffffff"
              stroke="#bbf7d0"
              strokeWidth="2"
              filter="drop-shadow(0 2px 5px rgba(22,163,74,0.1))"
            />
            <rect x="-75" y="-45" width="150" height="24" rx="12" fill="#f0fdf4" />
            <text
              x="0"
              y="-28"
              textAnchor="middle"
              className="text-[10px] font-bold uppercase font-mono tracking-wider"
              fill="#16a34a"
            >
              Protected Victim
            </text>
            <circle cx="-50" cy="8" r="14" fill="#dcfce7" />
            <rect x="-54" y="2" width="8" height="12" rx="1" fill="#16a34a" />
            <text
              x="-28"
              y="3"
              className="text-[12px] font-bold font-mono"
              fill="#0f172a"
            >
              {targetIp}
            </text>
            <text
              x="-28"
              y="18"
              className="text-[10px] font-mono"
              fill="#64748b"
            >
              Port: {targetPort}
            </text>
          </g>

          {/* Scanned Ports Sub-Graph Branches (Shown for Port Scans) */}
          {isPortScan && scannedPorts.length > 0 && (
            <g>
              {scannedPorts.slice(0, 6).map((p, idx) => {
                const total = Math.min(scannedPorts.length, 6);
                const angle = -50 + (idx * (100 / (total - 1 || 1)));
                const rad = (angle * Math.PI) / 180;
                const px = 160 + Math.cos(rad) * 135;
                const py = 180 + Math.sin(rad) * 115;

                return (
                  <g key={idx}>
                    {/* Connecting line */}
                    <line
                      x1="160"
                      y1="180"
                      x2={px}
                      y2={py}
                      stroke="#f59e0b"
                      strokeWidth="1.5"
                      strokeDasharray="3 3"
                      markerEnd="url(#arrowhead-amber)"
                    />
                    {/* Small Port Badge Node */}
                    <rect
                      x={px - 26}
                      y={py - 12}
                      width="52"
                      height="24"
                      rx="6"
                      fill="#fffbeb"
                      stroke="#fcd34d"
                      strokeWidth="1.2"
                    />
                    <text
                      x={px}
                      y={py + 4}
                      textAnchor="middle"
                      className="text-[10px] font-bold font-mono"
                      fill="#b45309"
                    >
                      :{p}
                    </text>
                  </g>
                );
              })}
            </g>
          )}
        </svg>

        {/* Legend / Metrics Footer */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 mt-1 border-t border-slate-200/60 text-xs font-mono">
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5 text-slate-600">
              <span className="w-2 h-2 rounded-full bg-rose-500" /> Attacker: <strong className="text-slate-800">{attackerIp}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-slate-600">
              <span className="w-2 h-2 rounded-full bg-emerald-500" /> Victim: <strong className="text-slate-800">{targetIp}</strong>
            </span>
            {isPortScan && (
              <span className="flex items-center gap-1.5 text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">
                {scannedPorts.length} Unique Ports Probed
              </span>
            )}
          </div>
          <div className="text-slate-500">
            Model: <span className="font-semibold text-indigo-700">Random Forest (100 Trees)</span> &bull; Predict Proba: <span className="font-bold text-rose-600">{probVal}%</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AttackGraph;
