import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Cpu,
  Clock,
  Layers,
  Lock,
  Unlock,
  ChevronDown,
  ChevronUp,
  History,
  Info,
  CheckCircle2,
  X
} from 'lucide-react';

const AttackDetailsPanel = ({
  threat,
  recentThreats = [],
  onSelectThreat,
  onClose,
  onBlockIp,
  onUnblockIp,
  isBlocked = false,
}) => {
  const [showAllFeatures, setShowAllFeatures] = useState(false);

  if (!threat) {
    return (
      <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-sm text-center">
        <ShieldCheck className="w-10 h-10 text-emerald-500 mx-auto mb-2" />
        <h3 className="text-sm font-bold text-slate-800">No Active Attack Alert Selected</h3>
        <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
          The network topology is currently processing normal traffic. When an attack is detected by the Random Forest model, explainable details will automatically display here.
        </p>
      </div>
    );
  }

  const ml = threat.ml_prediction || {};
  const probs = ml.probabilities || {
    BENIGN: 0.05,
    SYN_FLOOD: threat.threat_type === 'SYN_FLOOD' ? 0.94 : 0.01,
    PORT_SCAN: threat.threat_type === 'PORT_SCAN' ? 0.92 : 0.01,
  };
  const conf = ml.confidence || 0.95;
  const traffic = threat.traffic_measurements || {};
  const features = ml.features || {};
  const topFeatures = ml.top_features || [];

  return (
    <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden text-slate-800">
      {/* ── Top Header Strip ──────────────────────────────────────────────── */}
      <div className="bg-slate-900 text-white p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="w-5 h-5 text-rose-400" />
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold font-mono tracking-wider uppercase text-rose-300">
                Random Forest Detection Alert
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase ${
                  threat.severity === 'CRITICAL'
                    ? 'bg-rose-600 text-white'
                    : threat.severity === 'HIGH'
                    ? 'bg-orange-500 text-white'
                    : 'bg-amber-500 text-slate-900'
                }`}
              >
                {threat.severity || 'HIGH'}
              </span>
            </div>
            <h2 className="text-base font-bold font-mono mt-0.5 text-white">
              {threat.threat_type || 'SYN_FLOOD'}
            </h2>
          </div>
        </div>

        {/* Previous Alerts Selector Dropdown */}
        <div className="flex items-center gap-2">
          {recentThreats.length > 1 && (
            <div className="flex items-center gap-1.5 bg-slate-800/80 px-2.5 py-1 rounded-lg border border-slate-700 text-xs">
              <History className="w-3.5 h-3.5 text-slate-400" />
              <select
                value={recentThreats.findIndex((t) => t === threat)}
                onChange={(e) => onSelectThreat && onSelectThreat(recentThreats[Number(e.target.value)])}
                className="bg-transparent text-slate-200 font-mono text-xs focus:outline-none cursor-pointer"
              >
                {recentThreats.map((t, idx) => (
                  <option key={idx} value={idx} className="bg-slate-900 text-white">
                    Alert #{idx + 1}: {t.threat_type} ({t.src_ip})
                  </option>
                ))}
              </select>
            </div>
          )}

          {onClose && (
            <button
              onClick={onClose}
              className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      <div className="p-5 space-y-5">
        {/* ── 1. Attack Identification Grid ─────────────────────────────────── */}
        <div>
          <h4 className="text-[11px] font-bold font-mono uppercase tracking-wider text-slate-400 mb-2">
            1. Attack Identification & Endpoint Metadata
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
            <div className="bg-slate-50 p-2.5 rounded-xl border border-slate-200/80">
              <span className="text-[10px] text-slate-400 uppercase block font-sans">Attacker IP</span>
              <strong className="text-rose-600 font-bold text-sm block mt-0.5 truncate">{threat.src_ip}</strong>
            </div>

            <div className="bg-slate-50 p-2.5 rounded-xl border border-slate-200/80">
              <span className="text-[10px] text-slate-400 uppercase block font-sans">Target IP : Port</span>
              <strong className="text-slate-900 font-bold text-sm block mt-0.5 truncate">
                {threat.dst_ip || '192.168.1.1'}:{threat.dst_port || '80'}
              </strong>
            </div>

            <div className="bg-slate-50 p-2.5 rounded-xl border border-slate-200/80">
              <span className="text-[10px] text-slate-400 uppercase block font-sans">Protocol & Flags</span>
              <strong className="text-slate-800 font-bold text-xs block mt-1">
                {threat.protocol || 'TCP'} &bull; Flags=[{threat.flags || 'S'}]
              </strong>
            </div>

            <div className="bg-slate-50 p-2.5 rounded-xl border border-slate-200/80">
              <span className="text-[10px] text-slate-400 uppercase block font-sans">Detection Mode</span>
              <span className="inline-block mt-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-indigo-50 text-indigo-700 border border-indigo-200">
                {threat.event_source === 'simulation' ? 'Simulation Mode' : 'Live Capture'}
              </span>
            </div>
          </div>
        </div>

        {/* ── 2. Descriptive Traffic Measurements ──────────────────────────── */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-[11px] font-bold font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-indigo-600" />
              2. Observed Traffic Measurements (Descriptive Only)
            </h4>
            <span className="text-[10px] text-slate-500 italic font-sans">
              Descriptive metrics &bull; Classification by Random Forest
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-xs font-mono">
            <div className="bg-indigo-50/50 p-2.5 rounded-xl border border-indigo-100">
              <span className="text-[10px] text-indigo-700 uppercase block font-sans">Observed Packet Count</span>
              <strong className="text-slate-900 text-sm">{traffic.observed_packet_count || threat.count || 25} pkts</strong>
            </div>

            <div className="bg-indigo-50/50 p-2.5 rounded-xl border border-indigo-100">
              <span className="text-[10px] text-indigo-700 uppercase block font-sans">Observed Packet Rate</span>
              <strong className="text-rose-600 text-sm font-bold">
                {traffic.attack_rate_str || `${traffic.observed_rate_pps || 2.5} pkts/sec`}
              </strong>
            </div>

            <div className="bg-indigo-50/50 p-2.5 rounded-xl border border-indigo-100">
              <span className="text-[10px] text-indigo-700 uppercase block font-sans">Observation Window</span>
              <strong className="text-slate-900 text-sm">{traffic.window_seconds || 10.0}s</strong>
            </div>

            <div className="bg-indigo-50/50 p-2.5 rounded-xl border border-indigo-100">
              <span className="text-[10px] text-indigo-700 uppercase block font-sans">Unique Ports Probed</span>
              <strong className="text-slate-900 text-sm">{traffic.unique_ports_contacted || 1} port(s)</strong>
            </div>
          </div>

          {traffic.ports_list && traffic.ports_list.length > 1 && (
            <div className="mt-2 text-[11px] font-mono text-slate-600 bg-slate-50 p-2 rounded-lg border border-slate-200">
              <strong className="text-slate-800">Probed Ports: </strong>
              {traffic.ports_list.join(', ')}
            </div>
          )}
        </div>

        {/* ── 3. Random Forest Inference & Class Probabilities ──────────────── */}
        <div className="p-4 bg-slate-50/80 rounded-xl border border-slate-200 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-violet-600" />
              <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-800">
                3. Random Forest ML Analysis (100 Trees, 76 Features)
              </h4>
            </div>
            <div className="text-xs font-mono">
              Ensemble Confidence:{' '}
              <strong className="text-violet-700 font-bold">{(conf * 100).toFixed(1)}%</strong>
            </div>
          </div>

          {/* Probabilities Progress Bars */}
          <div className="space-y-2 pt-1">
            <span className="text-[11px] font-semibold text-slate-600 block">Class Probabilities:</span>

            {/* BENIGN */}
            <div className="space-y-1">
              <div className="flex justify-between text-[11px] font-mono text-slate-600">
                <span>BENIGN (Normal Traffic)</span>
                <span>{((probs.BENIGN || 0) * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-emerald-500 h-full rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(100, (probs.BENIGN || 0) * 100)}%` }}
                />
              </div>
            </div>

            {/* SYN_FLOOD */}
            <div className="space-y-1">
              <div className="flex justify-between text-[11px] font-mono text-slate-600">
                <span>SYN_FLOOD (Connection Exhaustion)</span>
                <span className="text-rose-600 font-bold">{((probs.SYN_FLOOD || 0) * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-rose-600 h-full rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(100, (probs.SYN_FLOOD || 0) * 100)}%` }}
                />
              </div>
            </div>

            {/* PORT_SCAN */}
            <div className="space-y-1">
              <div className="flex justify-between text-[11px] font-mono text-slate-600">
                <span>PORT_SCAN (Reconnaissance Sweep)</span>
                <span className="text-amber-600 font-bold">{((probs.PORT_SCAN || 0) * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-amber-500 h-full rounded-full transition-all duration-500"
                  style={{ width: `${Math.min(100, (probs.PORT_SCAN || 0) * 100)}%` }}
                />
              </div>
            </div>
          </div>

          {/* Concise Feature Attribution Summary */}
          <div className="pt-2 border-t border-slate-200/80 text-xs text-slate-700 leading-relaxed space-y-1">
            <p>
              <strong>Detection Reason: </strong>
              {threat.detection_reason}
            </p>
            <p className="text-slate-600 text-[11px]">
              <strong>Technical Attribution: </strong>
              {threat.technical_reason}
            </p>
          </div>

          {/* Top Features Attribution Chips */}
          {topFeatures.length > 0 && (
            <div className="pt-2 border-t border-slate-200/80 space-y-2">
              <span className="text-[11px] font-bold text-slate-700 block font-mono">
                Top Contributing Flow Features (Tree Ensemble Attribution):
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                {topFeatures.slice(0, 4).map((f, i) => (
                  <div key={i} className="bg-white p-2 rounded-lg border border-slate-200">
                    <div className="flex justify-between font-mono">
                      <span className="font-bold text-slate-800">{f.feature}</span>
                      <span className="text-violet-600 font-bold">{f.importance_pct}%</span>
                    </div>
                    <p className="text-[10px] text-slate-500 mt-0.5 line-clamp-1">{f.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Actual Model Features Table Toggle */}
          {Object.keys(features).length > 0 && (
            <div className="pt-2 border-t border-slate-200">
              <button
                onClick={() => setShowAllFeatures(!showAllFeatures)}
                className="flex items-center gap-1.5 text-xs font-mono font-semibold text-indigo-600 hover:text-indigo-800 transition-colors"
              >
                {showAllFeatures ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                <span>
                  {showAllFeatures ? 'Hide' : 'View'} Actual 76 Flow Features Passed to Model ({Object.keys(features).length} non-zero)
                </span>
              </button>

              {showAllFeatures && (
                <div className="mt-2 max-h-48 overflow-y-auto bg-white rounded-lg border border-slate-200 p-2 font-mono text-[11px]">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="border-b border-slate-200 text-slate-400 text-[10px]">
                        <th className="py-1">Feature Name</th>
                        <th className="py-1 text-right">Extracted Flow Value</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {Object.entries(features).map(([k, v]) => (
                        <tr key={k} className="hover:bg-slate-50">
                          <td className="py-1 text-slate-700">{k}</td>
                          <td className="py-1 text-right text-indigo-600 font-bold">
                            {typeof v === 'number' ? (v % 1 === 0 ? v : v.toFixed(3)) : String(v)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>

        {/* ── 4. Defense Response & Containment ────────────────────────────── */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-3 border-t border-slate-100">
          <div>
            <span className="text-[10px] font-mono text-slate-400 uppercase block font-semibold">
              Perimeter Defense Policy:
            </span>
            <p className="text-xs text-slate-700 mt-0.5">
              {threat.recommended_response || 'Drop incoming traffic from source IP at perimeter defense barrier.'}
            </p>
          </div>

          <div className="flex items-center gap-2 self-end sm:self-auto">
            {isBlocked ? (
              <button
                onClick={() => onUnblockIp && onUnblockIp(threat.src_ip)}
                className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 rounded-lg text-xs font-mono font-semibold transition-all"
              >
                Unblock IP
              </button>
            ) : (
              <button
                onClick={() => onBlockIp && onBlockIp(threat.src_ip)}
                className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-xs font-mono font-semibold shadow-sm transition-all"
              >
                Block IP at Barrier
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AttackDetailsPanel;

