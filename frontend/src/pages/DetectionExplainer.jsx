import React, { useState, useEffect } from 'react';
import {
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Pause,
  Shield,
  ShieldAlert,
  ArrowRight,
  Clock,
  Layers,
  Database,
  Lock,
  Unlock,
  Radio,
  ExternalLink,
  ChevronDown
} from 'lucide-react';
import { endpoints } from '../services/api';

const DetectionExplainer = () => {
  const [recentDetections, setRecentDetections] = useState([]);
  const [selectedDetectionId, setSelectedDetectionId] = useState('latest');
  const [snapshot, setSnapshot] = useState(null);
  const [modelInfo, setModelInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isPaused, setIsPaused] = useState(false);
  const [activeStep, setActiveStep] = useState(5); // For walkthrough replay
  const [isReplaying, setIsReplaying] = useState(false);
  const [notification, setNotification] = useState({ type: '', message: '' });

  const showNotification = (type, message) => {
    setNotification({ type, message });
    setTimeout(() => setNotification({ type: '', message: '' }), 4000);
  };

  // Fetch recent detections list
  const fetchRecent = async () => {
    try {
      const res = await endpoints.getRecentExplanations(15);
      const items = res.data?.recent_detections || [];
      setRecentDetections(items);
    } catch (e) {
      console.debug('Failed to fetch recent explanations list', e);
    }
  };

  // Fetch model info
  const fetchModelInfo = async () => {
    try {
      const res = await endpoints.getModelInfo();
      setModelInfo(res.data);
    } catch (e) {
      console.debug('Failed to fetch model info', e);
    }
  };

  // Fetch snapshot for selected detection
  const fetchSnapshot = async (id) => {
    if (isPaused && snapshot) return;
    try {
      setLoading(true);
      const res = await endpoints.getDetectionExplanation(id || 'latest');
      if (res.data?.snapshot) {
        setSnapshot(res.data.snapshot);
      }
    } catch (e) {
      console.debug('Failed to fetch snapshot', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRecent();
    fetchModelInfo();
    fetchSnapshot('latest');
  }, []);

  // Poll for latest if not paused
  useEffect(() => {
    if (isPaused) return;
    const timer = setInterval(() => {
      fetchRecent();
      if (selectedDetectionId === 'latest') {
        fetchSnapshot('latest');
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [isPaused, selectedDetectionId]);

  // Replay animation for the 5-step walkthrough
  const handleReplayWalkthrough = () => {
    setIsReplaying(true);
    setActiveStep(1);
    let step = 1;
    const interval = setInterval(() => {
      step += 1;
      setActiveStep(step);
      if (step >= 5) {
        clearInterval(interval);
        setIsReplaying(false);
      }
    }, 600);
  };

  // Manual Block / Unblock actions
  const handleBlockIp = async (ip) => {
    if (!ip) return;
    try {
      await endpoints.manualBlockIP(ip, 'Explainer containment', 30);
      showNotification('success', `Contained ${ip} at perimeter (Safe Dry-Run)`);
      fetchSnapshot(selectedDetectionId);
    } catch (e) {
      showNotification('error', 'Failed to contain IP.');
    }
  };

  const handleUnblockIp = async (ip) => {
    if (!ip) return;
    try {
      await endpoints.manualUnblockIP(ip);
      showNotification('info', `Unblocked ${ip} (Safe Dry-Run)`);
      fetchSnapshot(selectedDetectionId);
    } catch (e) {
      showNotification('error', 'Failed to unblock IP.');
    }
  };

  if (loading && !snapshot) {
    return (
      <div className="p-8 text-center font-mono text-xs text-[#64748B]">
        Loading detection explainability telemetry...
      </div>
    );
  }

  const threatType = snapshot?.threat_type || 'PORT_SCAN';
  const probPct = snapshot?.predict_proba_pct ?? 94;
  const isAttack = threatType !== 'BENIGN';
  const voteSummary = snapshot?.vote_summary || {};
  const treeVotes = snapshot?.tree_votes || [];
  const primaryVoteCount = voteSummary[threatType] || Math.round(probPct);

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

      {/* Top Header & Selector Bar */}
      <div className="bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-[#6D28D9]" />
            <h1 className="text-base font-bold text-[#1B2B28] uppercase font-mono tracking-wide">
              Detection Explainer &bull; Random Forest Model Decisions
            </h1>
          </div>
          <p className="text-xs text-[#64748B] mt-0.5">
            Transparent step-by-step breakdown of how the 100-tree ensemble evaluated 76 statistical flow features.
          </p>
        </div>

        {/* Dropdown Selector & Pause Toggle */}
        <div className="flex items-center gap-2 font-mono text-xs">
          {/* Pause Toggle */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border font-semibold transition-all ${
              isPaused
                ? 'bg-[#FFFBEB] text-[#D97706] border-[#FDE68A]'
                : 'bg-[#F4F7F6] text-[#64748B] border-[#E2E8E6] hover:bg-[#E2E8E6]'
            }`}
            title="Freeze live updates while explaining to evaluator"
          >
            {isPaused ? <Play className="w-3 h-3 fill-current" /> : <Pause className="w-3 h-3 fill-current" />}
            <span>{isPaused ? 'Resume Updates' : 'Pause Updates'}</span>
          </button>

          {/* Detections Dropdown */}
          <div className="relative">
            <select
              value={selectedDetectionId}
              onChange={(e) => {
                setSelectedDetectionId(e.target.value);
                fetchSnapshot(e.target.value);
              }}
              className="bg-[#F4F7F6] border border-[#E2E8E6] rounded-lg px-3 py-1.5 text-xs text-[#1B2B28] font-mono focus:outline-none focus:border-[#0F766E]"
            >
              <option value="latest">Latest Detection ({threatType})</option>
              {recentDetections.map((d) => (
                <option key={d.id} value={d.id}>
                  #{d.id} - {d.threat_type} ({d.src_ip}) [{d.predict_proba_pct}%]
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Row 1: Detection Walkthrough (5 steps) with Replay Button */}
      <div className="bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#E2E8E6]">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#0F766E]" />
            <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
              a) Detection Walkthrough (5-Step Pipeline Lifecycle)
            </h2>
          </div>
          <button
            onClick={handleReplayWalkthrough}
            disabled={isReplaying}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-mono font-semibold rounded-md border border-[#E2E8E6] bg-[#F4F7F6] hover:bg-[#E2E8E6] text-[#1B2B28] transition-all disabled:opacity-50"
          >
            <RotateCcw className="w-3 h-3" />
            <span>Replay Steps</span>
          </button>
        </div>

        {/* 5 Sequential Cards */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {(snapshot?.walkthrough || []).map((step) => {
            const isLit = step.step <= activeStep;
            return (
              <div
                key={step.step}
                className={`p-3 rounded-lg border transition-all duration-300 ${
                  isLit
                    ? 'bg-[#F0FDFA] border-[#CCFBF1] shadow-sm'
                    : 'bg-[#F4F7F6] border-[#E2E8E6] opacity-60'
                }`}
              >
                <div className="flex items-center justify-between text-[11px] font-mono text-[#64748B] mb-1">
                  <span className="font-bold text-[#0F766E]">Step {step.step}</span>
                  <span>{step.timestamp}</span>
                </div>
                <h3 className="text-xs font-bold text-[#1B2B28] mb-1">{step.title}</h3>
                <p className="text-[11px] text-[#64748B] leading-relaxed font-sans">{step.detail}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Row 2: Tree Voting Grid (b) & Attack Signature Card (d) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* b) 10x10 Tree Voting Grid (lg:col-span-6) */}
        <div className="lg:col-span-6 bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-[#E2E8E6]">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-[#6D28D9]" />
                <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
                  b) 100-Tree Voting Distribution
                </h2>
              </div>
              <span className="font-mono text-xs font-bold text-[#1B2B28]">
                {primaryVoteCount} of 100 trees voted {threatType}
              </span>
            </div>
            <p className="text-xs text-[#64748B] mt-1.5">
              Individual vote of each decision tree estimator in the trained Random Forest pipeline:
            </p>

            {/* 10x10 Grid of Squares */}
            <div className="mt-3 grid grid-cols-10 gap-1.5 p-3 bg-[#F4F7F6] rounded-lg border border-[#E2E8E6] max-w-sm mx-auto">
              {treeVotes.map((t) => {
                const isThreatVote = t.vote === threatType && isAttack;
                const isBenign = t.vote === 'BENIGN';
                return (
                  <div
                    key={t.tree_id}
                    title={`Tree #${t.tree_id}: Voted ${t.vote}`}
                    className={`w-5 h-5 rounded-sm flex items-center justify-center text-[9px] font-mono font-bold transition-transform hover:scale-125 cursor-pointer ${
                      isThreatVote
                        ? threatType === 'SYN_FLOOD'
                          ? 'bg-[#DC2626] text-white'
                          : 'bg-[#F59E0B] text-white'
                        : isBenign
                        ? 'bg-[#16A34A] text-white'
                        : 'bg-[#6D28D9] text-white'
                    }`}
                  >
                    {t.tree_id}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Voting Legend */}
          <div className="pt-2 border-t border-[#E2E8E6] flex flex-wrap items-center justify-between text-xs font-mono text-[#64748B]">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#16A34A]" />
              <span>BENIGN ({voteSummary.BENIGN || 0})</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#F59E0B]" />
              <span>PORT_SCAN ({voteSummary.PORT_SCAN || 0})</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#DC2626]" />
              <span>SYN_FLOOD ({voteSummary.SYN_FLOOD || 0})</span>
            </div>
          </div>
        </div>

        {/* d) Attack Signature Card & TCP Diagram (lg:col-span-6) */}
        <div className="lg:col-span-6 bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-[#E2E8E6]">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-[#DC2626]" />
                <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
                  d) Attack Signature & TCP Flow Diagram
                </h2>
              </div>
              <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-[#FEF2F2] text-[#DC2626]">
                {threatType}
              </span>
            </div>

            <p className="text-xs text-[#64748B] mt-1.5">
              {snapshot?.attack_signature?.description}
            </p>

            {/* Small TCP Diagram */}
            <div className="mt-3 p-3 bg-[#F4F7F6] rounded-lg border border-[#E2E8E6] space-y-2 font-mono text-xs">
              <div className="font-bold text-[11px] text-[#0F766E] uppercase border-b border-[#E2E8E6] pb-1">
                Handshake Sequence (Observed Packets: {snapshot?.count})
              </div>
              {(snapshot?.attack_signature?.steps || []).map((step, idx) => (
                <div key={idx} className="flex items-center justify-between text-xs py-1">
                  <span className="font-semibold text-[#1B2B28]">{step.from}</span>
                  <div className="flex-1 mx-3 border-b border-dashed border-[#CBD5E1] relative flex items-center justify-center">
                    <span className="px-1 bg-[#F4F7F6] text-[10px] text-[#64748B]">{step.msg}</span>
                    <ArrowRight className="w-3 h-3 text-[#64748B] absolute right-0" />
                  </div>
                  <span className="font-semibold text-[#1B2B28]">{step.to}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-2 border-t border-[#E2E8E6] flex items-center justify-between text-xs font-mono">
            <span className="text-[#64748B]">Perimeter Action:</span>
            <div className="flex items-center gap-2">
              <span className="font-bold text-[#7C3AED] bg-[#F5F3FF] px-2 py-0.5 rounded">
                {snapshot?.action_taken}
              </span>
              <button
                onClick={() => handleUnblockIp(snapshot?.src_ip)}
                className="px-2 py-0.5 rounded border border-[#E2E8E6] bg-white text-[#1B2B28] hover:bg-[#E2E8E6]"
              >
                Unblock
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Row 3: Feature Evidence Table (c) */}
      <div className="bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#E2E8E6]">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-[#0F766E]" />
            <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
              c) Feature Evidence Table (Observed vs. Training BENIGN Baseline)
            </h2>
          </div>
          <span className="text-[11px] font-mono text-[#64748B]">
            Baseline source: CIC-IDS2017 Benign Calibration Set
          </span>
        </div>

        <div className="overflow-x-auto border border-[#E2E8E6] rounded-lg">
          <table className="w-full text-left font-mono text-xs divide-y divide-[#E2E8E6]">
            <thead className="bg-[#F4F7F6] text-[#64748B] text-[10px] uppercase">
              <tr>
                <th className="py-2 px-3">Flow Feature</th>
                <th className="py-2 px-3">Observed Value</th>
                <th className="py-2 px-3">Normal Baseline Range</th>
                <th className="py-2 px-3">Verdict</th>
                <th className="py-2 px-3">Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E2E8E6] bg-white">
              {(snapshot?.evidence_table || []).map((row, idx) => (
                <tr key={idx} className="hover:bg-[#F4F7F6]/50">
                  <td className="py-2 px-3 font-bold text-[#1B2B28]">{row.feature}</td>
                  <td className="py-2 px-3 font-bold text-[#0F766E]">{row.observed_value}</td>
                  <td className="py-2 px-3 text-[#64748B]">{row.normal_range}</td>
                  <td className="py-2 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        row.verdict === 'Attack'
                          ? 'bg-[#FEF2F2] text-[#DC2626] border border-[#FECACA]'
                          : row.verdict === 'Suspicious'
                          ? 'bg-[#FFFBEB] text-[#D97706] border border-[#FDE68A]'
                          : 'bg-[#ECFDF3] text-[#16A34A] border border-[#BBF7D0]'
                      }`}
                    >
                      {row.verdict}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-[#64748B] font-sans text-[11px]">{row.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Row 4: Normal vs Attack (e) & Decision Path (f) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* e) Normal vs Attack Comparison */}
        <div className="lg:col-span-6 bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-[#E2E8E6]">
            <ArrowRight className="w-4 h-4 text-[#0F766E]" />
            <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
              e) Normal vs. Attack Comparison
            </h2>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            {/* Normal card */}
            <div className="p-3 bg-[#ECFDF3]/40 border border-[#BBF7D0] rounded-lg space-y-1.5">
              <span className="font-bold text-[#16A34A] text-xs block">
                {snapshot?.normal_vs_attack?.normal_flow?.title}
              </span>
              <div className="text-[11px] text-[#1B2B28]">SYN Flags: {snapshot?.normal_vs_attack?.normal_flow?.syn_flags}</div>
              <div className="text-[11px] text-[#1B2B28]">Duration: {snapshot?.normal_vs_attack?.normal_flow?.flow_duration}</div>
              <div className="text-[11px] text-[#1B2B28]">Ports: {snapshot?.normal_vs_attack?.normal_flow?.unique_ports}</div>
              <div className="text-[11px] text-[#1B2B28]">Packet Length: {snapshot?.normal_vs_attack?.normal_flow?.packet_length}</div>
              <div className="text-[11px] text-[#1B2B28]">Rate: {snapshot?.normal_vs_attack?.normal_flow?.packet_rate}</div>
            </div>

            {/* Attack card */}
            <div className="p-3 bg-[#FEF2F2]/50 border border-[#FECACA] rounded-lg space-y-1.5">
              <span className="font-bold text-[#DC2626] text-xs block">
                {snapshot?.normal_vs_attack?.attack_flow?.title}
              </span>
              <div className="text-[11px] text-[#1B2B28]">SYN Flags: {snapshot?.normal_vs_attack?.attack_flow?.syn_flags}</div>
              <div className="text-[11px] text-[#1B2B28]">Duration: {snapshot?.normal_vs_attack?.attack_flow?.flow_duration}</div>
              <div className="text-[11px] text-[#1B2B28]">Ports: {snapshot?.normal_vs_attack?.attack_flow?.unique_ports}</div>
              <div className="text-[11px] text-[#1B2B28]">Packet Length: {snapshot?.normal_vs_attack?.attack_flow?.packet_length}</div>
              <div className="text-[11px] text-[#1B2B28]">Rate: {snapshot?.normal_vs_attack?.attack_flow?.packet_rate}</div>
            </div>
          </div>
        </div>

        {/* f) Sample Decision Path */}
        <div className="lg:col-span-6 bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-[#E2E8E6]">
            <Cpu className="w-4 h-4 text-[#6D28D9]" />
            <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
              f) Sample Decision Path (Tree #0 Traversal)
            </h2>
          </div>
          <p className="text-xs text-[#64748B]">
            Authentic split path through Tree #0 of the trained forest based on the observed flow features:
          </p>

          <div className="p-3 bg-[#F4F7F6] border border-[#E2E8E6] rounded-lg font-mono text-xs text-[#1B2B28] leading-relaxed break-words">
            {snapshot?.decision_path_text}
          </div>
        </div>
      </div>

      {/* Row 5: Timing Strip (g) & Model Card (h) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* g) Timing Strip */}
        <div className="lg:col-span-6 bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-[#E2E8E6]">
            <Clock className="w-4 h-4 text-[#0F766E]" />
            <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
              g) Timing Strip & Detection Latency
            </h2>
          </div>

          <div className="grid grid-cols-3 gap-2 text-xs font-mono">
            <div className="p-2.5 bg-[#F4F7F6] rounded-lg border border-[#E2E8E6]">
              <span className="text-[10px] text-[#64748B] block uppercase">Attack Start</span>
              <span className="font-bold text-[#1B2B28]">{snapshot?.timing?.attack_start}</span>
            </div>
            <div className="p-2.5 bg-[#F0FDFA] rounded-lg border border-[#CCFBF1]">
              <span className="text-[10px] text-[#0F766E] block uppercase">ML Detection</span>
              <span className="font-bold text-[#0F766E]">{snapshot?.timing?.detected_at}</span>
            </div>
            <div className="p-2.5 bg-[#F5F3FF] rounded-lg border border-[#DDD6FE]">
              <span className="text-[10px] text-[#7C3AED] block uppercase">Dry-Run Block</span>
              <span className="font-bold text-[#7C3AED]">{snapshot?.timing?.blocked_at}</span>
            </div>
          </div>
          <div className="text-xs font-mono text-[#64748B] pt-1">
            End-to-end detection delay:{' '}
            <strong className="text-[#1B2B28]">{snapshot?.timing?.delay_sec} seconds</strong> (within 1 observation window).
          </div>
        </div>

        {/* h) Model Card */}
        <div className="lg:col-span-6 bg-white border border-[#E2E8E6] rounded-xl p-4 shadow-sm space-y-3">
          <div className="flex items-center gap-2 pb-2 border-b border-[#E2E8E6]">
            <Database className="w-4 h-4 text-[#0F766E]" />
            <h2 className="text-xs font-bold uppercase tracking-wider font-mono text-[#1B2B28]">
              h) Model Card & Saved Metrics
            </h2>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono">
            <div className="p-2 bg-[#F4F7F6] rounded-md border border-[#E2E8E6]">
              <span className="text-[10px] text-[#64748B] block">Model</span>
              <span className="font-bold text-[#1B2B28]">{snapshot?.model_card?.algorithm}</span>
            </div>
            <div className="p-2 bg-[#F4F7F6] rounded-md border border-[#E2E8E6]">
              <span className="text-[10px] text-[#64748B] block">Estimators</span>
              <span className="font-bold text-[#1B2B28]">{snapshot?.model_card?.estimators_count} Trees</span>
            </div>
            <div className="p-2 bg-[#F4F7F6] rounded-md border border-[#E2E8E6]">
              <span className="text-[10px] text-[#64748B] block">Test Accuracy</span>
              <span className="font-bold text-[#16A34A]">{snapshot?.model_card?.accuracy_pct}%</span>
            </div>
            <div className="p-2 bg-[#F4F7F6] rounded-md border border-[#E2E8E6]">
              <span className="text-[10px] text-[#64748B] block">Macro F1</span>
              <span className="font-bold text-[#16A34A]">{snapshot?.model_card?.macro_f1}</span>
            </div>
            <div className="p-2 bg-[#F4F7F6] rounded-md border border-[#E2E8E6]">
              <span className="text-[10px] text-[#64748B] block">Features</span>
              <span className="font-bold text-[#1B2B28]">{snapshot?.model_card?.n_features} Flow Cols</span>
            </div>
            <div className="p-2 bg-[#F4F7F6] rounded-md border border-[#E2E8E6]">
              <span className="text-[10px] text-[#64748B] block">Framework</span>
              <span className="font-bold text-[#1B2B28]">{snapshot?.model_card?.sklearn_version}</span>
            </div>
          </div>
          <div className="text-[11px] font-mono text-[#64748B] pt-1 truncate">
            Datasets: {snapshot?.model_card?.dataset_provenance}
          </div>
        </div>
      </div>
    </div>
  );
};

export default DetectionExplainer;

