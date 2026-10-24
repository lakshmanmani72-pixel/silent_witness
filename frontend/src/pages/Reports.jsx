import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  Calendar,
  Filter,
  CheckCircle,
  AlertTriangle,
  ShieldAlert,
  Info,
  Layers,
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { endpoints } from '../services/api';

const Reports = () => {
  const [timeRange, setTimeRange] = useState('24h');
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchSummary = async () => {
    try {
      setLoading(true);
      const res = await endpoints.getReportSummary(timeRange);
      setSummary(res.data);
    } catch (err) {
      console.error('Failed to load report summary:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, [timeRange]);

  const downloadJsonSummary = () => {
    if (!summary) return;
    const blob = new Blob([JSON.stringify(summary, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `silent_witness_report_${timeRange}_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono-code">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyber-cyan" />
            Security Reports & Forensic Exports
          </h1>
          <p className="text-xs text-cyber-muted mt-1 font-sans">
            Formal incident compliance summaries, audit trail verification, and raw CSV forensic dataset downloads.
          </p>
        </div>

        {/* Download Summary Button */}
        <button
          onClick={downloadJsonSummary}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-cyan hover:bg-cyan-400 text-black font-bold text-xs shadow-cyan-glow transition-all"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Download Summary JSON</span>
        </button>
      </div>

      {/* Filter Options Card */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-lg space-y-4 text-xs">
        <h3 className="text-xs uppercase font-bold text-cyber-text tracking-wider flex items-center gap-2">
          <Filter className="w-4 h-4 text-cyber-cyan" />
          Report Scope & Parameters
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="text-cyber-muted block mb-1">Time Horizon:</label>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="w-full bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
            >
              <option value="1h">Last 1 Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </div>

          <div>
            <label className="text-cyber-muted block mb-1">Severity Filter (CSV Export):</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical Only</option>
              <option value="HIGH">High Only</option>
              <option value="MEDIUM">Medium Only</option>
            </select>
          </div>

          <div>
            <label className="text-cyber-muted block mb-1">Threat Vector (CSV Export):</label>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
            >
              <option value="">All Threat Types</option>
              <option value="SYN_FLOOD">SYN Flood</option>
              <option value="PORT_SCAN">Port Scan</option>
              <option value="SUSPICIOUS">Suspicious Activity</option>
            </select>
          </div>
        </div>

        {/* Direct CSV Download Buttons */}
        <div className="pt-3 border-t border-cyber-border/30 flex flex-wrap items-center gap-3">
          <a
            href={endpoints.getThreatsCsvUrl({
              time_range: timeRange,
              severity: severityFilter || undefined,
              threat_type: typeFilter || undefined,
            })}
            download
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyber-panel hover:bg-cyber-card border border-cyber-border/40 hover:border-cyber-cyan text-cyber-text hover:text-cyber-cyan transition-all text-xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Threat Records CSV</span>
          </a>

          <a
            href={endpoints.getIncidentsCsvUrl({
              severity: severityFilter || undefined,
              incident_type: typeFilter || undefined,
            })}
            download
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyber-panel hover:bg-cyber-card border border-cyber-border/40 hover:border-cyber-cyan text-cyber-text hover:text-cyber-cyan transition-all text-xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download Incident Audit CSV</span>
          </a>
        </div>
      </div>

      {/* Report Preview Panel */}
      {summary && (
        <div className="space-y-6 text-xs">
          {/* Executive Summary Card */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 border-b border-cyber-border/40 gap-2">
              <div>
                <span className="text-[10px] uppercase font-bold text-cyber-cyan tracking-widest">
                  Executive SOC Report Preview
                </span>
                <h2 className="text-lg font-bold text-white mt-0.5">
                  Network Security Assessment Summary
                </h2>
              </div>
              <span className="px-2.5 py-1 rounded bg-cyber-panel border border-cyber-border/40 text-cyber-muted text-[11px]">
                Period: {timeRange} ({new Date(summary.reporting_period.start_time).toLocaleDateString()} &mdash; Present)
              </span>
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-cyber-panel/50 p-4 rounded-xl border border-cyber-border/30">
                <span className="text-cyber-muted text-[11px]">Total Recorded Events:</span>
                <p className="text-2xl font-bold text-cyber-cyan mt-1">
                  {summary.total_recorded_events.toLocaleString()}
                </p>
              </div>

              <div className="bg-cyber-panel/50 p-4 rounded-xl border border-cyber-border/30">
                <span className="text-cyber-muted text-[11px]">Automated Containment Blocks:</span>
                <p className="text-2xl font-bold text-cyber-red mt-1">
                  {summary.total_blocks_recorded}
                </p>
              </div>

              <div className="bg-cyber-panel/50 p-4 rounded-xl border border-cyber-border/30">
                <span className="text-cyber-muted text-[11px]">Demonstration (Synthetic):</span>
                <p className="text-2xl font-bold text-cyber-amber mt-1">
                  {summary.event_source_counts.simulation}
                </p>
              </div>

              <div className="bg-cyber-panel/50 p-4 rounded-xl border border-cyber-border/30">
                <span className="text-cyber-muted text-[11px]">Live Sensor Detections:</span>
                <p className="text-2xl font-bold text-cyber-green mt-1">
                  {summary.event_source_counts.live}
                </p>
              </div>
            </div>

            {/* Distribution Breakdowns */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              {/* Threat Types Breakdown */}
              <div className="bg-cyber-panel/40 p-4 rounded-xl border border-cyber-border/20 space-y-2">
                <h4 className="font-bold text-cyber-text text-xs uppercase tracking-wider">
                  Threat Vector Distribution
                </h4>
                <div className="space-y-1.5">
                  {summary.threat_distribution.map((t, idx) => (
                    <div key={idx} className="flex items-center justify-between">
                      <span className="text-cyber-muted">{t.threat_type}:</span>
                      <span className="font-bold text-white">{t.cnt}</span>
                    </div>
                  ))}
                  {summary.threat_distribution.length === 0 && (
                    <p className="text-cyber-muted">No threats recorded in this window.</p>
                  )}
                </div>
              </div>

              {/* Severity Breakdown */}
              <div className="bg-cyber-panel/40 p-4 rounded-xl border border-cyber-border/20 space-y-2">
                <h4 className="font-bold text-cyber-text text-xs uppercase tracking-wider">
                  Severity Tier Breakdown
                </h4>
                <div className="space-y-1.5">
                  {summary.severity_distribution.map((s, idx) => (
                    <div key={idx} className="flex items-center justify-between">
                      <span className="text-cyber-muted">{s.severity}:</span>
                      <span className="font-bold text-white">{s.cnt}</span>
                    </div>
                  ))}
                  {summary.severity_distribution.length === 0 && (
                    <p className="text-cyber-muted">No events recorded in this window.</p>
                  )}
                </div>
              </div>
            </div>

            {/* Important Limitations & Educational Mandate */}
            <div className="mt-4 p-4 rounded-xl bg-cyber-bg border border-cyber-border/30 space-y-2">
              <h4 className="font-bold text-cyber-cyan text-xs uppercase flex items-center gap-1.5">
                <Info className="w-4 h-4" />
                Operational & Academic Disclaimers
              </h4>
              <ul className="list-disc pl-5 space-y-1 text-cyber-muted text-[11px] font-sans">
                {summary.important_limitations.map((lim, idx) => (
                  <li key={idx}>{lim}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;
