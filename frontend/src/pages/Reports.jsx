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
  BarChart3,
  FileSpreadsheet,
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
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-bluegrey animate-pulse" />
            <span className="text-[10px] uppercase font-bold text-forest tracking-widest font-sans">
              Forensic Intelligence & Compliance
            </span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-ink flex items-center gap-2">
            <FileText className="w-5 h-5 text-bluegrey-ink" />
            Security Reports & Forensic Exports
          </h1>
          <p className="text-xs text-muted mt-1 font-sans">
            Formal incident compliance summaries, audit trail verification, and raw CSV forensic dataset downloads.
          </p>
        </div>

        {/* Download Summary Button */}
        <button
          onClick={downloadJsonSummary}
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-forest hover:bg-forest/90 text-white font-bold text-xs shadow-aurora-btn transition-all font-sans"
        >
          <Download className="w-4 h-4" />
          <span>Download Summary JSON</span>
        </button>
      </div>

      {/* Filter Options Card */}
      <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft space-y-4 text-xs">
        <h3 className="text-xs uppercase font-bold text-ink tracking-wider flex items-center gap-2 font-sans">
          <Filter className="w-4 h-4 text-forest" />
          Report Scope & Parameters
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div>
            <label className="text-muted block mb-1 font-sans text-[11px]">Time Horizon:</label>
            <select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
            >
              <option value="1h">Last 1 Hour</option>
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </div>

          <div>
            <label className="text-muted block mb-1 font-sans text-[11px]">Severity Filter (CSV Export):</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical Only</option>
              <option value="HIGH">High Only</option>
              <option value="MEDIUM">Medium Only</option>
            </select>
          </div>

          <div>
            <label className="text-muted block mb-1 font-sans text-[11px]">Threat Vector (CSV Export):</label>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
            >
              <option value="">All Threat Types</option>
              <option value="SYN_FLOOD">SYN Flood</option>
              <option value="PORT_SCAN">Port Scan</option>
              <option value="SUSPICIOUS">Suspicious Activity</option>
            </select>
          </div>
        </div>

        {/* Direct CSV Download Buttons */}
        <div className="pt-3 border-t border-bluegrey/30 flex flex-wrap items-center gap-3">
          <a
            href={endpoints.getThreatsCsvUrl({
              time_range: timeRange,
              severity: severityFilter || undefined,
              threat_type: typeFilter || undefined,
            })}
            download
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-mist/80 hover:bg-surface border border-bluegrey/40 hover:border-forest/50 text-ink hover:text-forest transition-all text-xs font-sans font-medium"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-forest" />
            <span>Download Threat Records CSV</span>
          </a>

          <a
            href={endpoints.getIncidentsCsvUrl({
              severity: severityFilter || undefined,
              incident_type: typeFilter || undefined,
            })}
            download
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-mist/80 hover:bg-surface border border-bluegrey/40 hover:border-bluegrey/50 text-ink hover:text-bluegrey-ink transition-all text-xs font-sans font-medium"
          >
            <Download className="w-3.5 h-3.5 text-bluegrey-ink" />
            <span>Download Incident Audit CSV</span>
          </a>
        </div>
      </div>

      {/* Report Preview Panel */}
      {summary && (
        <div className="space-y-6 text-xs">
          {/* Executive Summary Card */}
          <div className="bg-surface border border-bluegrey/40 rounded-xl p-6 shadow-soft space-y-5 relative overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-bluegrey via-forest to-bluegrey" />

            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 border-b border-bluegrey/40 gap-2">
              <div>
                <span className="text-[10px] uppercase font-bold text-forest tracking-widest font-sans">
                  Executive SOC Report Preview
                </span>
                <h2 className="text-lg font-bold text-ink mt-0.5">
                  Network Security Assessment Summary
                </h2>
              </div>
              <span className="px-3 py-1 rounded-lg bg-mist/70 border border-bluegrey/40 text-muted text-[11px] font-sans">
                Period: <span className="text-forest font-bold">{timeRange}</span> ({new Date(summary.reporting_period.start_time).toLocaleDateString()} &mdash; Present)
              </span>
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-mist/60 p-4 rounded-xl border border-bluegrey/30 relative">
                <span className="text-muted text-[11px] font-sans">Total Recorded Events:</span>
                <p className="text-2xl font-bold text-bluegrey-ink mt-1">
                  {summary.total_recorded_events.toLocaleString()}
                </p>
              </div>

              <div className="bg-mist/60 p-4 rounded-xl border border-bluegrey/30 relative">
                <span className="text-muted text-[11px] font-sans">Automated Blocks:</span>
                <p className="text-2xl font-bold text-bad-ink mt-1">
                  {summary.total_blocks_recorded}
                </p>
              </div>

              <div className="bg-mist/60 p-4 rounded-xl border border-bluegrey/30 relative">
                <span className="text-muted text-[11px] font-sans">Demonstration (Synthetic):</span>
                <p className="text-2xl font-bold text-amber-ink mt-1">
                  {summary.event_source_counts.simulation}
                </p>
              </div>

              <div className="bg-mist/60 p-4 rounded-xl border border-bluegrey/30 relative">
                <span className="text-muted text-[11px] font-sans">Live Sensor Detections:</span>
                <p className="text-2xl font-bold text-good-ink mt-1">
                  {summary.event_source_counts.live}
                </p>
              </div>
            </div>

            {/* Distribution Breakdowns */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              {/* Threat Types Breakdown */}
              <div className="bg-mist/40 p-4 rounded-xl border border-bluegrey/30 space-y-3">
                <h4 className="font-bold text-ink text-xs uppercase tracking-wider font-sans flex items-center justify-between">
                  <span>Threat Vector Distribution</span>
                  <BarChart3 className="w-3.5 h-3.5 text-forest" />
                </h4>
                <div className="space-y-2">
                  {summary.threat_distribution.map((t, idx) => {
                    const totalThreats = summary.total_recorded_events || 1;
                    const pct = Math.min(100, Math.round((t.cnt / totalThreats) * 100));
                    return (
                      <div key={idx} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-muted">{t.threat_type}:</span>
                          <span className="font-bold text-ink">{t.cnt} ({pct}%)</span>
                        </div>
                        <div className="w-full h-1.5 bg-mist rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-bluegrey to-forest rounded-full"
                            style={{ width: `${Math.max(5, pct)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                  {summary.threat_distribution.length === 0 && (
                    <p className="text-muted font-sans">No threats recorded in this window.</p>
                  )}
                </div>
              </div>

              {/* Severity Breakdown */}
              <div className="bg-mist/40 p-4 rounded-xl border border-bluegrey/30 space-y-3">
                <h4 className="font-bold text-ink text-xs uppercase tracking-wider font-sans flex items-center justify-between">
                  <span>Severity Tier Breakdown</span>
                  <ShieldAlert className="w-3.5 h-3.5 text-bad-ink" />
                </h4>
                <div className="space-y-2">
                  {summary.severity_distribution.map((s, idx) => {
                    const totalEvts = summary.total_recorded_events || 1;
                    const pct = Math.min(100, Math.round((s.cnt / totalEvts) * 100));
                    const color = s.severity === 'CRITICAL' ? 'bg-bad' : s.severity === 'HIGH' ? 'bg-amber' : 'bg-bluegrey';
                    return (
                      <div key={idx} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-muted">{s.severity}:</span>
                          <span className="font-bold text-ink">{s.cnt} ({pct}%)</span>
                        </div>
                        <div className="w-full h-1.5 bg-mist rounded-full overflow-hidden">
                          <div
                            className={`h-full ${color} rounded-full`}
                            style={{ width: `${Math.max(5, pct)}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                  {summary.severity_distribution.length === 0 && (
                    <p className="text-muted font-sans">No events recorded in this window.</p>
                  )}
                </div>
              </div>
            </div>

            {/* Important Limitations & Educational Mandate */}
            <div className="mt-4 p-4 rounded-xl bg-mist/80 border border-bluegrey/30 space-y-2">
              <h4 className="font-bold text-forest text-xs uppercase flex items-center gap-2 font-sans">
                <Info className="w-4 h-4 text-forest" />
                Operational & Academic Disclaimers
              </h4>
              <ul className="list-disc pl-5 space-y-1 text-muted text-[11px] font-sans leading-relaxed">
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
