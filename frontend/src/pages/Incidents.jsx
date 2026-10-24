import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  History,
  Search,
  Filter,
  Download,
  CheckCircle,
  Eye,
  Shield,
  FileCheck,
  ChevronLeft,
  ChevronRight,
  Info,
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import { endpoints } from '../services/api';

const Incidents = () => {
  const navigate = useNavigate();

  const [incidents, setIncidents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(15);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(false);

  // Filters
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [reviewedFilter, setReviewedFilter] = useState('');

  // Selected incident for audit inspection
  const [selectedIncident, setSelectedIncident] = useState(null);

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const res = await endpoints.getIncidents({
        page,
        page_size: pageSize,
        search: search || undefined,
        severity: severityFilter || undefined,
        incident_type: typeFilter || undefined,
        reviewed: reviewedFilter || undefined,
      });
      setIncidents(res.data.incidents || []);
      setTotal(res.data.total || 0);
      setPages(res.data.pages || 1);
    } catch (err) {
      console.error('Failed to load incidents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [page, severityFilter, typeFilter, reviewedFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    fetchIncidents();
  };

  const handleToggleReviewed = async (incident) => {
    try {
      await endpoints.reviewIncident(incident.id, !incident.reviewed);
      await fetchIncidents();
      if (selectedIncident && selectedIncident.id === incident.id) {
        setSelectedIncident((prev) => ({ ...prev, reviewed: !prev.reviewed }));
      }
    } catch (err) {
      console.error('Failed to update review status:', err);
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono-code">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <History className="w-5 h-5 text-cyber-cyan" />
            Security Incident Audit Log
          </h1>
          <p className="text-xs text-cyber-muted mt-1 font-sans">
            Immutable, append-only operational audit trail for incident investigation and compliance verification.
          </p>
        </div>

        <a
          href={endpoints.getIncidentsCsvUrl({
            severity: severityFilter || undefined,
            incident_type: typeFilter || undefined,
            reviewed: reviewedFilter || undefined,
          })}
          download
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyber-card border border-cyber-border/40 hover:border-cyber-cyan text-xs text-cyber-text hover:text-cyber-cyan transition-all shadow-sm"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export Audit CSV</span>
        </a>
      </div>

      {/* Filter Bar */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 shadow-lg flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 text-xs">
        <form onSubmit={handleSearchSubmit} className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted" />
          <input
            type="text"
            placeholder="Search by IP or Incident ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-cyber-panel border border-cyber-border/40 rounded-lg pl-9 pr-4 py-2 text-cyber-text placeholder:text-cyber-muted/60 focus:outline-none focus:border-cyber-cyan"
          />
        </form>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
            className="bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
          >
            <option value="">All Incident Types</option>
            <option value="SYN_FLOOD">SYN Flood</option>
            <option value="PORT_SCAN">Port Scan</option>
            <option value="MANUAL_UNBLOCK">Manual Unblock</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
            className="bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
          </select>

          <select
            value={reviewedFilter}
            onChange={(e) => { setReviewedFilter(e.target.value); setPage(1); }}
            className="bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
          >
            <option value="">All Review Statuses</option>
            <option value="false">Pending Analyst Review</option>
            <option value="true">Analyst Reviewed</option>
          </select>
        </div>
      </div>

      {/* Main Incident Audit Table */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl shadow-lg overflow-hidden text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-cyber-border/40 text-cyber-muted uppercase text-[11px] tracking-wider bg-cyber-panel/50">
                <th className="py-3 px-4 font-semibold">Incident ID</th>
                <th className="py-3 px-4 font-semibold">Timestamp</th>
                <th className="py-3 px-4 font-semibold">Incident Type</th>
                <th className="py-3 px-4 font-semibold">Source IP</th>
                <th className="py-3 px-4 font-semibold">Severity</th>
                <th className="py-3 px-4 font-semibold">Action Status</th>
                <th className="py-3 px-4 font-semibold">Source Origin</th>
                <th className="py-3 px-4 font-semibold">Analyst Review</th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/20">
              {incidents.length === 0 ? (
                <tr>
                  <td colSpan="9" className="py-12 text-center text-cyber-muted">
                    No incidents recorded. Audit log is clean.
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-cyber-panel/50 transition-colors">
                    <td className="py-3 px-4 font-bold text-cyber-cyan whitespace-nowrap">
                      INC-{String(inc.id).padStart(4, '0')}
                    </td>
                    <td className="py-3 px-4 text-cyber-muted whitespace-nowrap">
                      {new Date(inc.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-3 px-4 text-white font-semibold whitespace-nowrap">
                      {inc.incident_type}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <button
                        onClick={() => navigate(`/intelligence?ip=${inc.src_ip}`)}
                        className="text-cyber-cyan hover:underline font-bold"
                      >
                        {inc.src_ip}
                      </button>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-cyber-panel border border-cyber-border/40 text-cyber-text text-[10px] uppercase font-semibold">
                        {inc.action_status || 'completed'}
                      </span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-cyber-panel border border-cyber-border/40 text-cyber-cyan text-[10px] uppercase font-bold">
                        {inc.event_source === 'simulation' ? 'DEMO' : 'LIVE'}
                      </span>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <button
                        onClick={() => handleToggleReviewed(inc)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] font-semibold border transition-all ${
                          inc.reviewed
                            ? 'bg-cyber-green/10 text-cyber-green border-cyber-green/40 hover:bg-cyber-green/20'
                            : 'bg-cyber-amber/10 text-cyber-amber border-cyber-amber/40 hover:bg-cyber-amber/20'
                        }`}
                      >
                        <CheckCircle className="w-3 h-3" />
                        <span>{inc.reviewed ? 'Reviewed' : 'Pending'}</span>
                      </button>
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => setSelectedIncident(inc)}
                        className="px-2.5 py-1 rounded bg-cyber-panel hover:bg-cyber-cyan hover:text-black border border-cyber-border/40 text-cyber-text transition-all"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="p-4 border-t border-cyber-border/30 flex items-center justify-between text-xs text-cyber-muted">
          <div>
            Showing {incidents.length} of {total} incidents (Page {page} of {pages})
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1.5 rounded bg-cyber-panel border border-cyber-border/40 disabled:opacity-30 hover:border-cyber-cyan transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-2 font-bold text-cyber-cyan">{page}</span>
            <button
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
              disabled={page >= pages}
              className="p-1.5 rounded bg-cyber-panel border border-cyber-border/40 disabled:opacity-30 hover:border-cyber-cyan transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Incident Inspection Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="relative w-full max-w-lg bg-cyber-card border border-cyber-border rounded-xl shadow-2xl p-6">
            <div className="flex items-center justify-between pb-3 border-b border-cyber-border/40 mb-4">
              <h3 className="text-base font-bold text-cyber-text flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-cyber-cyan" />
                Audit Record INC-{String(selectedIncident.id).padStart(4, '0')}
              </h3>
              <button
                onClick={() => setSelectedIncident(null)}
                className="text-cyber-muted hover:text-white"
              >
                &times;
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-3 bg-cyber-panel/60 p-3 rounded-lg border border-cyber-border/30">
                <div>
                  <span className="text-cyber-muted">Timestamp:</span>
                  <p className="text-white mt-0.5">{new Date(selectedIncident.timestamp).toUTCString()}</p>
                </div>
                <div>
                  <span className="text-cyber-muted">Severity:</span>
                  <div className="mt-0.5">
                    <SeverityBadge severity={selectedIncident.severity} />
                  </div>
                </div>
                <div>
                  <span className="text-cyber-muted">Source IP:</span>
                  <p className="text-cyber-cyan font-bold mt-0.5">{selectedIncident.src_ip}</p>
                </div>
                <div>
                  <span className="text-cyber-muted">Threat ID:</span>
                  <p className="text-white mt-0.5">#{selectedIncident.threat_id || 'N/A'}</p>
                </div>
              </div>

              <div>
                <span className="text-cyber-muted block mb-1">Details & Technical Parameters:</span>
                <pre className="p-3 bg-cyber-bg border border-cyber-border/30 rounded-lg text-cyber-text text-[11px] overflow-x-auto whitespace-pre-wrap font-mono-code">
                  {selectedIncident.details || 'No extended payload metadata logged.'}
                </pre>
              </div>

              <div className="p-3 bg-cyber-panel/40 border border-cyber-border/20 rounded-lg flex items-center justify-between">
                <span className="text-cyber-muted">Compliance Review Status:</span>
                <button
                  onClick={() => handleToggleReviewed(selectedIncident)}
                  className={`px-3 py-1 rounded text-xs font-semibold border ${
                    selectedIncident.reviewed
                      ? 'bg-cyber-green/10 text-cyber-green border-cyber-green/40'
                      : 'bg-cyber-amber/10 text-cyber-amber border-cyber-amber/40'
                  }`}
                >
                  {selectedIncident.reviewed ? 'Marked Reviewed' : 'Mark as Reviewed'}
                </button>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3 pt-3 border-t border-cyber-border/30">
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-2 rounded-lg bg-cyber-panel border border-cyber-border/40 text-cyber-muted hover:text-white"
              >
                Close Audit Entry
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Incidents;
