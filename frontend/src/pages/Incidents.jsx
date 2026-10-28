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
  Clock,
  ExternalLink,
  X,
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
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-forest animate-pulse" />
            <span className="text-[10px] uppercase font-bold text-forest tracking-widest font-sans">
              Compliance & Forensics
            </span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-ink flex items-center gap-2">
            <History className="w-5 h-5 text-forest" />
            Security Incident Audit Log
          </h1>
          <p className="text-xs text-muted mt-1 font-sans">
            Immutable, append-only operational audit trail for incident investigation, threat forensics, and compliance.
          </p>
        </div>

        <a
          href={endpoints.getIncidentsCsvUrl({
            severity: severityFilter || undefined,
            incident_type: typeFilter || undefined,
            reviewed: reviewedFilter || undefined,
          })}
          download
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-surface border border-bluegrey/40 hover:border-forest/50 text-xs text-ink hover:text-forest transition-all shadow-soft font-sans font-medium"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Export Audit CSV</span>
        </a>
      </div>

      {/* Filter Bar */}
      <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 shadow-soft flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 text-xs">
        <form onSubmit={handleSearchSubmit} className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            placeholder="Search by IP or Incident ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg pl-9 pr-4 py-2 text-ink placeholder:text-muted/50 focus:outline-none focus:border-bluegrey/40 transition-colors"
          />
        </form>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setPage(1); }}
            className="bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
          >
            <option value="">All Incident Types</option>
            <option value="SYN_FLOOD">SYN Flood</option>
            <option value="PORT_SCAN">Port Scan</option>
            <option value="MANUAL_UNBLOCK">Manual Unblock</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
            className="bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
          </select>

          <select
            value={reviewedFilter}
            onChange={(e) => { setReviewedFilter(e.target.value); setPage(1); }}
            className="bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
          >
            <option value="">All Review Statuses</option>
            <option value="false">Pending Analyst Review</option>
            <option value="true">Analyst Reviewed</option>
          </select>
        </div>
      </div>

      {/* Main Incident Audit Table */}
      <div className="bg-surface border border-bluegrey/40 rounded-xl shadow-soft overflow-hidden text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-bluegrey/40 text-muted uppercase text-[10px] tracking-wider bg-mist/40 font-sans">
                <th className="py-3.5 px-4 font-semibold">Incident ID</th>
                <th className="py-3.5 px-4 font-semibold">Timestamp</th>
                <th className="py-3.5 px-4 font-semibold">Incident Type</th>
                <th className="py-3.5 px-4 font-semibold">Source IP</th>
                <th className="py-3.5 px-4 font-semibold">Severity</th>
                <th className="py-3.5 px-4 font-semibold">Action Status</th>
                <th className="py-3.5 px-4 font-semibold">Source Origin</th>
                <th className="py-3.5 px-4 font-semibold">Analyst Review</th>
                <th className="py-3.5 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bluegrey/20">
              {incidents.length === 0 ? (
                <tr>
                  <td colSpan="9" className="py-14 text-center text-muted font-sans">
                    <FileCheck className="w-8 h-8 mx-auto mb-2 text-forest/50" />
                    No incidents recorded. Audit log is clean.
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-sage/40 transition-colors">
                    <td className="py-3.5 px-4 font-bold text-bluegrey-ink whitespace-nowrap">
                      INC-{String(inc.id).padStart(4, '0')}
                    </td>
                    <td className="py-3.5 px-4 text-muted whitespace-nowrap">
                      {new Date(inc.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="py-3.5 px-4 text-ink font-medium whitespace-nowrap">
                      {inc.incident_type}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <button
                        onClick={() => navigate(`/intelligence?ip=${inc.src_ip}`)}
                        className="text-forest hover:underline font-bold"
                      >
                        {inc.src_ip}
                      </button>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-mist/60 border border-bluegrey/40 text-ink text-[10px] uppercase font-semibold">
                        {inc.action_status || 'completed'}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-mist/60 border border-bluegrey/40 text-forest text-[10px] uppercase font-bold">
                        {inc.event_source === 'simulation' ? 'DEMO' : 'LIVE'}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <button
                        onClick={() => handleToggleReviewed(inc)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10px] font-semibold border transition-all ${
                          inc.reviewed
                            ? 'bg-good/15 text-good-ink border-good/40 hover:bg-good/25'
                            : 'bg-amber/15 text-amber-ink border-amber/40 hover:bg-amber/25'
                        }`}
                      >
                        <CheckCircle className="w-3 h-3" />
                        <span>{inc.reviewed ? 'Reviewed' : 'Pending'}</span>
                      </button>
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => setSelectedIncident(inc)}
                        className="px-2.5 py-1 rounded-lg bg-mist/80 hover:bg-forest hover:text-white border border-bluegrey/40 text-ink transition-all font-sans font-medium"
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
        <div className="p-4 border-t border-bluegrey/30 flex items-center justify-between text-xs text-muted font-sans">
          <div>
            Showing <span className="font-bold text-ink">{incidents.length}</span> of <span className="font-bold text-ink">{total}</span> incidents (Page {page} of {pages})
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1.5 rounded-lg bg-mist/70 border border-bluegrey/40 disabled:opacity-30 hover:border-forest transition-colors"
            >
              <ChevronLeft className="w-4 h-4 text-ink" />
            </button>
            <span className="px-2 font-bold text-forest font-mono-code">{page}</span>
            <button
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
              disabled={page >= pages}
              className="p-1.5 rounded-lg bg-mist/70 border border-bluegrey/40 disabled:opacity-30 hover:border-forest transition-colors"
            >
              <ChevronRight className="w-4 h-4 text-ink" />
            </button>
          </div>
        </div>
      </div>

      {/* Incident Inspection Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-ink/40 animate-fadeIn">
          <div className="relative w-full max-w-lg bg-surface border border-bluegrey/40 rounded-2xl shadow-soft p-6 overflow-hidden">
            <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-bluegrey via-forest to-bluegrey" />

            <div className="flex items-center justify-between pb-3 border-b border-bluegrey/40 mb-4">
              <h3 className="text-base font-bold text-ink flex items-center gap-2">
                <FileCheck className="w-4 h-4 text-forest" />
                Audit Record INC-{String(selectedIncident.id).padStart(4, '0')}
              </h3>
              <button
                onClick={() => setSelectedIncident(null)}
                className="w-7 h-7 rounded-lg bg-mist/60 border border-bluegrey/40 text-muted hover:text-ink flex items-center justify-center transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3.5 text-xs">
              <div className="grid grid-cols-2 gap-3 bg-mist/60 p-3.5 rounded-xl border border-bluegrey/30">
                <div>
                  <span className="text-muted font-sans text-[11px]">Timestamp:</span>
                  <p className="text-ink mt-0.5">{new Date(selectedIncident.timestamp).toUTCString()}</p>
                </div>
                <div>
                  <span className="text-muted font-sans text-[11px]">Severity:</span>
                  <div className="mt-0.5">
                    <SeverityBadge severity={selectedIncident.severity} />
                  </div>
                </div>
                <div>
                  <span className="text-muted font-sans text-[11px]">Source IP:</span>
                  <p className="text-forest font-bold mt-0.5">{selectedIncident.src_ip}</p>
                </div>
                <div>
                  <span className="text-muted font-sans text-[11px]">Threat ID:</span>
                  <p className="text-ink mt-0.5">#{selectedIncident.threat_id || 'N/A'}</p>
                </div>
              </div>

              <div>
                <span className="text-muted block mb-1 font-sans text-[11px]">Details & Technical Parameters:</span>
                <pre className="p-3.5 bg-mist border border-bluegrey/30 rounded-xl text-ink text-[11px] overflow-x-auto whitespace-pre-wrap font-mono-code">
                  {selectedIncident.details || 'No extended payload metadata logged.'}
                </pre>
              </div>

              <div className="p-3.5 bg-sage/50 border border-bluegrey/30 rounded-xl flex items-center justify-between font-sans">
                <span className="text-muted text-xs">Compliance Review Status:</span>
                <button
                  onClick={() => handleToggleReviewed(selectedIncident)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                    selectedIncident.reviewed
                      ? 'bg-good/15 text-good-ink border-good/40 hover:bg-good/25'
                      : 'bg-amber/15 text-amber-ink border-amber/40 hover:bg-amber/25'
                  }`}
                >
                  {selectedIncident.reviewed ? 'Marked Reviewed' : 'Mark as Reviewed'}
                </button>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3 pt-3 border-t border-bluegrey/40 font-sans">
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-2 rounded-lg bg-mist/80 border border-bluegrey/40 text-muted hover:text-ink transition-colors text-xs"
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
