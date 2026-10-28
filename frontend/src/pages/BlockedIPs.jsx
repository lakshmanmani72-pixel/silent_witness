import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Ban,
  Search,
  Filter,
  ShieldAlert,
  Clock,
  Unlock,
  AlertTriangle,
  RefreshCw,
  Info,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import ConfirmationModal from '../components/ConfirmationModal';
import { endpoints } from '../services/api';

const BlockedIPs = () => {
  const navigate = useNavigate();

  const [blocks, setBlocks] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  // Filters
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  // Unblock confirmation modal
  const [targetBlock, setTargetBlock] = useState(null);
  const [isUnblockModalOpen, setIsUnblockModalOpen] = useState(false);

  // Live countdown ticker
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const fetchBlocks = async () => {
    try {
      setLoading(true);
      const res = await endpoints.getBlockedIPs({
        search: search || undefined,
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
      });
      setBlocks(res.data.blocked_ips || []);
      setTotal(res.data.total || 0);
    } catch (err) {
      console.error('Failed to load blocked IPs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBlocks();
    const interval = setInterval(fetchBlocks, 5000);
    return () => clearInterval(interval);
  }, [search, statusFilter, severityFilter]);

  const handleConfirmUnblock = async () => {
    if (!targetBlock) return;
    try {
      await endpoints.unblockIP(targetBlock.id, 'Manual operator unblock via dashboard');
      await fetchBlocks();
    } catch (err) {
      console.error('Failed to unblock IP:', err);
    }
  };

  const getRemainingTime = (expiresAt) => {
    if (!expiresAt) return 'Permanent';
    const diff = new Date(expiresAt).getTime() - now;
    if (diff <= 0) return 'Expired';
    const mins = Math.floor(diff / 60000);
    const secs = Math.floor((diff % 60000) / 1000);
    return `${mins}m ${secs < 10 ? '0' : ''}${secs}s`;
  };

  // KPI calculations derived directly from live state
  const activeCount = blocks.filter((b) => b.status === 'active').length;
  const dryRunCount = blocks.filter((b) => b.dry_run).length;
  const criticalCount = blocks.filter((b) => b.severity === 'CRITICAL').length;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono-code">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-bad animate-ping" />
            <span className="text-[10px] uppercase font-bold text-forest tracking-widest font-sans">
              Defensive Firewall Response
            </span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-ink flex items-center gap-2">
            <Ban className="w-5 h-5 text-bad-ink" />
            Automated Response & Blocked IPs
          </h1>
          <p className="text-xs text-muted mt-1 font-sans">
            Managed containment list. Active rules are temporarily enforced to mitigate high-severity attacks.
          </p>
        </div>

        <button
          onClick={fetchBlocks}
          className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-surface border border-bluegrey/40 hover:border-forest/50 text-xs text-ink hover:text-forest transition-all shadow-soft"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-forest' : ''}`} />
          <span className="font-sans font-medium">Refresh Containment</span>
        </button>
      </div>

      {/* Mini KPI Bento Strip */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 shadow-soft relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-bluegrey/60 to-transparent" />
          <span className="text-[10px] uppercase font-bold text-muted tracking-wider block font-sans">
            Total Rules
          </span>
          <p className="text-2xl font-bold text-ink mt-1">{total}</p>
        </div>

        <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 shadow-soft relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-bad/80 to-transparent" />
          <span className="text-[10px] uppercase font-bold text-muted tracking-wider block font-sans">
            Active Containments
          </span>
          <p className="text-2xl font-bold text-bad-ink mt-1">{activeCount}</p>
        </div>

        <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 shadow-soft relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-forest/80 to-transparent" />
          <span className="text-[10px] uppercase font-bold text-muted tracking-wider block font-sans">
            Simulated / Dry-Run
          </span>
          <p className="text-2xl font-bold text-forest mt-1">{dryRunCount}</p>
        </div>

        <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 shadow-soft relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-amber/80 to-transparent" />
          <span className="text-[10px] uppercase font-bold text-muted tracking-wider block font-sans">
            Critical Severity
          </span>
          <p className="text-2xl font-bold text-amber-ink mt-1">{criticalCount}</p>
        </div>
      </div>

      {/* Safety Mode Banner */}
      <div className="p-4 bg-sage/50 border border-forest/30 rounded-xl flex items-start gap-3 shadow-soft">
        <div className="w-8 h-8 rounded-lg bg-forest/10 border border-forest/30 flex items-center justify-center shrink-0 mt-0.5">
          <Info className="w-4 h-4 text-forest" />
        </div>
        <div className="text-xs font-sans text-muted leading-relaxed">
          <p className="font-semibold text-ink font-mono-code mb-0.5 flex items-center gap-2">
            Defensive Response Engine: Safe Dry-Run Active
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-forest/15 text-forest border border-forest/30">
              SAFE VIVA MODE
            </span>
          </p>
          Simulated blocking is applied by default. Real host iptables modification requires explicit administrator toggle in settings and valid platform support. Blocks automatically expire after the configured containment duration.
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-surface border border-bluegrey/40 rounded-xl p-4 shadow-soft flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 text-xs">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="text"
            placeholder="Search by IP address (e.g., 192.168.1.105)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg pl-9 pr-4 py-2 text-ink placeholder:text-muted/50 focus:outline-none focus:border-bluegrey/40 transition-colors"
          />
        </div>

        <div className="flex items-center gap-2.5">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
          >
            <option value="">All Statuses</option>
            <option value="active">Active Only</option>
            <option value="unblocked">Unblocked</option>
            <option value="expired">Expired</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-surface border border-bluegrey/40 rounded-xl shadow-soft overflow-hidden text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-bluegrey/40 text-muted uppercase text-[10px] tracking-wider bg-mist/40 font-sans">
                <th className="py-3.5 px-4 font-semibold">Target IP</th>
                <th className="py-3.5 px-4 font-semibold">Trigger Threat</th>
                <th className="py-3.5 px-4 font-semibold">Severity</th>
                <th className="py-3.5 px-4 font-semibold">Enforced Mode</th>
                <th className="py-3.5 px-4 font-semibold">Block Timestamp</th>
                <th className="py-3.5 px-4 font-semibold">Remaining Time</th>
                <th className="py-3.5 px-4 font-semibold">Status</th>
                <th className="py-3.5 px-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bluegrey/20">
              {blocks.length === 0 ? (
                <tr>
                  <td colSpan="8" className="py-14 text-center text-muted font-sans">
                    <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-forest/50" />
                    No active or historical containment records matching current criteria.
                  </td>
                </tr>
              ) : (
                blocks.map((b) => {
                  const isActive = b.status === 'active';
                  const remaining = getRemainingTime(b.expires_at);
                  const isExpiring = isActive && remaining !== 'Expired';

                  return (
                    <tr key={b.id} className="hover:bg-sage/40 transition-colors">
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <button
                          onClick={() => navigate(`/intelligence?ip=${b.ip}`)}
                          className="font-bold text-forest hover:underline tracking-tight"
                        >
                          {b.ip}
                        </button>
                      </td>

                      <td className="py-3.5 px-4 text-ink whitespace-nowrap font-medium">
                        {b.threat_type || 'Attack Vector'}
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <SeverityBadge severity={b.severity} />
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          b.dry_run
                            ? 'bg-forest/15 text-forest border border-forest/30'
                            : 'bg-bad/15 text-bad-ink border border-bad/30'
                        }`}>
                          {b.dry_run ? 'DRY-RUN' : 'REAL IPTABLES'}
                        </span>
                      </td>

                      <td className="py-3.5 px-4 text-muted whitespace-nowrap">
                        {new Date(b.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className={`flex items-center gap-1.5 font-bold ${
                          isExpiring ? 'text-amber-ink animate-pulse' : 'text-muted'
                        }`}>
                          <Clock className="w-3.5 h-3.5 text-muted" />
                          {remaining}
                        </span>
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          isActive
                            ? 'bg-bad/15 text-bad-ink border border-bad/30'
                            : 'bg-mist/60 text-muted border border-bluegrey/30'
                        }`}>
                          {b.status}
                        </span>
                      </td>

                      <td className="py-3.5 px-4 text-right whitespace-nowrap">
                        {isActive ? (
                          <button
                            onClick={() => {
                              setTargetBlock(b);
                              setIsUnblockModalOpen(true);
                            }}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-mist/80 hover:bg-forest hover:text-white border border-bluegrey/40 hover:border-forest text-forest font-semibold transition-all shadow-sm"
                          >
                            <Unlock className="w-3 h-3" />
                            <span>Unblock</span>
                          </button>
                        ) : (
                          <span className="text-muted/40 text-[11px] font-sans">Deactivated</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Unblock Confirmation Modal */}
      <ConfirmationModal
        isOpen={isUnblockModalOpen}
        title="Confirm Manual Unblock"
        message={`Are you sure you want to deactivate the containment block for IP ${targetBlock?.ip}? This action will be recorded in the security audit log.`}
        confirmText="Confirm Unblock"
        isDanger={false}
        onConfirm={handleConfirmUnblock}
        onClose={() => {
          setIsUnblockModalOpen(false);
          setTargetBlock(null);
        }}
      />
    </div>
  );
};

export default BlockedIPs;
