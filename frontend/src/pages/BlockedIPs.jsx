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

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono-code">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Ban className="w-5 h-5 text-cyber-red" />
            Automated Response & Blocked IPs
          </h1>
          <p className="text-xs text-cyber-muted mt-1 font-sans">
            Managed containment list. Active rules are temporarily enforced to mitigate high-severity attacks.
          </p>
        </div>

        <button
          onClick={fetchBlocks}
          className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyber-card border border-cyber-border/40 hover:border-cyber-cyan text-xs text-cyber-text transition-all"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyber-cyan' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Safety Mode Banner */}
      <div className="p-4 bg-cyber-card border border-cyber-border/40 rounded-xl flex items-start gap-3">
        <Info className="w-5 h-5 text-cyber-cyan shrink-0 mt-0.5" />
        <div className="text-xs font-sans text-cyber-muted leading-relaxed">
          <p className="font-semibold text-cyber-text font-mono-code mb-0.5">
            Defensive Response Engine: Safe Dry-Run Active
          </p>
          Simulated blocking is applied by default. Real Linux iptables modification requires explicit administrator toggle in settings and valid platform support. Blocks automatically expire after the configured containment duration.
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 shadow-lg flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 text-xs">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted" />
          <input
            type="text"
            placeholder="Search by IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-cyber-panel border border-cyber-border/40 rounded-lg pl-9 pr-4 py-2 text-cyber-text placeholder:text-cyber-muted/60 focus:outline-none focus:border-cyber-cyan"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
          >
            <option value="">All Statuses</option>
            <option value="active">Active</option>
            <option value="unblocked">Unblocked</option>
            <option value="expired">Expired</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-cyber-panel border border-cyber-border/40 rounded-lg px-3 py-2 text-cyber-text focus:outline-none focus:border-cyber-cyan"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-cyber-card border border-cyber-border rounded-xl shadow-lg overflow-hidden text-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-cyber-border/40 text-cyber-muted uppercase text-[11px] tracking-wider bg-cyber-panel/50">
                <th className="py-3 px-4 font-semibold">Target IP</th>
                <th className="py-3 px-4 font-semibold">Trigger Threat</th>
                <th className="py-3 px-4 font-semibold">Severity</th>
                <th className="py-3 px-4 font-semibold">Enforced Mode</th>
                <th className="py-3 px-4 font-semibold">Block Timestamp</th>
                <th className="py-3 px-4 font-semibold">Remaining Time</th>
                <th className="py-3 px-4 font-semibold">Status</th>
                <th className="py-3 px-4 font-semibold text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/20">
              {blocks.length === 0 ? (
                <tr>
                  <td colSpan="8" className="py-12 text-center text-cyber-muted">
                    No active or historical blocked IP records found.
                  </td>
                </tr>
              ) : (
                blocks.map((b) => {
                  const isActive = b.status === 'active';
                  const remaining = getRemainingTime(b.expires_at);
                  const isExpiring = isActive && remaining !== 'Expired';

                  return (
                    <tr key={b.id} className="hover:bg-cyber-panel/50 transition-colors">
                      <td className="py-3 px-4 whitespace-nowrap">
                        <button
                          onClick={() => navigate(`/intelligence?ip=${b.ip}`)}
                          className="font-bold text-cyber-cyan hover:underline"
                        >
                          {b.ip}
                        </button>
                      </td>

                      <td className="py-3 px-4 text-cyber-text whitespace-nowrap font-semibold">
                        {b.threat_type || 'Attack Vector'}
                      </td>

                      <td className="py-3 px-4 whitespace-nowrap">
                        <SeverityBadge severity={b.severity} />
                      </td>

                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          b.dry_run
                            ? 'bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30'
                            : 'bg-red-500/10 text-cyber-red border border-cyber-red/30'
                        }`}>
                          {b.dry_run ? 'DRY-RUN / SIMULATED' : 'REAL IPTABLES'}
                        </span>
                      </td>

                      <td className="py-3 px-4 text-cyber-muted whitespace-nowrap">
                        {new Date(b.timestamp).toLocaleTimeString()}
                      </td>

                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`flex items-center gap-1.5 font-bold ${
                          isExpiring ? 'text-cyber-amber animate-pulse' : 'text-cyber-muted'
                        }`}>
                          <Clock className="w-3.5 h-3.5" />
                          {remaining}
                        </span>
                      </td>

                      <td className="py-3 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          isActive
                            ? 'bg-red-500/10 text-cyber-red border border-cyber-red/30'
                            : 'bg-cyber-panel text-cyber-muted border border-cyber-border/30'
                        }`}>
                          {b.status}
                        </span>
                      </td>

                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        {isActive ? (
                          <button
                            onClick={() => {
                              setTargetBlock(b);
                              setIsUnblockModalOpen(true);
                            }}
                            className="inline-flex items-center gap-1 px-3 py-1 rounded bg-cyber-panel hover:bg-cyber-green hover:text-black border border-cyber-border/40 text-cyber-green font-semibold transition-all shadow-sm"
                          >
                            <Unlock className="w-3 h-3" />
                            <span>Unblock</span>
                          </button>
                        ) : (
                          <span className="text-cyber-muted/50 text-[11px]">Deactivated</span>
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
