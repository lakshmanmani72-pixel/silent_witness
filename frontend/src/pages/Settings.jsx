import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon,
  ShieldAlert,
  Sliders,
  Database,
  Lock,
  Radio,
  Save,
  CheckCircle,
  AlertTriangle,
  Info,
  RefreshCw,
  HardDrive,
  Cpu,
} from 'lucide-react';
import ConfirmationModal from '../components/ConfirmationModal';
import { endpoints } from '../services/api';

const Settings = () => {
  const [settings, setSettings] = useState({
    syn_flood_critical_threshold: 100,
    syn_flood_high_threshold: 50,
    syn_flood_window_seconds: 10,
    port_scan_high_threshold: 100,
    port_scan_window_seconds: 60,
    alert_cooldown_seconds: 30,
    dry_run_mode: true,
    auto_response_enabled: false,
    default_block_duration_min: 60,
    max_blocks_per_hour: 20,
    monitoring_mode: 'simulation',
    allowlist_ips: ['127.0.0.1', '::1'],
    data_retention_days: 90,
    table_density: 'comfortable',
  });

  const [dbHealth, setDbHealth] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [scapyAvailable, setScapyAvailable] = useState(false);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [allowlistText, setAllowlistText] = useState('');

  const [loading, setLoading] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [isConfirmSaveOpen, setIsConfirmSaveOpen] = useState(false);

  const fetchSettingsAndStatus = async () => {
    try {
      setLoading(true);
      const [settingsRes, ifaceRes, healthRes] = await Promise.all([
        endpoints.getSettings(),
        endpoints.getMonitoringInterfaces(),
        endpoints.getHealth(),
      ]);

      const data = settingsRes.data;
      setSettings(data);
      setAllowlistText(data.allowlist_ips ? data.allowlist_ips.join(', ') : '127.0.0.1, ::1');
      setInterfaces(ifaceRes.data.interfaces || []);
      setScapyAvailable(ifaceRes.data.scapy_available || false);
      if (ifaceRes.data.interfaces?.length > 0) {
        setSelectedInterface(ifaceRes.data.interfaces[0]);
      }
      setDbHealth(healthRes.data.database || {});
    } catch (err) {
      console.error('Failed to load settings:', err);
      setErrorMsg('Failed to fetch settings from backend.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettingsAndStatus();
  }, []);

  const handleInputChange = (field, value) => {
    setSettings((prev) => ({ ...prev, [field]: value }));
  };

  const handleSaveConfirmed = async () => {
    try {
      setSuccessMsg('');
      setErrorMsg('');

      // Parse allowlist text into list
      const parsedAllowlist = allowlistText
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);

      const payload = {
        ...settings,
        allowlist_ips: parsedAllowlist,
      };

      await endpoints.updateSettings(payload);
      setSuccessMsg('Settings successfully persisted to SQLite database and loaded into detector engine.');
      setTimeout(() => setSuccessMsg(''), 5000);
      await fetchSettingsAndStatus();
    } catch (err) {
      console.error('Save settings error:', err);
      setErrorMsg(err.response?.data?.detail || 'Failed to save settings.');
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto font-mono-code">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-bluegrey animate-pulse" />
            <span className="text-[10px] uppercase font-bold text-forest tracking-widest font-sans">
              System Control & Policies
            </span>
          </div>
          <h1 className="text-xl font-bold tracking-tight text-ink flex items-center gap-2">
            <SettingsIcon className="w-5 h-5 text-bluegrey-ink" />
            System Configuration & Detection Policies
          </h1>
          <p className="text-xs text-muted mt-1 font-sans">
            Adjust real-time rolling window detection thresholds, automated response policies, and containment safeguards.
          </p>
        </div>

        <button
          onClick={() => setIsConfirmSaveOpen(true)}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-forest hover:bg-forest/90 text-white font-bold text-xs shadow-aurora-btn transition-all font-sans"
        >
          <Save className="w-4 h-4" />
          <span>Save Changes</span>
        </button>
      </div>

      {/* Status alerts */}
      {successMsg && (
        <div className="p-4 bg-good/10 border border-good/40 rounded-xl text-good-ink text-xs flex items-center gap-2.5 animate-fadeIn font-sans">
          <CheckCircle className="w-4 h-4 shrink-0 text-good-ink" />
          <span>{successMsg}</span>
        </div>
      )}

      {errorMsg && (
        <div className="p-4 bg-bad/10 border border-bad/40 rounded-xl text-bad-ink text-xs flex items-center gap-2.5 animate-fadeIn font-sans">
          <AlertTriangle className="w-4 h-4 shrink-0 text-bad-ink" />
          <span>{errorMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 text-xs">
        {/* ── 1. Detection Settings ────────────────────────────────────────── */}
        <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft space-y-4 relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-bluegrey to-transparent" />
          
          <h2 className="text-xs uppercase font-bold text-bluegrey-ink tracking-wider flex items-center gap-2 font-sans">
            <ShieldAlert className="w-4 h-4" />
            Detection Engine Thresholds
          </h2>

          <div className="space-y-3.5">
            <div>
              <label className="text-muted block mb-1 font-sans text-[11px]">
                SYN Flood Critical Threshold (Packets in Window):
              </label>
              <input
                type="number"
                min="1"
                value={settings.syn_flood_critical_threshold}
                onChange={(e) => handleInputChange('syn_flood_critical_threshold', parseInt(e.target.value) || 100)}
                className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
              />
              <span className="text-[10px] text-muted/70 font-sans">Default: &gt;100 packets in rolling window</span>
            </div>

            <div>
              <label className="text-muted block mb-1 font-sans text-[11px]">
                SYN Flood High Threshold (Packets in Window):
              </label>
              <input
                type="number"
                min="1"
                value={settings.syn_flood_high_threshold}
                onChange={(e) => handleInputChange('syn_flood_high_threshold', parseInt(e.target.value) || 50)}
                className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
              />
              <span className="text-[10px] text-muted/70 font-sans">Default: 50-100 packets triggers High severity</span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-muted block mb-1 font-sans text-[11px]">
                  SYN Flood Window (Sec):
                </label>
                <input
                  type="number"
                  min="1"
                  value={settings.syn_flood_window_seconds}
                  onChange={(e) => handleInputChange('syn_flood_window_seconds', parseInt(e.target.value) || 10)}
                  className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
                />
              </div>

              <div>
                <label className="text-muted block mb-1 font-sans text-[11px]">
                  Port Scan Window (Sec):
                </label>
                <input
                  type="number"
                  min="1"
                  value={settings.port_scan_window_seconds}
                  onChange={(e) => handleInputChange('port_scan_window_seconds', parseInt(e.target.value) || 60)}
                  className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
                />
              </div>
            </div>

            <div>
              <label className="text-muted block mb-1 font-sans text-[11px]">
                Port Scan High Threshold (Distinct Destination Ports):
              </label>
              <input
                type="number"
                min="1"
                value={settings.port_scan_high_threshold}
                onChange={(e) => handleInputChange('port_scan_high_threshold', parseInt(e.target.value) || 100)}
                className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
              />
              <span className="text-[10px] text-muted/70 font-sans">Default: &gt;100 distinct ports contacted in window</span>
            </div>

            <div>
              <label className="text-muted block mb-1 font-sans text-[11px]">
                Alert Cooldown Period (Seconds between repeated alerts per IP):
              </label>
              <input
                type="number"
                min="1"
                value={settings.alert_cooldown_seconds}
                onChange={(e) => handleInputChange('alert_cooldown_seconds', parseInt(e.target.value) || 30)}
                className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
              />
            </div>
          </div>
        </div>

        {/* ── 2. Response & Firewall Settings ──────────────────────────────── */}
        <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft space-y-4 relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-bad to-transparent" />
          
          <h2 className="text-xs uppercase font-bold text-bad-ink tracking-wider flex items-center gap-2 font-sans">
            <Lock className="w-4 h-4" />
            Automated Response & Safety Controls
          </h2>

          <div className="space-y-3.5">
            {/* Dry run switch */}
            <div className="flex items-center justify-between p-3.5 rounded-xl bg-mist/60 border border-bluegrey/30">
              <div className="pr-3">
                <span className="font-bold text-ink block">Dry-Run Mode (Simulation Guard)</span>
                <span className="text-[11px] text-muted font-sans leading-relaxed">
                  When enabled, all blocking actions are logged safely without modifying host firewall rules.
                </span>
              </div>
              <input
                type="checkbox"
                checked={settings.dry_run_mode}
                onChange={(e) => handleInputChange('dry_run_mode', e.target.checked)}
                className="w-4 h-4 accent-forest cursor-pointer shrink-0"
              />
            </div>

            {/* Auto response toggle */}
            <div className="flex items-center justify-between p-3.5 rounded-xl bg-mist/60 border border-bluegrey/30">
              <div className="pr-3">
                <span className="font-bold text-ink block">Enable Automated Response</span>
                <span className="text-[11px] text-muted font-sans leading-relaxed">
                  Automatically register containment blocks for Critical / High threat detections.
                </span>
              </div>
              <input
                type="checkbox"
                checked={settings.auto_response_enabled}
                onChange={(e) => handleInputChange('auto_response_enabled', e.target.checked)}
                className="w-4 h-4 accent-forest cursor-pointer shrink-0"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-muted block mb-1 font-sans text-[11px]">
                  Default Block (Minutes):
                </label>
                <input
                  type="number"
                  min="1"
                  value={settings.default_block_duration_min}
                  onChange={(e) => handleInputChange('default_block_duration_min', parseInt(e.target.value) || 60)}
                  className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
                />
              </div>

              <div>
                <label className="text-muted block mb-1 font-sans text-[11px]">
                  Max Blocks / Hour:
                </label>
                <input
                  type="number"
                  min="1"
                  value={settings.max_blocks_per_hour}
                  onChange={(e) => handleInputChange('max_blocks_per_hour', parseInt(e.target.value) || 20)}
                  className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
                />
              </div>
            </div>

            {/* Allowlist IPs */}
            <div>
              <label className="text-muted block mb-1 font-sans text-[11px]">
                Protected Allow-List (Comma-separated IPs):
              </label>
              <textarea
                rows="2"
                value={allowlistText}
                onChange={(e) => setAllowlistText(e.target.value)}
                className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 font-mono-code text-xs transition-colors"
                placeholder="127.0.0.1, ::1, 192.168.1.1"
              />
              <span className="text-[10px] text-muted/70 font-sans">
                These IP addresses will never be contained by the automated response engine.
              </span>
            </div>
          </div>
        </div>

        {/* ── 3. Monitoring & Packet Capture Settings ──────────────────────── */}
        <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft space-y-4 relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-forest to-transparent" />
          
          <h2 className="text-xs uppercase font-bold text-forest tracking-wider flex items-center gap-2 font-sans">
            <Radio className="w-4 h-4" />
            Sensor & Interface Configuration
          </h2>

          <div className="space-y-3.5">
            <div>
              <label className="text-muted block mb-1 font-sans text-[11px]">Operating Mode:</label>
              <select
                value={settings.monitoring_mode}
                onChange={(e) => handleInputChange('monitoring_mode', e.target.value)}
                className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
              >
                <option value="simulation">Simulation Mode (Synthetic Demonstration)</option>
                <option value="live">Live Monitoring (Scapy Local Passive Capture)</option>
              </select>
            </div>

            <div>
              <label className="text-muted block mb-1 font-sans text-[11px]">Available Network Interfaces:</label>
              <select
                value={selectedInterface}
                onChange={(e) => setSelectedInterface(e.target.value)}
                disabled={!scapyAvailable || interfaces.length === 0}
                className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 disabled:opacity-40 transition-colors"
              >
                {interfaces.map((iface, idx) => (
                  <option key={idx} value={iface}>{iface}</option>
                ))}
                {interfaces.length === 0 && (
                  <option value="">No network interfaces detected or capture driver absent</option>
                )}
              </select>
            </div>

            <div className="p-3.5 bg-mist/60 rounded-xl border border-bluegrey/30 text-muted text-[11px] font-sans space-y-1.5 leading-relaxed">
              <p>
                <strong className="text-ink">Windows Note:</strong> Scapy live capture on Windows requires the Npcap packet capture driver. In college viva and classroom environments, Simulation Mode runs immediately without driver prerequisites.
              </p>
              <p className="text-forest font-mono-code text-[10px]">
                Driver Status: {scapyAvailable ? 'Scapy module active' : 'Driver not installed / Simulation default'}
              </p>
            </div>
          </div>
        </div>

        {/* ── 4. Data & Persistence Settings ───────────────────────────────── */}
        <div className="bg-surface border border-bluegrey/40 rounded-xl p-5 shadow-soft space-y-4 relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-bluegrey to-transparent" />
          
          <h2 className="text-xs uppercase font-bold text-bluegrey-ink tracking-wider flex items-center gap-2 font-sans">
            <Database className="w-4 h-4" />
            Database Health & Maintenance
          </h2>

          <div className="space-y-3.5">
            <div className="grid grid-cols-2 gap-3 bg-mist/60 p-3.5 rounded-xl border border-bluegrey/30 font-sans">
              <div>
                <span className="text-muted text-[10px]">Database Status:</span>
                <p className="font-bold text-good-ink font-mono-code mt-0.5">{dbHealth?.status?.toUpperCase() || 'HEALTHY'}</p>
              </div>
              <div>
                <span className="text-muted text-[10px]">Engine:</span>
                <p className="font-bold text-ink font-mono-code mt-0.5">SQLite WAL Mode</p>
              </div>
              <div>
                <span className="text-muted text-[10px]">Threat Audit Rows:</span>
                <p className="font-bold text-forest font-mono-code mt-0.5">{dbHealth?.threat_count || 0}</p>
              </div>
              <div>
                <span className="text-muted text-[10px]">Incident Records:</span>
                <p className="font-bold text-amber-ink font-mono-code mt-0.5">{dbHealth?.incident_count || 0}</p>
              </div>
            </div>

            <div>
              <label className="text-muted block mb-1 font-sans text-[11px]">
                Data Retention Horizon (Days):
              </label>
              <input
                type="number"
                min="1"
                value={settings.data_retention_days}
                onChange={(e) => handleInputChange('data_retention_days', parseInt(e.target.value) || 90)}
                className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
              />
            </div>

            <div>
              <label className="text-muted block mb-1 font-sans text-[11px]">Table Display Density:</label>
              <select
                value={settings.table_density}
                onChange={(e) => handleInputChange('table_density', e.target.value)}
                className="w-full bg-mist/70 border border-bluegrey/40 rounded-lg px-3 py-2 text-ink focus:outline-none focus:border-bluegrey/40 transition-colors"
              >
                <option value="comfortable">Comfortable (Standard)</option>
                <option value="compact">Compact (High Information Density)</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Modal */}
      <ConfirmationModal
        isOpen={isConfirmSaveOpen}
        title="Confirm Policy & Threshold Update"
        message="Are you sure you want to update the detection engine thresholds and response settings? New parameters will immediately affect incoming network inspection."
        confirmText="Apply Settings"
        isDanger={false}
        onConfirm={handleSaveConfirmed}
        onClose={() => setIsConfirmSaveOpen(false)}
      />
    </div>
  );
};

export default Settings;
