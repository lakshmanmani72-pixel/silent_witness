import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  Activity,
  Cpu,
  Ban,
  History,
  Settings,
  Wifi,
  WifiOff,
  Radio,
  FileText
} from 'lucide-react';

const Sidebar = ({ isConnected, mode = 'simulation' }) => {
  // Navigation items currently displayed in the streamlined SOC demonstration console
  const navItems = [
    { name: 'Demonstration Console', path: '/', icon: Activity },
    { name: 'Detection Explainer', path: '/explainer', icon: Cpu },
    { name: 'Blocked IPs Management', path: '/blocked', icon: Ban },
    { name: 'Incident Audit Log', path: '/incidents', icon: History },
    { name: 'System Settings', path: '/settings', icon: Settings },
  ];

  /*
   * Hidden pages (kept in codebase for easy restoration):
   * const hiddenNavItems = [
   *   { name: 'Live Threat Monitor', path: '/threats', icon: Radio },
   *   { name: 'Reports & Export', path: '/reports', icon: FileText },
   * ];
   */

  return (
    <aside className="w-64 bg-[#1F4D45] border-r border-[#1a413a] flex flex-col justify-between shrink-0 h-screen sticky top-0 z-30 select-none text-[#E8F3F0]">
      {/* Top Branding */}
      <div>
        <div className="p-5 border-b border-white/10 flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-white/10 border border-white/15 text-white">
            <ShieldAlert className="w-5 h-5 text-white" />
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 border-2 border-[#1F4D45]" />
          </div>
          <div>
            <h1 className="text-sm font-bold tracking-wider text-white flex items-center gap-1 font-mono">
              SILENT<span className="text-emerald-300">WITNESS</span>
            </h1>
            <p className="text-[10px] uppercase tracking-widest text-[#E8F3F0]/70 font-mono">
              Random Forest NIDS
            </p>
          </div>
        </div>

        {/* Navigation links */}
        <nav className="p-3 space-y-1.5">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-colors duration-150 relative group ${
                    isActive
                      ? 'bg-[#2E6F63] text-white font-semibold shadow-sm'
                      : 'text-[#E8F3F0]/80 hover:text-white hover:bg-[#2E6F63]/50'
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon className={`w-4 h-4 ${isActive ? 'text-white' : 'text-[#E8F3F0]/75'}`} />
                    <span className="tracking-wide">{item.name}</span>
                  </>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status Panel */}
      <div className="p-4 bg-black/15 border border-white/10 space-y-3 font-mono text-xs m-3 rounded-xl">
        {/* Connection status */}
        <div className="flex items-center justify-between">
          <span className="text-[#E8F3F0]/70 flex items-center gap-1.5 text-[11px]">
            {isConnected ? (
              <Wifi className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <WifiOff className="w-3.5 h-3.5 text-rose-300" />
            )}
            Engine Link:
          </span>
          <span className={`text-[11px] font-bold ${isConnected ? 'text-emerald-300' : 'text-rose-300'}`}>
            {isConnected ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>

        {/* Monitoring mode badge */}
        <div className="flex items-center justify-between pt-1 border-t border-white/10">
          <span className="text-[#E8F3F0]/70 text-[11px]">Mode:</span>
          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-white/15 text-white">
            {mode === 'live' ? 'LIVE CAPTURE' : 'DEMO SIMULATION'}
          </span>
        </div>

        {/* Defense Policy Notice */}
        <div className="text-[10px] text-[#E8F3F0]/60 text-center leading-tight pt-1">
          Safe Dry-Run Active &bull; No host firewall rules modified
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
