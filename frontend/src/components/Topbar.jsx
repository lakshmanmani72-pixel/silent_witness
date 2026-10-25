import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Bell,
  Clock,
  Sparkles,
  Shield,
  Activity,
  UserCheck,
} from 'lucide-react';

const Topbar = ({ isConnected, mode = 'simulation', notificationsCount = 0 }) => {
  const location = useLocation();
  const [time, setTime] = useState(new Date().toUTCString().replace('GMT', 'UTC'));

  useEffect(() => {
    const timer = setInterval(() => {
      setTime(new Date().toUTCString().replace('GMT', 'UTC'));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const getPageTitle = (path) => {
    switch (path) {
      case '/': return { title: 'Security Operations Center', section: 'Overview' };
      case '/threats': return { title: 'Live Threat Monitor', section: 'Detection' };
      case '/analytics': return { title: 'Traffic Analytics', section: 'Metrics' };
      case '/intelligence': return { title: 'Threat Intelligence', section: 'Investigation' };
      case '/blocked': return { title: 'Blocked IP Management', section: 'Response' };
      case '/incidents': return { title: 'Incident History & Audit', section: 'Compliance' };
      case '/reports': return { title: 'Reports & Export', section: 'Reporting' };
      case '/settings': return { title: 'System Configuration', section: 'Administration' };
      default: return { title: 'Dashboard', section: 'SOC' };
    }
  };

  const { title, section } = getPageTitle(location.pathname);

  return (
    <header className="h-16 bg-[#253750]/90 backdrop-blur-md border-b border-[#364D6E]/60 px-6 flex items-center justify-between sticky top-0 z-20 shadow-[0_4px_20px_rgba(10,18,30,0.25)]">
      {/* Breadcrumb & Title */}
      <div className="flex items-center gap-2.5 min-w-0">
        <span className="text-[11px] uppercase tracking-wider text-[#B8C5D8] font-mono-code font-medium whitespace-nowrap">
          {section}
        </span>
        <span className="text-[#5B8DEF]/40 font-mono-code text-xs">/</span>
        <h2 className="text-sm sm:text-base font-semibold text-[#F3F6FC] tracking-wide truncate">
          {title}
        </h2>
      </div>

      {/* Middle Mode Banner */}
      <div className="hidden md:flex items-center gap-2">
        {mode === 'simulation' ? (
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-[#5B8DEF]/10 border border-[#5B8DEF]/30 shadow-neumorph-sm text-xs font-mono-code text-[#43D6C5]">
            <Sparkles className="w-3.5 h-3.5 text-[#43D6C5] animate-spin" style={{ animationDuration: '8s' }} />
            <span className="font-semibold tracking-wider text-[11px]">DEMO SCENARIO MODE</span>
          </div>
        ) : (
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-[#43D6A5]/10 border border-[#43D6A5]/30 shadow-neumorph-sm text-xs font-mono-code text-[#43D6A5]">
            <span className="w-2 h-2 rounded-full bg-[#43D6A5] animate-ping" />
            <span className="font-semibold tracking-wider text-[11px]">LIVE NETWORK SNIFFER</span>
          </div>
        )}
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3.5">
        {/* UTC Clock */}
        <div className="hidden lg:flex items-center gap-2 text-xs font-mono-code text-[#B8C5D8] bg-[#1E2F46]/70 px-3 py-1.5 rounded-lg border border-[#364D6E]/50 shadow-neumorph-inset">
          <Clock className="w-3.5 h-3.5 text-[#43D6C5]" />
          <span className="text-[11px]">{time}</span>
        </div>

        {/* Notifications Icon with Badge */}
        <button
          className="relative p-2 rounded-lg text-[#B8C5D8] hover:text-[#F3F6FC] hover:bg-[#2B3F59] border border-transparent hover:border-[#5B8DEF]/25 transition-all shadow-neumorph-sm"
          title="Security Notifications"
        >
          <Bell className="w-4 h-4" />
          {notificationsCount > 0 && (
            <span className="absolute top-1.5 right-1.5 flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#FF7185] opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-[#FF7185]" />
            </span>
          )}
        </button>

        {/* Admin profile pill */}
        <div className="flex items-center gap-2.5 pl-3 border-l border-[#364D6E]/60">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-[#2B3F59] to-[#1E2F46] border border-[#5B8DEF]/30 flex items-center justify-center text-[#43D6C5] shadow-neumorph-sm">
            <UserCheck className="w-4 h-4" />
          </div>
          <div className="hidden sm:block text-left">
            <p className="text-xs font-semibold text-[#F3F6FC] leading-none">Security Analyst</p>
            <p className="text-[10px] text-[#43D6C5] font-mono-code leading-tight mt-0.5">Tier-1 Operator</p>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Topbar;
