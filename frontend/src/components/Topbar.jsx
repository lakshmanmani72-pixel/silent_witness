import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Bell,
  Search,
  User,
  Shield,
  Clock,
  Sparkles,
} from 'lucide-react';

const Topbar = ({ isConnected, mode = 'simulation', notificationsCount = 0 }) => {
  const location = useLocation();
  const [time, setTime] = useState(new Date().toUTCString());

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
    <header className="h-16 bg-cyber-secondary/90 backdrop-blur-md border-b border-cyber-border px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Breadcrumb & Title */}
      <div className="flex items-center gap-3">
        <span className="text-xs uppercase tracking-widest text-cyber-muted font-mono-code">
          {section}
        </span>
        <span className="text-cyber-muted/40 font-mono-code">/</span>
        <h2 className="text-base font-semibold text-cyber-text tracking-wide">
          {title}
        </h2>
      </div>

      {/* Middle Mode Banner */}
      <div className="hidden md:flex items-center gap-2">
        {mode === 'simulation' ? (
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyber-cyan/40 shadow-cyan-glow text-xs font-mono-code text-cyber-cyan">
            <Sparkles className="w-3.5 h-3.5 animate-spin" style={{ animationDuration: '6s' }} />
            <span className="font-bold tracking-wider">DEMO MODE — SYNTHETIC DATA</span>
          </div>
        ) : (
          <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-cyber-green/40 shadow-green-glow text-xs font-mono-code text-cyber-green">
            <span className="w-2 h-2 rounded-full bg-cyber-green animate-ping" />
            <span className="font-bold tracking-wider">LIVE NETWORK OBSERVATION</span>
          </div>
        )}
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-4">
        {/* UTC Clock */}
        <div className="hidden lg:flex items-center gap-2 text-xs font-mono-code text-cyber-muted bg-cyber-card/60 px-3 py-1.5 rounded-lg border border-cyber-border/40">
          <Clock className="w-3.5 h-3.5 text-cyber-cyan" />
          <span>{time}</span>
        </div>

        {/* Notifications Icon with Badge */}
        <button
          className="relative p-2 rounded-lg text-cyber-muted hover:text-cyber-cyan hover:bg-cyber-card/60 transition-colors"
          title="Security Notifications"
        >
          <Bell className="w-4 h-4" />
          {notificationsCount > 0 && (
            <span className="absolute top-1.5 right-1.5 flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-red opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyber-red" />
            </span>
          )}
        </button>

        {/* Admin profile pill */}
        <div className="flex items-center gap-2.5 pl-3 border-l border-cyber-border/40">
          <div className="w-7 h-7 rounded-full bg-cyber-panel border border-cyber-cyan/30 flex items-center justify-center text-cyber-cyan shadow-[0_0_8px_rgba(0,245,255,0.2)]">
            <User className="w-4 h-4" />
          </div>
          <div className="hidden sm:block text-left">
            <p className="text-xs font-semibold text-cyber-text leading-none">Security Admin</p>
            <p className="text-[10px] text-cyber-cyan font-mono-code leading-tight">Tier-3 Analyst</p>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Topbar;
