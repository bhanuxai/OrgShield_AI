import React, { useState, useEffect } from 'react';
import {
  Shield,
  Inbox,
  Search,
  BarChart3,
  Fingerprint,
  Binary,
  Settings,
  Activity,
  Server,
  CheckCircle2,
  AlertCircle,
  Terminal,
  Zap
} from 'lucide-react';
import { api } from '../services/api';

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: Shield, badge: 'KPI' },
  { id: 'inbox', label: 'Threat Inbox', icon: Inbox, badge: 'FEED' },
  { id: 'investigation', label: 'Email Investigation', icon: Search, badge: 'SCAN' },
  { id: 'analytics', label: 'Analytics', icon: BarChart3, badge: 'DATA' },
  { id: 'forensics', label: 'Forensic Intelligence', icon: Fingerprint, badge: 'RFC' },
  { id: 'evaluation', label: 'Model Evaluation', icon: Binary, badge: 'EVAL' },
  { id: 'settings', label: 'Settings', icon: Settings, badge: 'CFG' },
];

export default function DashboardLayout({ activeTab, onSelectTab, children }) {
  const [healthInfo, setHealthInfo] = useState({
    state: 'connecting',
    label: 'CONNECTING',
    message: 'Connecting to backend...',
    active_model: 'one_class_svm'
  });

  const refreshHealth = () => {
    api.checkHealthDetailed()
      .then(setHealthInfo)
      .catch(() => setHealthInfo({
        state: 'offline',
        label: 'OFFLINE',
        message: 'Backend unreachable',
        active_model: 'offline'
      }));
  };

  useEffect(() => {
    refreshHealth();
    const interval = setInterval(refreshHealth, 30000);
    return () => clearInterval(interval);
  }, [activeTab]);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#F4F0EA] text-black font-sans selection:bg-[#FFE600] selection:text-black">
      {/* Neo-Brutalist Sidebar */}
      <aside className="w-64 flex-shrink-0 flex flex-col border-r-2 border-black bg-white shadow-[2px_0px_0px_0px_#000000] z-20">
        {/* Brand Bar */}
        <div className="h-16 px-4 flex items-center gap-3 border-b-2 border-black bg-[#FFE600]">
          <div className="h-10 w-10 bg-black flex items-center justify-center border-2 border-black shadow-[2px_2px_0px_0px_#FFFFFF] text-[#FFE600] flex-shrink-0">
            <Shield className="h-6 w-6 stroke-[2.5]" />
          </div>
          <div className="min-w-0">
            <div className="font-black text-sm tracking-tight text-black flex items-center gap-1.5 uppercase">
              <span className="truncate">OrgShield AI</span>
              <span className="text-[9px] px-1 py-0.2 bg-black text-[#FFE600] font-mono font-bold border border-black">
                v1.0
              </span>
            </div>
            <p className="text-[10px] text-black font-mono font-bold tracking-tight truncate">
              THREAT DISCOVERY // INT396
            </p>
          </div>
        </div>

        {/* Hazard Alert Ticker */}
        <div className="h-2 hazard-stripes border-b-2 border-black flex-shrink-0" />

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1.5 overflow-y-auto">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 text-xs font-bold transition-all text-left uppercase tracking-wider ${
                  isActive
                    ? 'bg-[#FFE600] text-black border-2 border-black shadow-[3px_3px_0px_0px_#000000] translate-x-1'
                    : 'bg-white text-black border-2 border-transparent hover:border-black hover:bg-[#FFFDF0] hover:shadow-[3px_3px_0px_0px_#000000] hover:translate-x-0.5'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`h-4 w-4 stroke-[2.5] ${isActive ? 'text-black' : 'text-slate-700'}`} />
                  <span className="font-black tracking-tight">{item.label}</span>
                </div>
                <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 border border-black ${
                  isActive ? 'bg-black text-[#FFE600]' : 'bg-slate-100 text-slate-800'
                }`}>
                  {item.badge}
                </span>
              </button>
            );
          })}
        </nav>

        {/* Brutalist Backend Status Panel */}
        <div className="p-3 border-t-2 border-black bg-[#F4F0EA]">
          <div className="p-3 bg-white border-2 border-black shadow-[3px_3px_0px_0px_#000000] text-[11px] space-y-2">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1 font-bold text-black font-mono uppercase text-[10px]">
                <Server className="h-3.5 w-3.5 text-black" />
                Backend
              </span>
              <span className={`inline-flex items-center gap-1 font-mono text-[10px] font-bold px-1.5 py-0.5 border border-black shadow-[1px_1px_0px_0px_#000] ${
                healthInfo.state === 'healthy' ? 'bg-[#00E599] text-black' :
                healthInfo.state === 'connecting' ? 'bg-[#FFE600] text-black animate-pulse' :
                'bg-[#FF3366] text-white'
              }`}>
                <span className={`h-1.5 w-1.5 rounded-full ${
                  healthInfo.state === 'healthy' ? 'bg-black' :
                  healthInfo.state === 'connecting' ? 'bg-black' :
                  'bg-white'
                }`} />
                {healthInfo.label}
              </span>
            </div>

            <div className="flex items-center justify-between border-t border-black/20 pt-1.5">
              <span className="flex items-center gap-1 text-slate-600 font-mono text-[10px]">
                <Activity className="h-3 w-3 text-black" />
                Active Model
              </span>
              <span className="font-mono text-[10px] font-bold text-black bg-amber-100 px-1 border border-black truncate max-w-[95px]" title={healthInfo.active_model}>
                {healthInfo.active_model.replace('_', ' ')}
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header */}
        <header className="h-16 px-6 border-b-2 border-black bg-white flex items-center justify-between flex-shrink-0 shadow-[0_2px_0px_0px_#000000] z-10">
          <div className="flex items-center gap-3">
            <div className="px-2.5 py-1 bg-black text-[#FFE600] font-black font-mono text-xs uppercase border-2 border-black shadow-[2px_2px_0px_0px_#000]">
              {NAV_ITEMS.find((n) => n.id === activeTab)?.label || 'Overview'}
            </div>
            <span className="text-xs text-black font-mono font-bold hidden sm:inline">
              // ENRON CORPUS ZERO-LABEL DISCOVERY
            </span>
          </div>

          <div className="flex items-center gap-2.5 text-xs">
            {/* Live API Health Badge */}
            <div className={`hidden md:flex items-center gap-1.5 px-3 py-1 border-2 border-black font-mono text-[11px] font-bold shadow-[2px_2px_0px_0px_#000] ${
              healthInfo.state === 'healthy'
                ? 'bg-[#00E599] text-black'
                : healthInfo.state === 'connecting'
                ? 'bg-[#FFE600] text-black animate-pulse'
                : 'bg-[#FF3366] text-white'
            }`}>
              <span className="h-2 w-2 rounded-full bg-black" />
              <span>API: {healthInfo.message}</span>
            </div>

            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1 bg-white border-2 border-black text-black font-mono font-bold shadow-[2px_2px_0px_0px_#000]">
              <span className="h-2 w-2 bg-[#00F0FF] border border-black" />
              <span>DOMAIN: ENRON.COM</span>
            </div>

            <div className="px-3 py-1 bg-[#FFE600] border-2 border-black text-black font-mono font-black shadow-[2px_2px_0px_0px_#000] uppercase tracking-tight flex items-center gap-1">
              <Zap className="h-3.5 w-3.5 fill-black stroke-black" />
              <span>UNSUPERVISED</span>
            </div>
          </div>
        </header>

        {/* Page Content Body with Brutalist Dot Grid */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#F4F0EA] dot-grid">
          <div className="max-w-7xl mx-auto space-y-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
