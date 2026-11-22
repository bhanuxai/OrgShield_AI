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
  AlertCircle
} from 'lucide-react';
import { api } from '../services/api';

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: Shield },
  { id: 'inbox', label: 'Threat Inbox', icon: Inbox },
  { id: 'investigation', label: 'Email Investigation', icon: Search },
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'forensics', label: 'Forensic Intelligence', icon: Fingerprint },
  { id: 'evaluation', label: 'Model Evaluation', icon: Binary },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export default function DashboardLayout({ activeTab, onSelectTab, children }) {
  const [health, setHealth] = useState({ status: 'connecting', models_loaded: false, active_model: 'isolation_forest' });

  useEffect(() => {
    api.getHealth()
      .then(setHealth)
      .catch(() => setHealth({ status: 'offline', models_loaded: false, active_model: 'offline' }));
  }, [activeTab]);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#070A12] text-slate-100">
      {/* Sidebar */}
      <aside className="w-64 flex-shrink-0 flex flex-col border-r border-slate-800/80 bg-[#0B0F19]/95 backdrop-blur-md">
        {/* Brand */}
        <div className="h-16 px-5 flex items-center gap-3 border-b border-slate-800/80">
          <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="font-semibold text-sm tracking-wide text-white flex items-center gap-1.5">
              <span>OrgShield AI</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/50 font-mono">v1.0</span>
            </div>
            <p className="text-[11px] text-slate-400 font-medium">Threat Discovery Platform</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all text-left ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/15 to-transparent text-cyan-400 border-l-2 border-cyan-400 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Icon className={`h-4 w-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Backend Status Footer */}
        <div className="p-3 border-t border-slate-800/80 bg-[#090D16]">
          <div className="px-3 py-2.5 rounded-lg bg-slate-900/80 border border-slate-800 text-[11px] space-y-1.5">
            <div className="flex items-center justify-between text-slate-400">
              <span className="flex items-center gap-1.5">
                <Server className="h-3 w-3 text-slate-500" />
                Backend Engine
              </span>
              <span className={`inline-flex items-center gap-1 font-mono text-[10px] ${
                health.status === 'healthy' ? 'text-emerald-400' : 'text-amber-400'
              }`}>
                <span className={`h-1.5 w-1.5 rounded-full ${health.status === 'healthy' ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
                {health.status === 'healthy' ? 'READY' : health.status.toUpperCase()}
              </span>
            </div>
            <div className="flex items-center justify-between text-slate-400">
              <span className="flex items-center gap-1.5">
                <Activity className="h-3 w-3 text-slate-500" />
                Active Model
              </span>
              <span className="font-mono text-[10px] text-cyan-400 truncate max-w-[90px]">
                {health.active_model.replace('_', ' ')}
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header */}
        <header className="h-16 px-6 border-b border-slate-800/80 bg-[#0B0F19]/80 backdrop-blur-md flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-3">
            <h1 className="text-base font-semibold text-white tracking-tight">
              {NAV_ITEMS.find((n) => n.id === activeTab)?.label || 'Overview'}
            </h1>
            <span className="text-xs text-slate-500 font-mono">/ Enron Corpus Baseline</span>
          </div>

          <div className="flex items-center gap-3 text-xs">
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 font-mono">
              <span className="h-2 w-2 rounded-full bg-cyan-400" />
              <span>Target: Enron Org (enron.com)</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-cyan-950/60 border border-cyan-800/60 text-cyan-400 font-mono font-medium">
              Mode: Unsupervised Threat Discovery
            </div>
          </div>
        </header>

        {/* Page Body */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#070A12]">
          <div className="max-w-7xl mx-auto space-y-6">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
