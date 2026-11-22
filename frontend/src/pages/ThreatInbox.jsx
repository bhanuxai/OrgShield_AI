import React, { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  ShieldAlert,
  ArrowUpRight,
  RefreshCw,
  SlidersHorizontal,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { api } from '../services/api';

const SEVERITY_OPTIONS = ['ALL', 'Critical', 'High', 'Medium', 'Low', 'Safe'];

export default function ThreatInbox({ onNavigateToInvestigation }) {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [threatOnly, setThreatOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  const limit = 15;

  const loadAlerts = () => {
    setLoading(true);
    api.getAlerts({
      limit,
      offset,
      severity: selectedSeverity === 'ALL' ? undefined : selectedSeverity,
      threat_only: threatOnly,
      query: searchQuery || undefined
    })
      .then((data) => {
        setAlerts(data.alerts || []);
        setTotal(data.total || 0);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadAlerts();
  }, [offset, selectedSeverity, threatOnly]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setOffset(0);
    loadAlerts();
  };

  return (
    <div className="space-y-6">
      {/* Search & Filter Header Bar */}
      <div className="cyber-card p-4 flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Search Input */}
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-80">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search sender, subject, indicators..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 font-mono"
          />
        </form>

        {/* Severity Tabs */}
        <div className="flex items-center gap-1.5 flex-wrap w-full md:w-auto">
          {SEVERITY_OPTIONS.map((sev) => (
            <button
              key={sev}
              onClick={() => { setSelectedSeverity(sev); setOffset(0); }}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors ${
                selectedSeverity === sev
                  ? 'bg-cyan-950 text-cyan-400 border border-cyan-800 font-semibold'
                  : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800/80'
              }`}
            >
              {sev}
            </button>
          ))}

          {/* Threat Only Toggle */}
          <button
            onClick={() => { setThreatOnly(!threatOnly); setOffset(0); }}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-colors flex items-center gap-1.5 ${
              threatOnly
                ? 'bg-rose-950/80 text-rose-400 border border-rose-800 font-medium'
                : 'bg-slate-900/60 text-slate-400 hover:text-slate-200 border border-slate-800/80'
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            <span>Threats Only</span>
          </button>

          <button
            onClick={loadAlerts}
            className="p-1.5 rounded-lg bg-slate-900 text-slate-400 hover:text-cyan-400 border border-slate-800 transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-xs font-semibold text-white tracking-wider uppercase">Threat Intelligence Queue</h3>
            <p className="text-[11px] text-slate-400 font-mono">Showing {alerts.length} of {total} records</p>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-48 text-slate-400 font-mono text-xs">
            Querying threat records...
          </div>
        ) : alerts.length === 0 ? (
          <div className="flex items-center justify-center h-48 text-slate-500 font-mono text-xs">
            No matching communications found in audit history.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="py-2.5 px-3">Alert ID</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Score</th>
                  <th className="py-2.5 px-3">Sender</th>
                  <th className="py-2.5 px-3">Subject</th>
                  <th className="py-2.5 px-3">Detection Reason</th>
                  <th className="py-2.5 px-3">Date</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {alerts.map((alert) => (
                  <tr key={alert.alert_id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3 font-mono text-cyan-400 font-medium whitespace-nowrap">
                      {alert.alert_id}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-mono font-medium ${
                        alert.risk_category === 'Critical' ? 'bg-rose-950/80 text-rose-400 border border-rose-800' :
                        alert.risk_category === 'High' ? 'bg-orange-950/80 text-orange-400 border border-orange-800' :
                        alert.risk_category === 'Medium' ? 'bg-amber-950/80 text-amber-400 border border-amber-800' :
                        alert.risk_category === 'Low' ? 'bg-cyan-950/80 text-cyan-400 border border-cyan-800' :
                        'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
                      }`}>
                        {alert.risk_category}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300 whitespace-nowrap">
                      {alert.risk_score.toFixed(4)}
                    </td>
                    <td className="py-3 px-3 text-slate-300 font-mono truncate max-w-[160px]">
                      {alert.sender}
                    </td>
                    <td className="py-3 px-3 text-slate-200 truncate max-w-[220px] font-medium">
                      {alert.subject}
                    </td>
                    <td className="py-3 px-3 text-slate-400 truncate max-w-[280px]">
                      {alert.explanation || (alert.anomaly_indicators?.[0] || 'Statistical anomaly detected')}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-500 whitespace-nowrap text-[11px]">
                      {alert.timestamp?.slice(0, 10)}
                    </td>
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={() => onNavigateToInvestigation && onNavigateToInvestigation(alert.alert_id)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-900/40 text-slate-300 hover:text-cyan-400 border border-slate-700 transition-colors text-[11px]"
                      >
                        <span>Investigate</span>
                        <ArrowUpRight className="h-3 w-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div className="flex items-center justify-between border-t border-slate-800/80 pt-4 mt-4 text-xs font-mono text-slate-400">
          <div>
            Showing {Math.min(total, offset + 1)} - {Math.min(total, offset + limit)} of {total}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              onClick={() => setOffset(offset + limit)}
              disabled={offset + limit >= total}
              className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
