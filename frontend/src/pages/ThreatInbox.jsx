import React, { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  ShieldAlert,
  ArrowUpRight,
  RefreshCw,
  SlidersHorizontal,
  ChevronLeft,
  ChevronRight,
  AlertTriangle
} from 'lucide-react';
import { api } from '../services/api';

const SEVERITY_OPTIONS = ['ALL', 'Critical', 'High', 'Medium', 'Low', 'Safe'];

export default function ThreatInbox({ onNavigateToInvestigation }) {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [threatOnly, setThreatOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  const limit = 15;

  const loadAlerts = () => {
    setLoading(true);
    setError(null);
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
      .catch((err) => {
        console.error(err);
        setError(err.message || 'Failed to load threat inbox records.');
      })
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
      <div className="border-2 border-black bg-white p-4 shadow-[4px_4px_0px_0px_#000000] flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Search Input */}
        <form onSubmit={handleSearchSubmit} className="relative w-full md:w-80">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-black stroke-[2.5]" />
          <input
            type="text"
            placeholder="Search sender, subject, indicators..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 border-2 border-black bg-[#F4F0EA] text-xs font-mono font-bold text-black placeholder-slate-500 focus:outline-none focus:bg-[#FFFDF0] focus:shadow-[2px_2px_0px_#000]"
          />
        </form>

        {/* Severity Tabs */}
        <div className="flex items-center gap-1.5 flex-wrap w-full md:w-auto">
          {SEVERITY_OPTIONS.map((sev) => (
            <button
              key={sev}
              onClick={() => { setSelectedSeverity(sev); setOffset(0); }}
              className={`px-3 py-1.5 border-2 border-black text-xs font-mono font-bold uppercase transition-all shadow-[2px_2px_0px_0px_#000] active:translate-x-0.5 active:translate-y-0.5 active:shadow-none ${
                selectedSeverity === sev
                  ? 'bg-[#FFE600] text-black'
                  : 'bg-white text-black hover:bg-[#FFFDF0]'
              }`}
            >
              {sev}
            </button>
          ))}

          {/* Threat Only Toggle */}
          <button
            onClick={() => { setThreatOnly(!threatOnly); setOffset(0); }}
            className={`px-3 py-1.5 border-2 border-black text-xs font-mono font-black uppercase transition-all flex items-center gap-1.5 shadow-[2px_2px_0px_0px_#000] active:translate-x-0.5 active:translate-y-0.5 active:shadow-none ${
              threatOnly
                ? 'bg-[#FF3366] text-white'
                : 'bg-white text-black hover:bg-[#FFE4E6]'
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5 stroke-[2.5]" />
            <span>THREATS ONLY</span>
          </button>

          <button
            onClick={loadAlerts}
            className="p-1.5 bg-white hover:bg-[#FFE600] border-2 border-black text-black shadow-[2px_2px_0px_0px_#000] active:translate-x-0.5 active:translate-y-0.5 transition-all"
            title="Refresh"
          >
            <RefreshCw className={`h-4 w-4 stroke-[2.5] ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000]">
        <div className="flex items-center justify-between border-b-2 border-black pb-3 mb-4">
          <div>
            <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2">
              <span className="h-2.5 w-2.5 bg-black" />
              <span>Telemetry Communications Queue</span>
            </h3>
            <p className="text-[11px] text-slate-600 font-mono mt-0.5">
              Showing {alerts.length} of {total} records from baseline audit queue
            </p>
          </div>
          <span className="text-xs font-mono font-bold px-2 py-0.5 bg-[#FFE600] border border-black shadow-[1px_1px_0px_#000]">
            ACTIVE CORPUS
          </span>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-48 font-mono text-xs font-bold text-black">
            <div className="p-3 bg-[#FFE600] border-2 border-black shadow-[3px_3px_0px_#000] flex items-center gap-2">
              <div className="h-3.5 w-3.5 border-2 border-black border-t-transparent animate-spin rounded-full" />
              <span>QUERYING AUDIT STREAM...</span>
            </div>
          </div>
        ) : error ? (
          <div className="p-6 text-center space-y-3 bg-[#FFE4E6] border-2 border-black">
            <div className="text-black font-mono text-xs font-bold flex items-center justify-center gap-2">
              <AlertTriangle className="h-4 w-4 text-[#FF3366]" />
              <span>{error}</span>
            </div>
            <button
              onClick={loadAlerts}
              className="brutal-btn px-4 py-1.5 text-xs font-mono bg-[#FFE600] text-black"
            >
              RETRY FETCHING RECORDS
            </button>
          </div>
        ) : alerts.length === 0 ? (
          <div className="flex items-center justify-center h-48 font-mono text-xs text-slate-600 font-bold">
            No matching communications found in audit history.
          </div>
        ) : (
          <div className="overflow-x-auto border-2 border-black">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="bg-[#FFE600] border-b-2 border-black text-black font-black uppercase text-[11px]">
                  <th className="py-2.5 px-3 border-r-2 border-black">Alert ID</th>
                  <th className="py-2.5 px-3 border-r-2 border-black">Severity</th>
                  <th className="py-2.5 px-3 border-r-2 border-black">Score</th>
                  <th className="py-2.5 px-3 border-r-2 border-black">Sender</th>
                  <th className="py-2.5 px-3 border-r-2 border-black">Subject</th>
                  <th className="py-2.5 px-3 border-r-2 border-black">Detection Reason</th>
                  <th className="py-2.5 px-3 border-r-2 border-black">Date</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y-2 divide-black bg-white">
                {alerts.map((alert) => (
                  <tr key={alert.alert_id} className="hover:bg-[#FFFDF0] transition-colors">
                    <td className="py-3 px-3 font-mono text-black font-black whitespace-nowrap border-r-2 border-black">
                      {alert.alert_id}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap border-r-2 border-black">
                      <span className={`inline-flex px-2 py-0.5 text-[10px] font-mono font-black uppercase border-2 border-black shadow-[1.5px_1.5px_0px_#000] ${
                        alert.risk_category === 'Critical' ? 'bg-[#FF3366] text-white' :
                        alert.risk_category === 'High' ? 'bg-[#FF8800] text-black' :
                        alert.risk_category === 'Medium' ? 'bg-[#FFE600] text-black' :
                        alert.risk_category === 'Low' ? 'bg-[#00F0FF] text-black' :
                        'bg-[#00E599] text-black'
                      }`}>
                        {alert.risk_category}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono font-black text-black whitespace-nowrap border-r-2 border-black">
                      {alert.risk_score.toFixed(4)}
                    </td>
                    <td className="py-3 px-3 text-black font-mono truncate max-w-[160px] border-r-2 border-black">
                      {alert.sender}
                    </td>
                    <td className="py-3 px-3 text-black truncate max-w-[220px] font-bold border-r-2 border-black">
                      {alert.subject}
                    </td>
                    <td className="py-3 px-3 text-slate-700 truncate max-w-[280px] border-r-2 border-black">
                      {alert.explanation || (alert.anomaly_indicators?.[0] || 'Statistical anomaly detected')}
                    </td>
                    <td className="py-3 px-3 font-mono text-black whitespace-nowrap text-[11px] border-r-2 border-black">
                      {alert.timestamp?.slice(0, 10)}
                    </td>
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={() => onNavigateToInvestigation && onNavigateToInvestigation(alert.alert_id)}
                        className="brutal-btn inline-flex items-center gap-1 px-2.5 py-1 bg-white hover:bg-[#FFE600] text-black text-[10px] font-mono font-black uppercase"
                      >
                        <span>INSPECT</span>
                        <ArrowUpRight className="h-3 w-3 stroke-[2.5]" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div className="flex items-center justify-between border-t-2 border-black pt-4 mt-4 text-xs font-mono font-bold text-black">
          <div>
            SHOWING {Math.min(total, offset + 1)} - {Math.min(total, offset + limit)} OF {total}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="p-1.5 bg-white border-2 border-black text-black shadow-[2px_2px_0px_#000] active:translate-x-0.5 active:translate-y-0.5 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-[#FFE600] transition-all"
            >
              <ChevronLeft className="h-4 w-4 stroke-[2.5]" />
            </button>
            <button
              onClick={() => setOffset(offset + limit)}
              disabled={offset + limit >= total}
              className="p-1.5 bg-white border-2 border-black text-black shadow-[2px_2px_0px_#000] active:translate-x-0.5 active:translate-y-0.5 disabled:opacity-30 disabled:cursor-not-allowed hover:bg-[#FFE600] transition-all"
            >
              <ChevronRight className="h-4 w-4 stroke-[2.5]" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
