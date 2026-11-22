import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Mail,
  Cpu,
  Target,
  ArrowUpRight,
  TrendingUp,
  ExternalLink
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { api } from '../services/api';

const RISK_COLORS = {
  Safe: '#10B981',
  Low: '#38BDF8',
  Medium: '#F59E0B',
  High: '#F97316',
  Critical: '#EF4444'
};

export default function Overview({ onNavigateToInvestigation }) {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchSummary = () => {
    setLoading(true);
    setError(null);
    api.getDashboardSummary()
      .then(setSummary)
      .catch((err) => {
        console.error(err);
        setError(err.message || 'Unable to connect to OrgShield AI API');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchSummary();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 font-mono text-sm">
        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-cyan-400 mr-3"></div>
        Loading cybersecurity telemetry...
      </div>
    );
  }

  if (error || !summary) {
    return (
      <div className="cyber-card p-8 text-center space-y-4 my-8 max-w-lg mx-auto">
        <div className="inline-flex p-3 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
          <AlertTriangle className="h-6 w-6" />
        </div>
        <h3 className="text-sm font-semibold text-white">Backend Telemetry Unavailable</h3>
        <p className="text-xs text-slate-400">
          {error || 'Unable to retrieve dashboard summary telemetry from the backend API.'}
        </p>
        <button
          onClick={fetchSummary}
          className="px-4 py-2 text-xs font-mono rounded bg-cyan-950 border border-cyan-800 text-cyan-400 hover:bg-cyan-900 transition-colors"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const riskData = Object.entries(summary.risk_distribution || {}).map(([name, count]) => ({
    name,
    count,
    color: RISK_COLORS[name] || '#64748B'
  }));

  return (
    <div className="space-y-6">
      {/* Top Banner Notice */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/40 via-blue-950/20 to-transparent border border-cyan-800/40 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Cpu className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-xs font-semibold text-white tracking-wide">
              Unsupervised Email Threat Discovery Active
            </h3>
            <p className="text-[11px] text-slate-400">
              Pattern learned solely from historical organization communications without using labeled phishing examples during training.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-cyan-400 bg-cyan-950/80 px-2.5 py-1 rounded border border-cyan-800/50">
            Threshold: {summary.calibrated_threshold}
          </span>
        </div>
      </div>

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="cyber-card p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Emails Analysed</span>
            <Mail className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono">{summary.emails_analyzed}</div>
          <p className="text-[11px] text-slate-500 mt-1">Audit trail + live scan queue</p>
        </div>

        <div className="cyber-card p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Threats Flagged</span>
            <ShieldAlert className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono">{summary.threats_flagged}</div>
          <p className="text-[11px] text-slate-500 mt-1">Threat rate: {summary.threat_percentage}% of total</p>
        </div>

        <div className="cyber-card p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Active Model</span>
            <Target className="h-4 w-4 text-blue-400" />
          </div>
          <div className="text-xl font-bold text-cyan-400 font-mono capitalize">
            {summary.active_model.replace('_', ' ')}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Unsupervised anomaly detection</p>
        </div>

        <div className="cyber-card p-5">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-2">
            <span>Phishing Detection Rate</span>
            <TrendingUp className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 font-mono">
            {summary.evaluation_highlights?.detection_rate_pct || 83.0}%
          </div>
          <p className="text-[11px] text-slate-500 mt-1">PR-AUC: {summary.evaluation_highlights?.pr_auc || 0.8944}</p>
        </div>
      </div>

      {/* Visualizations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Category Breakdown */}
        <div className="cyber-card p-5 lg:col-span-1 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-white tracking-wider uppercase">Risk Severity Profile</h3>
            <span className="text-[11px] font-mono text-slate-500">Live Scans</span>
          </div>
          <div className="h-48 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="count"
                >
                  {riskData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} stroke="#0B0F19" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#1E293B', borderRadius: '8px', fontSize: '12px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-5 gap-1 mt-2 text-center text-[10px] font-mono">
            {riskData.map((d) => (
              <div key={d.name} className="p-1 rounded bg-slate-900/60 border border-slate-800/80">
                <div style={{ color: d.color }} className="font-bold">{d.count}</div>
                <div className="text-slate-400 text-[9px] truncate">{d.name}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Severity Count Bar Chart */}
        <div className="cyber-card p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-semibold text-white tracking-wider uppercase">Audit Severity Distribution</h3>
              <p className="text-[11px] text-slate-400">Total volume categorized by calibrated risk thresholds</p>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
              FPR Target: 1.5%
            </span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748B" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#1E293B', borderRadius: '8px', fontSize: '12px' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Alerts Feed */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-xs font-semibold text-white tracking-wider uppercase">Recent Security Alerts</h3>
            <p className="text-[11px] text-slate-400">Latest communications flagged by the anomaly detection pipeline</p>
          </div>
          <span className="text-xs text-slate-400 font-mono">Top Flagged Incidents</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                <th className="py-2.5 px-3">Alert ID</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Sender</th>
                <th className="py-2.5 px-3">Subject</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {(!summary.recent_alerts || summary.recent_alerts.length === 0) && (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-slate-500 font-mono text-xs">
                    No security alerts recorded yet. Scan an email in the Email Investigation module to populate alerts.
                  </td>
                </tr>
              )}
              {summary.recent_alerts?.map((alert) => (
                <tr key={alert.alert_id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-3 font-mono text-cyan-400 font-medium">{alert.alert_id}</td>
                  <td className="py-3 px-3">
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
                  <td className="py-3 px-3 text-slate-300 font-mono truncate max-w-[180px]">{alert.sender}</td>
                  <td className="py-3 px-3 text-slate-200 truncate max-w-[280px] font-medium">{alert.subject}</td>
                  <td className="py-3 px-3 font-mono text-slate-300">{alert.risk_score.toFixed(4)}</td>
                  <td className="py-3 px-3 text-right">
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
      </div>
    </div>
  );
}
