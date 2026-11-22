import React, { useState, useEffect } from 'react';
import {
  BarChart3,
  TrendingUp,
  Globe,
  ShieldAlert,
  Calendar,
  Layers
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  Legend
} from 'recharts';
import { api } from '../services/api';

export default function Analytics() {
  const [analytics, setAnalytics] = useState(null);
  const [evalData, setEvalData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.getAnalytics(),
      api.getEvaluation()
    ])
      .then(([aData, eData]) => {
        setAnalytics(aData);
        setEvalData(eData);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading || !analytics) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 font-mono text-sm">
        Compiling organizational analytics...
      </div>
    );
  }

  // Model comparison bar data
  const modelBarData = evalData?.models ? Object.entries(evalData.models).map(([key, val]) => ({
    name: key.replace(/_/g, ' '),
    detection_rate: val.detection_rate_pct,
    f1_score: Math.round(val.f1_score * 100),
    fp_rate: val.false_positives_per_1000
  })) : [];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="cyber-card p-4 flex items-center justify-between">
        <div>
          <h2 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-cyan-400" />
            <span>Organizational Communication & Threat Analytics</span>
          </h2>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
            Temporal patterns, domain anomalies, and comparative model dynamics
          </p>
        </div>
      </div>

      {/* Grid: Activity Trends & Domain Risk */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Email Activity Over Time */}
        <div className="cyber-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-semibold text-white tracking-wider uppercase">Audit Volume Over Time</h3>
              <p className="text-[11px] text-slate-400">Total email communications vs flagged anomalies</p>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
              Live Feed
            </span>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={analytics.timeline_data || []}>
                <defs>
                  <linearGradient id="scansGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0EA5E9" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#0EA5E9" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="threatsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#64748B" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#1E293B', borderRadius: '8px', fontSize: '11px' }}
                />
                <Area type="monotone" dataKey="total_scans" stroke="#0EA5E9" fillOpacity={1} fill="url(#scansGrad)" name="Total Scans" />
                <Area type="monotone" dataKey="threats" stroke="#EF4444" fillOpacity={1} fill="url(#threatsGrad)" name="Flagged Threats" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Model Detection vs False Positive Comparison */}
        <div className="cyber-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-semibold text-white tracking-wider uppercase">Model Detection Rate vs False Alarms</h3>
              <p className="text-[11px] text-slate-400">Held-out benchmark comparison on identical test data</p>
            </div>
            <span className="text-xs font-mono text-emerald-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
              Test Set: 859 Emails
            </span>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={modelBarData}>
                <XAxis dataKey="name" stroke="#64748B" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748B" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#1E293B', borderRadius: '8px', fontSize: '11px' }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }} />
                <Bar dataKey="detection_rate" fill="#0EA5E9" name="Detection Rate (%)" radius={[4, 4, 0, 0]} />
                <Bar dataKey="fp_rate" fill="#F59E0B" name="False Positives / 1k" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* External Domain Anomaly Table */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-xs font-semibold text-white tracking-wider uppercase">Top External Sender Domains</h3>
            <p className="text-[11px] text-slate-400">External domains observed in audit queue with average risk score</p>
          </div>
          <Globe className="h-4 w-4 text-cyan-400" />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                <th className="py-2.5 px-3">External Domain</th>
                <th className="py-2.5 px-3">Occurrence Count</th>
                <th className="py-2.5 px-3">Average Risk Score</th>
                <th className="py-2.5 px-3">Risk Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {analytics.top_external_domains?.map((dom) => (
                <tr key={dom.domain} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-3 text-cyan-400 font-medium">{dom.domain}</td>
                  <td className="py-3 px-3 text-slate-300">{dom.count}</td>
                  <td className="py-3 px-3 text-slate-300">{dom.avg_risk}</td>
                  <td className="py-3 px-3">
                    <span className={`inline-flex px-2 py-0.5 rounded text-[10px] ${
                      dom.avg_risk >= 0.70 ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                      dom.avg_risk >= 0.45 ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                      'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    }`}>
                      {dom.avg_risk >= 0.70 ? 'High Threat Domain' : dom.avg_risk >= 0.45 ? 'Suspicious Origin' : 'Low Risk Partner'}
                    </span>
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
