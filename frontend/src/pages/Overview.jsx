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
  ExternalLink,
  Zap,
  Radio
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
  Safe: '#00E599',
  Low: '#00F0FF',
  Medium: '#FFE600',
  High: '#FF8800',
  Critical: '#FF3366'
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
      <div className="flex flex-col items-center justify-center h-64 font-mono">
        <div className="p-4 bg-[#FFE600] border-2 border-black shadow-[4px_4px_0px_0px_#000] font-black uppercase tracking-wider flex items-center gap-3">
          <div className="h-4 w-4 border-2 border-black border-t-transparent animate-spin rounded-full" />
          <span>LOADING TELEMETRY ENGINE...</span>
        </div>
      </div>
    );
  }

  if (error || !summary) {
    return (
      <div className="brutal-card p-6 text-center space-y-4 my-8 max-w-lg mx-auto bg-white">
        <div className="inline-flex p-3 bg-[#FF3366] text-white border-2 border-black shadow-[3px_3px_0px_0px_#000]">
          <AlertTriangle className="h-6 w-6 stroke-[2.5]" />
        </div>
        <h3 className="text-base font-black uppercase text-black">Backend Telemetry Offline</h3>
        <p className="text-xs font-mono text-slate-700">
          {error || 'Unable to retrieve dashboard summary telemetry from the backend API.'}
        </p>
        <button
          onClick={fetchSummary}
          className="brutal-btn px-4 py-2 text-xs font-mono bg-[#FFE600] text-black"
        >
          RETRY CONNECTION
        </button>
      </div>
    );
  }

  const riskData = Object.entries(summary.risk_distribution || {}).map(([name, count]) => ({
    name,
    count,
    color: RISK_COLORS[name] || '#94A3B8'
  }));

  return (
    <div className="space-y-6">
      {/* Top Banner Notice */}
      <div className="border-2 border-black bg-[#FFFDF0] p-4 shadow-[4px_4px_0px_0px_#000000] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 bg-[#FFE600] border-2 border-black shadow-[2px_2px_0px_0px_#000000] flex items-center justify-center text-black flex-shrink-0">
            <Radio className="h-5 w-5 stroke-[2.5] animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-black uppercase bg-black text-[#FFE600] px-1.5 py-0.5 border border-black font-mono">
                ACTIVE PIPELINE
              </span>
              <h3 className="text-sm font-black text-black uppercase tracking-tight">
                Zero-Phishing-Label Anomaly Engine Online
              </h3>
            </div>
            <p className="text-xs text-slate-700 font-mono mt-0.5">
              Trained exclusively on baseline Enron communications. Identifies zero-day impersonation, anomalous routing, and credential lures.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <div className="px-3 py-1 bg-white border-2 border-black font-mono text-xs font-bold shadow-[2px_2px_0px_0px_#000]">
            THRESHOLD: <strong className="text-black">{summary.calibrated_threshold}</strong>
          </div>
        </div>
      </div>

      {/* Corpus Dataset & Training Scale Bar */}
      <div className="border-2 border-black bg-white p-4 shadow-[4px_4px_0px_0px_#000000]">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 border-b-2 border-black pb-3 mb-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 bg-[#FFE600] border border-black font-mono font-black text-xs uppercase">
                DATASET VOLUME
              </span>
              <h4 className="font-black text-sm uppercase tracking-tight text-black">
                Enterprise Training Corpus & Evaluation Breakdown
              </h4>
            </div>
            <p className="text-xs text-slate-600 font-mono mt-0.5">
              Zero labeled phishing examples used in training. Clean normal communications profile learned from historical corporate email.
            </p>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="px-2.5 py-1 bg-black text-[#00F0FF] font-bold border border-black">
              TARGET DOMAIN: enron.com
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-2.5 bg-[#F4F0EA] border-2 border-black">
            <div className="text-slate-600 text-[10px] uppercase font-bold">Total Corpus Explored</div>
            <div className="text-lg font-black text-black">{Number(summary.corpus_emails || 6000).toLocaleString()} Emails</div>
            <div className="text-[10px] text-slate-600 font-bold">121 Users · 397 Domains</div>
          </div>

          <div className="p-2.5 bg-[#FFFDF0] border-2 border-black">
            <div className="text-slate-600 text-[10px] uppercase font-bold">Clean Training Sample</div>
            <div className="text-lg font-black text-black">{Number(summary.training_sample_size || 4201).toLocaleString()} Clean Mails</div>
            <div className="text-[10px] text-emerald-700 font-bold">0 Phishing Labels Used</div>
          </div>

          <div className="p-2.5 bg-[#FFF0F5] border-2 border-black">
            <div className="text-slate-600 text-[10px] uppercase font-bold">Academic Test Benchmark</div>
            <div className="text-lg font-black text-black">{Number(summary.benchmark_evaluated || 999).toLocaleString()} Evaluated</div>
            <div className="text-[10px] text-rose-600 font-bold">899 Normal · 100 Phish</div>
          </div>

          <div className="p-2.5 bg-[#E6FFFA] border-2 border-black">
            <div className="text-slate-600 text-[10px] uppercase font-bold">Live Scan Audit Queue</div>
            <div className="text-lg font-black text-black">{Number(summary.live_scans_count || 0).toLocaleString()} Scans</div>
            <div className="text-[10px] text-cyan-800 font-bold">Real-time Anomaly Stream</div>
          </div>
        </div>
      </div>

      {/* Primary KPI Grid (Brutalist Colored Cards) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Emails */}
        <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000] hover:-translate-x-0.5 hover:-translate-y-0.5 transition-all">
          <div className="flex items-center justify-between text-black text-xs font-mono font-bold mb-2">
            <span className="uppercase tracking-wider">Emails Analysed</span>
            <div className="p-1 bg-[#00F0FF] border border-black shadow-[1px_1px_0px_#000]">
              <Mail className="h-4 w-4 text-black stroke-[2.5]" />
            </div>
          </div>
          <div className="text-3xl font-black text-black font-mono tracking-tight">
            {Number(summary.emails_analyzed || 6000).toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-600 font-mono mt-1 border-t border-black/20 pt-1">
            6,000 Enron Baseline + {summary.live_scans_count || 0} live scans
          </p>
        </div>

        {/* Card 2: Threats Flagged */}
        <div className="border-2 border-black bg-[#FFE4E6] p-5 shadow-[4px_4px_0px_0px_#000000] hover:-translate-x-0.5 hover:-translate-y-0.5 transition-all">
          <div className="flex items-center justify-between text-black text-xs font-mono font-bold mb-2">
            <span className="uppercase tracking-wider">Threats Flagged</span>
            <div className="p-1 bg-[#FF3366] text-white border border-black shadow-[1px_1px_0px_#000]">
              <ShieldAlert className="h-4 w-4 stroke-[2.5]" />
            </div>
          </div>
          <div className="text-3xl font-black text-[#FF3366] font-mono tracking-tight">{summary.threats_flagged}</div>
          <p className="text-[11px] text-black font-mono font-bold mt-1 border-t border-black/20 pt-1">
            Anomalous rate: {summary.threat_percentage}% of total
          </p>
        </div>

        {/* Card 3: Active Model */}
        <div className="border-2 border-black bg-[#FFFDF0] p-5 shadow-[4px_4px_0px_0px_#000000] hover:-translate-x-0.5 hover:-translate-y-0.5 transition-all">
          <div className="flex items-center justify-between text-black text-xs font-mono font-bold mb-2">
            <span className="uppercase tracking-wider">Active Engine</span>
            <div className="p-1 bg-[#FFE600] border border-black shadow-[1px_1px_0px_#000]">
              <Target className="h-4 w-4 text-black stroke-[2.5]" />
            </div>
          </div>
          <div className="text-xl font-black text-black font-mono capitalize tracking-tight truncate">
            {summary.active_model.replace('_', ' ')}
          </div>
          <p className="text-[11px] text-slate-600 font-mono mt-1 border-t border-black/20 pt-1">
            Unsupervised boundary learner
          </p>
        </div>

        {/* Card 4: Detection Rate */}
        <div className="border-2 border-black bg-[#DCFCE7] p-5 shadow-[4px_4px_0px_0px_#000000] hover:-translate-x-0.5 hover:-translate-y-0.5 transition-all">
          <div className="flex items-center justify-between text-black text-xs font-mono font-bold mb-2">
            <span className="uppercase tracking-wider">Detection Rate</span>
            <div className="p-1 bg-[#00E599] border border-black shadow-[1px_1px_0px_#000]">
              <TrendingUp className="h-4 w-4 text-black stroke-[2.5]" />
            </div>
          </div>
          <div className="text-3xl font-black text-black font-mono tracking-tight">
            {summary.evaluation_highlights?.detection_rate_pct || 83.0}%
          </div>
          <p className="text-[11px] text-black font-mono font-bold mt-1 border-t border-black/20 pt-1">
            PR-AUC: {summary.evaluation_highlights?.pr_auc || 0.8944} (FPR &le; 1.5%)
          </p>
        </div>
      </div>

      {/* Visualizations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Category Breakdown */}
        <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000] lg:col-span-1 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b-2 border-black pb-3 mb-4">
              <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 bg-black" />
                <span>Risk Severity Profile</span>
              </h3>
              <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 bg-black text-[#FFE600] border border-black">
                LIVE
              </span>
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
                    paddingAngle={4}
                    dataKey="count"
                    stroke="#000000"
                    strokeWidth={2}
                  >
                    {riskData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FFFFFF',
                      borderColor: '#000000',
                      borderWidth: '2px',
                      borderRadius: '0px',
                      boxShadow: '3px 3px 0px 0px #000000',
                      fontWeight: 'bold',
                      fontFamily: 'monospace',
                      fontSize: '11px',
                      color: '#000000'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="grid grid-cols-5 gap-1.5 mt-3 text-center font-mono">
            {riskData.map((d) => (
              <div key={d.name} className="p-1.5 border-2 border-black shadow-[2px_2px_0px_0px_#000]" style={{ backgroundColor: `${d.color}25` }}>
                <div className="font-black text-xs text-black">{d.count}</div>
                <div className="text-[9px] uppercase font-bold text-black truncate">{d.name}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Severity Count Bar Chart */}
        <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000] lg:col-span-2">
          <div className="flex items-center justify-between border-b-2 border-black pb-3 mb-4">
            <div>
              <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 bg-[#FFE600] border border-black" />
                <span>Audit Volume Distribution By Risk Tier</span>
              </h3>
              <p className="text-[11px] text-slate-600 font-mono mt-0.5">
                Distribution classified across the calibrated anomaly threshold spectrum
              </p>
            </div>
            <span className="text-[10px] font-mono font-bold bg-[#FFE600] text-black px-2 py-0.5 border border-black shadow-[1px_1px_0px_#000]">
              FPR TARGET: 1.5%
            </span>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#000000" fontSize={11} tickLine={true} fontWeight="bold" />
                <YAxis stroke="#000000" fontSize={11} tickLine={true} fontWeight="bold" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#FFFFFF',
                    borderColor: '#000000',
                    borderWidth: '2px',
                    borderRadius: '0px',
                    boxShadow: '3px 3px 0px 0px #000000',
                    fontWeight: 'bold',
                    fontFamily: 'monospace',
                    fontSize: '11px',
                    color: '#000000'
                  }}
                />
                <Bar dataKey="count" stroke="#000000" strokeWidth={2}>
                  {riskData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Alerts Feed (Brutalist Ledger) */}
      <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000]">
        <div className="flex items-center justify-between border-b-2 border-black pb-3 mb-4">
          <div>
            <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2">
              <span className="h-2.5 w-2.5 bg-[#FF3366] border border-black" />
              <span>Recent Incident Feed</span>
            </h3>
            <p className="text-[11px] text-slate-600 font-mono mt-0.5">
              High-risk anomalies flagged by the unsupervised anomaly scoring pipeline
            </p>
          </div>
          <span className="text-xs text-black font-mono font-bold bg-[#F4F0EA] px-2 py-0.5 border border-black">
            TOP FLAGGED EVENTS
          </span>
        </div>

        <div className="overflow-x-auto border-2 border-black">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="bg-[#FFE600] border-b-2 border-black text-black font-black uppercase text-[11px]">
                <th className="py-2.5 px-3 border-r-2 border-black">Alert ID</th>
                <th className="py-2.5 px-3 border-r-2 border-black">Severity</th>
                <th className="py-2.5 px-3 border-r-2 border-black">Sender</th>
                <th className="py-2.5 px-3 border-r-2 border-black">Subject</th>
                <th className="py-2.5 px-3 border-r-2 border-black">Risk Score</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y-2 divide-black bg-white">
              {(!summary.recent_alerts || summary.recent_alerts.length === 0) && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-700 font-mono text-xs font-bold">
                    No security alerts recorded yet. Run a scan in the Email Investigation module to populate alerts.
                  </td>
                </tr>
              )}
              {summary.recent_alerts?.map((alert) => (
                <tr key={alert.alert_id} className="hover:bg-[#FFFDF0] transition-colors">
                  <td className="py-3 px-3 font-mono text-black font-black border-r-2 border-black whitespace-nowrap">
                    {alert.alert_id}
                  </td>
                  <td className="py-3 px-3 border-r-2 border-black whitespace-nowrap">
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
                  <td className="py-3 px-3 text-black font-mono font-medium truncate max-w-[180px] border-r-2 border-black">
                    {alert.sender}
                  </td>
                  <td className="py-3 px-3 text-black truncate max-w-[280px] font-bold border-r-2 border-black">
                    {alert.subject}
                  </td>
                  <td className="py-3 px-3 font-mono font-black text-black border-r-2 border-black">
                    {alert.risk_score.toFixed(4)}
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
      </div>
    </div>
  );
}
