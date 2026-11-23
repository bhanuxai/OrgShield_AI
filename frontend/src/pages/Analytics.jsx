import React, { useState, useEffect } from 'react';
import {
  BarChart3,
  TrendingUp,
  Globe,
  ShieldAlert,
  Calendar,
  Layers,
  AlertTriangle
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
  const [error, setError] = useState(null);

  const fetchAnalytics = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      api.getAnalytics(),
      api.getEvaluation()
    ])
      .then(([aData, eData]) => {
        setAnalytics(aData);
        setEvalData(eData);
      })
      .catch((err) => {
        console.error(err);
        setError(err.message || 'Unable to retrieve organizational analytics from backend.');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchAnalytics();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 font-mono">
        <div className="p-4 bg-[#FFE600] border-2 border-black shadow-[4px_4px_0px_0px_#000] font-black uppercase tracking-wider flex items-center gap-3">
          <div className="h-4 w-4 border-2 border-black border-t-transparent animate-spin rounded-full" />
          <span>COMPILING ORGANIZATIONAL TELEMETRY...</span>
        </div>
      </div>
    );
  }

  if (error || !analytics) {
    return (
      <div className="border-2 border-black bg-white p-6 text-center space-y-4 my-8 max-w-lg mx-auto shadow-[4px_4px_0px_0px_#000]">
        <div className="inline-flex p-3 bg-[#FF3366] text-white border-2 border-black shadow-[3px_3px_0px_0px_#000]">
          <AlertTriangle className="h-6 w-6 stroke-[2.5]" />
        </div>
        <h3 className="text-base font-black uppercase text-black">Analytics Pipeline Unavailable</h3>
        <p className="text-xs font-mono text-slate-700">
          {error || 'Unable to retrieve organizational analytics from backend.'}
        </p>
        <button
          onClick={fetchAnalytics}
          className="brutal-btn px-4 py-2 text-xs font-mono bg-[#FFE600] text-black"
        >
          RETRY CONNECTION
        </button>
      </div>
    );
  }

  const modelBarData = evalData?.models ? Object.entries(evalData.models).map(([key, val]) => ({
    name: key.replace(/_/g, ' '),
    detection_rate: val.detection_rate_pct,
    f1_score: Math.round(val.f1_score * 100),
    fp_rate: val.false_positives_per_1000
  })) : [];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="border-2 border-black bg-[#FFFDF0] p-4 shadow-[4px_4px_0px_0px_#000000] flex items-center justify-between">
        <div>
          <h2 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2">
            <span className="p-1 bg-[#FFE600] border border-black shadow-[1px_1px_0px_#000]">
              <BarChart3 className="h-4 w-4 stroke-[2.5]" />
            </span>
            <span>Communication Dynamics & Threat Analytics</span>
          </h2>
          <p className="text-[11px] text-slate-700 font-mono mt-0.5">
            Temporal communication distributions, external domain anomalies, and algorithmic comparative benchmarks
          </p>
        </div>
        <span className="text-xs font-mono font-bold bg-white px-2.5 py-1 border-2 border-black shadow-[2px_2px_0px_#000]">
          INT396 TELEMETRY
        </span>
      </div>

      {/* Grid: Activity Trends & Domain Risk */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Email Activity Over Time */}
        <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000]">
          <div className="flex items-center justify-between border-b-2 border-black pb-3 mb-4">
            <div>
              <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 bg-[#00F0FF] border border-black" />
                <span>Audit Volume Over Time</span>
              </h3>
              <p className="text-[11px] text-slate-600 font-mono mt-0.5">Total communications vs flagged threat volume</p>
            </div>
            <span className="text-[10px] font-mono font-bold bg-[#FFE600] text-black px-2 py-0.5 border border-black shadow-[1px_1px_0px_#000]">
              LIVE AUDIT
            </span>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={analytics.timeline_data || []}>
                <defs>
                  <linearGradient id="scansGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00F0FF" stopOpacity={0.6} />
                    <stop offset="95%" stopColor="#00F0FF" stopOpacity={0.1} />
                  </linearGradient>
                  <linearGradient id="threatsGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF3366" stopOpacity={0.7} />
                    <stop offset="95%" stopColor="#FF3366" stopOpacity={0.2} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" stroke="#000000" fontSize={10} tickLine={true} fontWeight="bold" />
                <YAxis stroke="#000000" fontSize={10} tickLine={true} fontWeight="bold" />
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
                <Area type="monotone" dataKey="total_scans" stroke="#000000" strokeWidth={2} fillOpacity={1} fill="url(#scansGrad)" name="Total Scans" />
                <Area type="monotone" dataKey="threats" stroke="#000000" strokeWidth={2} fillOpacity={1} fill="url(#threatsGrad)" name="Flagged Threats" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Model Detection vs False Positive Comparison */}
        <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000]">
          <div className="flex items-center justify-between border-b-2 border-black pb-3 mb-4">
            <div>
              <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 bg-[#FFE600] border border-black" />
                <span>Detection Rate vs False Alarms</span>
              </h3>
              <p className="text-[11px] text-slate-600 font-mono mt-0.5">Held-out benchmark evaluated on identical data</p>
            </div>
            <span className="text-[10px] font-mono font-bold bg-[#00E599] text-black px-2 py-0.5 border border-black shadow-[1px_1px_0px_#000]">
              TEST SET: 859
            </span>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={modelBarData}>
                <XAxis dataKey="name" stroke="#000000" fontSize={10} tickLine={true} fontWeight="bold" />
                <YAxis stroke="#000000" fontSize={10} tickLine={true} fontWeight="bold" />
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
                <Legend wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace', fontWeight: 'bold', paddingTop: '10px' }} />
                <Bar dataKey="detection_rate" fill="#00E599" stroke="#000000" strokeWidth={2} name="Detection Rate (%)" />
                <Bar dataKey="fp_rate" fill="#FFE600" stroke="#000000" strokeWidth={2} name="False Positives / 1k" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* External Domain Anomaly Table */}
      <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000]">
        <div className="flex items-center justify-between border-b-2 border-black pb-3 mb-4">
          <div>
            <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2">
              <span className="p-1 bg-[#00F0FF] border border-black">
                <Globe className="h-3.5 w-3.5 stroke-[2.5]" />
              </span>
              <span>Top External Sender Domains</span>
            </h3>
            <p className="text-[11px] text-slate-600 font-mono mt-0.5">External domains observed with average anomaly scores</p>
          </div>
        </div>

        <div className="overflow-x-auto border-2 border-black">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="bg-[#FFE600] border-b-2 border-black text-black font-black uppercase text-[11px]">
                <th className="py-2.5 px-3 border-r-2 border-black">External Domain</th>
                <th className="py-2.5 px-3 border-r-2 border-black">Occurrence Count</th>
                <th className="py-2.5 px-3 border-r-2 border-black">Average Risk Score</th>
                <th className="py-2.5 px-3">Risk Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y-2 divide-black bg-white">
              {analytics.top_external_domains?.map((dom) => (
                <tr key={dom.domain} className="hover:bg-[#FFFDF0] transition-colors">
                  <td className="py-3 px-3 text-black font-black border-r-2 border-black">{dom.domain}</td>
                  <td className="py-3 px-3 text-black font-bold border-r-2 border-black">{dom.count}</td>
                  <td className="py-3 px-3 text-black font-black border-r-2 border-black">{dom.avg_risk}</td>
                  <td className="py-3 px-3">
                    <span className={`inline-flex px-2 py-0.5 text-[10px] font-mono font-black uppercase border-2 border-black shadow-[1.5px_1.5px_0px_#000] ${
                      dom.avg_risk >= 0.70 ? 'bg-[#FF3366] text-white' :
                      dom.avg_risk >= 0.45 ? 'bg-[#FF8800] text-black' :
                      'bg-[#00E599] text-black'
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
