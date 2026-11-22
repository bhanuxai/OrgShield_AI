import React, { useState, useEffect } from 'react';
import {
  Fingerprint,
  Server,
  Globe,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Info,
  CheckCircle2,
  XCircle,
  Network
} from 'lucide-react';
import { api } from '../services/api';

export default function ForensicIntelligence() {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAlerts({ limit: 20 })
      .then((data) => {
        const list = data.alerts || [];
        setAlerts(list);
        if (list.length > 0) {
          setSelectedAlert(list[0]);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 font-mono text-sm">
        Loading forensic records...
      </div>
    );
  }

  const forensics = selectedAlert?.forensics || {};
  const geo = forensics.geolocation_intelligence || {};
  const routing = forensics.routing_analysis || {};
  const urlIntel = forensics.url_threat_intelligence || [];
  const headerIssues = forensics.header_inconsistencies || [];

  return (
    <div className="space-y-6">
      {/* Top Banner Notice */}
      <div className="cyber-card p-4 flex items-center justify-between">
        <div>
          <h2 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2">
            <Fingerprint className="h-4 w-4 text-cyan-400" />
            <span>Forensic Intelligence & Network Routing Analysis</span>
          </h2>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
            Strict verification boundaries: private IPs marked unavailable; zero invented geolocation coordinates
          </p>
        </div>
      </div>

      {/* Main Forensic Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Alert Selector */}
        <div className="cyber-card p-4 lg:col-span-1 space-y-3">
          <h3 className="text-xs font-semibold text-white tracking-wider uppercase mb-2">Select Scanned Message</h3>
          <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
            {alerts.map((alt) => {
              const isSelected = selectedAlert?.alert_id === alt.alert_id;
              return (
                <button
                  key={alt.alert_id}
                  onClick={() => setSelectedAlert(alt)}
                  className={`w-full p-3 rounded-lg text-left transition-all border ${
                    isSelected
                      ? 'bg-cyan-950/70 border-cyan-500/60 shadow-[0_0_15px_rgba(14,165,233,0.15)]'
                      : 'bg-slate-900/60 border-slate-800/80 hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-mono mb-1">
                    <span className="font-semibold text-cyan-400">{alt.alert_id}</span>
                    <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                      alt.is_threat ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    }`}>
                      {alt.risk_category}
                    </span>
                  </div>
                  <div className="text-xs font-medium text-slate-200 truncate">{alt.subject || 'No Subject'}</div>
                  <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">{alt.sender}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right 2 Columns: Deep Forensic Details */}
        <div className="lg:col-span-2 space-y-6">
          {selectedAlert ? (
            <>
              {/* Geolocation & Routing Intelligence Card */}
              <div className="cyber-card p-5 space-y-4">
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                  <h3 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2">
                    <Globe className="h-4 w-4 text-cyan-400" />
                    <span>IP Telemetry & Geolocation Verdict</span>
                  </h3>
                  <span className="text-xs font-mono text-slate-400">
                    Routing Hops: <strong className="text-cyan-400">{routing.hop_count || 0}</strong>
                  </span>
                </div>

                {/* Geolocation Status Banner */}
                <div className={`p-4 rounded-xl border font-mono text-xs ${
                  geo.available
                    ? 'bg-cyan-950/40 border-cyan-800/60 text-cyan-300'
                    : 'bg-slate-900/80 border-slate-800 text-slate-400'
                }`}>
                  <div className="flex items-center gap-2 font-semibold mb-1">
                    <Info className="h-4 w-4 text-cyan-400" />
                    <span>Geolocation Status: {geo.available ? 'Public IP Identified (Approximate)' : 'Strictly Unavailable'}</span>
                  </div>

                  {geo.available ? (
                    <div className="space-y-1 mt-2 text-[11px] text-slate-300">
                      <div>Primary Routable IP: <strong className="text-cyan-400">{geo.primary_public_ip}</strong></div>
                      <div>Inferred Location: <strong>{geo.city}, {geo.country}</strong></div>
                      <div>Autonomous System: <strong>{geo.asn}</strong></div>
                      <p className="text-[10px] text-slate-400 italic mt-2 border-t border-cyan-800/40 pt-2">
                        {geo.disclaimer}
                      </p>
                    </div>
                  ) : (
                    <div className="text-[11px] space-y-1 mt-1 text-slate-400">
                      <p>{geo.reason || 'No public IPv4 headers detected.'}</p>
                      <p className="text-[10px] text-slate-500 italic">
                        {geo.disclaimer || 'Internal RFC 1918 private IPs are non-routable.'}
                      </p>
                    </div>
                  )}
                </div>

                {/* IP Addresses Inspected in Routing Hops */}
                <div>
                  <h4 className="text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-2">
                    Inspected IP Addresses in Received Hops
                  </h4>
                  {routing.inspected_ips?.length > 0 ? (
                    <div className="space-y-1.5 font-mono text-xs">
                      {routing.inspected_ips.map((ipRec, i) => (
                        <div key={i} className="flex items-center justify-between p-2.5 rounded bg-slate-900 border border-slate-800">
                          <div className="flex items-center gap-2">
                            <Network className="h-3.5 w-3.5 text-slate-500" />
                            <span className="text-slate-200">{ipRec.ip}</span>
                            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                              {ipRec.type}
                            </span>
                          </div>
                          <span className={`text-[10px] ${ipRec.is_public ? 'text-cyan-400' : 'text-slate-500'}`}>
                            {ipRec.status_note}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-xs font-mono text-slate-500 p-3 rounded bg-slate-900 border border-slate-800">
                      No Received IP headers available in this message.
                    </div>
                  )}
                </div>
              </div>

              {/* Header Inconsistencies Card */}
              <div className="cyber-card p-5 space-y-3">
                <h3 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                  <span>Header Inconsistency Audit</span>
                </h3>

                {headerIssues.length > 0 ? (
                  <div className="space-y-2">
                    {headerIssues.map((issue, idx) => (
                      <div key={idx} className="p-3 rounded-lg bg-amber-950/20 border border-amber-800/40 text-xs font-mono space-y-1">
                        <div className="flex items-center justify-between text-amber-400 font-bold">
                          <span>{issue.type}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-950 border border-amber-800">
                            Severity: {issue.severity}
                          </span>
                        </div>
                        <p className="text-slate-300 text-[11px]">{issue.description}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 p-3 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-xs font-mono text-emerald-400">
                    <CheckCircle2 className="h-4 w-4 flex-shrink-0" />
                    <span>No structural header discrepancies detected. From, Reply-To, and Message-ID align with standards.</span>
                  </div>
                )}
              </div>

              {/* URL Threat Intelligence Card */}
              <div className="cyber-card p-5 space-y-3">
                <h3 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2">
                  <Server className="h-4 w-4 text-cyan-400" />
                  <span>URL Threat Intelligence ({urlIntel.length})</span>
                </h3>

                {urlIntel.length > 0 ? (
                  <div className="space-y-2">
                    {urlIntel.map((item, idx) => (
                      <div key={idx} className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-cyan-400 truncate max-w-[400px]">{item.url}</span>
                          <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                            item.risk_level === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                            item.risk_level === 'MEDIUM' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                            'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}>
                            {item.risk_level} Risk
                          </span>
                        </div>
                        {item.detected_flags?.length > 0 && (
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="text-[10px] text-slate-500">Flags:</span>
                            {item.detected_flags.map((flag, fIdx) => (
                              <span key={fIdx} className="text-[9px] px-1.5 py-0.5 rounded bg-rose-950/60 text-rose-300 border border-rose-800/50">
                                {flag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-slate-500 p-3 rounded bg-slate-900 border border-slate-800">
                    No URLs detected in this communication.
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="cyber-card p-12 text-center text-slate-500 font-mono text-xs">
              Select an email from the left to view comprehensive forensic telemetry.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
