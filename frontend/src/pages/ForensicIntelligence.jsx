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
  const [error, setError] = useState(null);

  const fetchAlerts = () => {
    setLoading(true);
    setError(null);
    api.getAlerts({ limit: 20 })
      .then((data) => {
        const list = data.alerts || [];
        setAlerts(list);
        if (list.length > 0) {
          setSelectedAlert(list[0]);
        }
      })
      .catch((err) => {
        console.error(err);
        setError(err.message || 'Unable to retrieve forensic records from backend.');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchAlerts();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 font-mono">
        <div className="p-4 bg-[#FFE600] border-2 border-black shadow-[4px_4px_0px_0px_#000] font-black uppercase tracking-wider flex items-center gap-3">
          <div className="h-4 w-4 border-2 border-black border-t-transparent animate-spin rounded-full" />
          <span>LOADING FORENSIC DOSSIERS...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="border-2 border-black bg-white p-6 text-center space-y-4 my-8 max-w-lg mx-auto shadow-[4px_4px_0px_0px_#000]">
        <div className="inline-flex p-3 bg-[#FF3366] text-white border-2 border-black shadow-[3px_3px_0px_0px_#000]">
          <AlertTriangle className="h-6 w-6 stroke-[2.5]" />
        </div>
        <h3 className="text-base font-black uppercase text-black">Forensics Pipeline Offline</h3>
        <p className="text-xs font-mono text-slate-700">{error}</p>
        <button
          onClick={fetchAlerts}
          className="brutal-btn px-4 py-2 text-xs font-mono bg-[#FFE600] text-black"
        >
          RETRY CONNECTION
        </button>
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
      <div className="border-2 border-black bg-[#FFFDF0] p-4 shadow-[4px_4px_0px_0px_#000000] flex items-center justify-between">
        <div>
          <h2 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2">
            <span className="p-1 bg-[#FFE600] border border-black shadow-[1px_1px_0px_#000]">
              <Fingerprint className="h-4 w-4 stroke-[2.5]" />
            </span>
            <span>Forensic Intelligence & Network Routing Analysis</span>
          </h2>
          <p className="text-[11px] text-slate-700 font-mono mt-0.5">
            Strict verification boundaries: private IPs marked non-routable; zero invented geolocation coordinates
          </p>
        </div>
        <span className="text-xs font-mono font-bold bg-[#FFE600] px-2.5 py-1 border-2 border-black shadow-[2px_2px_0px_#000]">
          RFC 822 / 2822 INSPECT
        </span>
      </div>

      {/* Main Forensic Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Alert Selector */}
        <div className="border-2 border-black bg-white p-4 lg:col-span-1 space-y-3 shadow-[4px_4px_0px_0px_#000]">
          <div className="flex items-center justify-between border-b-2 border-black pb-2">
            <h3 className="text-xs font-black uppercase text-black tracking-wider">Select Scanned Message</h3>
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 bg-black text-[#FFE600]">
              {alerts.length} ITEMS
            </span>
          </div>

          <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
            {alerts.length === 0 && (
              <div className="text-slate-600 text-xs font-mono p-4 text-center font-bold">
                No alerts available in audit queue.
              </div>
            )}
            {alerts.map((alt) => {
              const isSelected = selectedAlert?.alert_id === alt.alert_id;
              return (
                <button
                  key={alt.alert_id}
                  onClick={() => setSelectedAlert(alt)}
                  className={`w-full p-3 text-left transition-all border-2 border-black ${
                    isSelected
                      ? 'bg-[#FFE600] text-black shadow-[3px_3px_0px_0px_#000] translate-x-1'
                      : 'bg-[#F4F0EA] hover:bg-[#FFFDF0] hover:shadow-[2px_2px_0px_0px_#000]'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs font-mono mb-1">
                    <span className="font-black text-black">{alt.alert_id}</span>
                    <span className={`px-1.5 py-0.5 text-[9px] font-black uppercase border border-black ${
                      alt.is_threat ? 'bg-[#FF3366] text-white' : 'bg-[#00E599] text-black'
                    }`}>
                      {alt.risk_category}
                    </span>
                  </div>
                  <div className="text-xs font-bold text-black truncate">{alt.subject || 'No Subject'}</div>
                  <div className="text-[10px] font-mono font-medium text-slate-700 truncate mt-0.5">{alt.sender}</div>
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
              <div className="border-2 border-black bg-white p-5 space-y-4 shadow-[4px_4px_0px_0px_#000]">
                <div className="flex items-center justify-between border-b-2 border-black pb-3">
                  <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2">
                    <span className="p-1 bg-[#00F0FF] border border-black">
                      <Globe className="h-3.5 w-3.5 stroke-[2.5]" />
                    </span>
                    <span>IP Telemetry & Geolocation Verdict</span>
                  </h3>
                  <span className="text-xs font-mono font-bold text-black bg-[#F4F0EA] px-2 py-0.5 border border-black">
                    ROUTING HOPS: <strong className="text-black">{routing.hop_count || 0}</strong>
                  </span>
                </div>

                {/* Geolocation Status Banner */}
                <div className={`p-4 border-2 border-black font-mono text-xs shadow-[3px_3px_0px_0px_#000] ${
                  geo.available
                    ? 'bg-[#DCFCE7] text-black'
                    : 'bg-[#FFFDF0] text-black'
                }`}>
                  <div className="flex items-center gap-2 font-black mb-1 text-sm uppercase">
                    <Info className="h-4 w-4 stroke-[2.5]" />
                    <span>Geolocation Status: {geo.available ? 'Public IP Identified (Approximate)' : 'Strictly Unavailable'}</span>
                  </div>

                  {geo.available ? (
                    <div className="space-y-1 mt-2 text-[11px] font-bold">
                      <div>Primary Routable IP: <span className="bg-white px-1.5 border border-black">{geo.primary_public_ip}</span></div>
                      <div>Inferred Location: <span className="bg-[#FFE600] px-1.5 border border-black">{geo.city}, {geo.country}</span></div>
                      <div>Autonomous System: <span className="bg-white px-1.5 border border-black">{geo.asn}</span></div>
                      <p className="text-[10px] text-slate-700 italic mt-2 border-t border-black/30 pt-2 font-normal">
                        {geo.disclaimer}
                      </p>
                    </div>
                  ) : (
                    <div className="text-[11px] space-y-1 mt-1 text-slate-800 font-bold">
                      <p>{geo.reason || 'No public IPv4 headers detected in communication hops.'}</p>
                      <p className="text-[10px] text-slate-600 italic font-normal">
                        {geo.disclaimer || 'Internal RFC 1918 private IPs are non-routable on the public internet.'}
                      </p>
                    </div>
                  )}
                </div>

                {/* IP Addresses Inspected in Routing Hops */}
                <div>
                  <h4 className="text-[11px] font-mono font-black text-black uppercase tracking-wider mb-2">
                    Inspected IP Addresses in Received Hops
                  </h4>
                  {routing.inspected_ips?.length > 0 ? (
                    <div className="space-y-2 font-mono text-xs">
                      {routing.inspected_ips.map((ipRec, i) => (
                        <div key={i} className="flex items-center justify-between p-2.5 border-2 border-black bg-[#F4F0EA] shadow-[2px_2px_0px_#000]">
                          <div className="flex items-center gap-2">
                            <Network className="h-3.5 w-3.5 text-black stroke-[2.5]" />
                            <span className="font-black text-black">{ipRec.ip}</span>
                            <span className="text-[9px] font-bold px-1.5 py-0.5 bg-white text-black border border-black">
                              {ipRec.type}
                            </span>
                          </div>
                          <span className={`text-[10px] font-bold px-2 py-0.5 border border-black ${
                            ipRec.is_public ? 'bg-[#00E599] text-black' : 'bg-slate-200 text-slate-700'
                          }`}>
                            {ipRec.status_note}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-xs font-mono text-slate-600 font-bold p-3 border-2 border-black bg-[#F4F0EA]">
                      No Received IP headers available in this message.
                    </div>
                  )}
                </div>
              </div>

              {/* Header Inconsistencies Card */}
              <div className="border-2 border-black bg-white p-5 space-y-3 shadow-[4px_4px_0px_0px_#000]">
                <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2 border-b-2 border-black pb-2">
                  <span className="p-1 bg-[#FFE600] border border-black">
                    <AlertTriangle className="h-3.5 w-3.5 stroke-[2.5]" />
                  </span>
                  <span>Header Inconsistency Audit</span>
                </h3>

                {headerIssues.length > 0 ? (
                  <div className="space-y-2">
                    {headerIssues.map((issue, idx) => (
                      <div key={idx} className="p-3 border-2 border-black bg-[#FFFDF0] shadow-[2px_2px_0px_#000] text-xs font-mono space-y-1">
                        <div className="flex items-center justify-between text-black font-black">
                          <span className="uppercase">{issue.type}</span>
                          <span className="text-[9px] px-1.5 py-0.5 bg-[#FF8800] text-black border border-black font-black uppercase">
                            SEVERITY: {issue.severity}
                          </span>
                        </div>
                        <p className="text-slate-800 text-[11px] font-bold">{issue.description}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 p-3 border-2 border-black bg-[#DCFCE7] text-xs font-mono text-black font-bold shadow-[2px_2px_0px_#000]">
                    <CheckCircle2 className="h-4 w-4 stroke-[2.5] flex-shrink-0" />
                    <span>No structural header discrepancies detected. From, Reply-To, and Message-ID align with RFC standards.</span>
                  </div>
                )}
              </div>

              {/* URL Threat Intelligence Card */}
              <div className="border-2 border-black bg-white p-5 space-y-3 shadow-[4px_4px_0px_0px_#000]">
                <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2 border-b-2 border-black pb-2">
                  <span className="p-1 bg-[#00F0FF] border border-black">
                    <Server className="h-3.5 w-3.5 stroke-[2.5]" />
                  </span>
                  <span>URL Threat Intelligence ({urlIntel.length})</span>
                </h3>

                {urlIntel.length > 0 ? (
                  <div className="space-y-2">
                    {urlIntel.map((item, idx) => (
                      <div key={idx} className="p-3 border-2 border-black bg-[#F4F0EA] shadow-[2px_2px_0px_#000] text-xs font-mono space-y-1.5">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-black font-black truncate max-w-[400px] bg-white px-2 py-0.5 border border-black">{item.url}</span>
                          <span className={`text-[10px] px-2 py-0.5 border-2 border-black font-black uppercase ${
                            item.risk_level === 'CRITICAL' ? 'bg-[#FF3366] text-white' :
                            item.risk_level === 'MEDIUM' ? 'bg-[#FFE600] text-black' :
                            'bg-white text-black'
                          }`}>
                            {item.risk_level} RISK
                          </span>
                        </div>
                        {item.detected_flags?.length > 0 && (
                          <div className="flex items-center gap-1.5 flex-wrap pt-1">
                            <span className="text-[10px] text-black font-black uppercase">FLAGS:</span>
                            {item.detected_flags.map((flag, fIdx) => (
                              <span key={fIdx} className="text-[9px] px-1.5 py-0.5 bg-[#FFE4E6] text-[#FF3366] border border-black font-bold uppercase">
                                {flag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-slate-600 font-bold p-3 border-2 border-black bg-[#F4F0EA]">
                    No URLs detected in this communication.
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="border-2 border-black bg-white p-12 text-center text-slate-700 font-mono text-xs font-bold shadow-[4px_4px_0px_0px_#000]">
              Select an email from the left to view comprehensive forensic telemetry.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
