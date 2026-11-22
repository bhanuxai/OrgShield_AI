import React, { useState, useEffect } from 'react';
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Link as LinkIcon,
  Clock,
  Server,
  FileText,
  Send,
  CheckCircle,
  HelpCircle,
  Hash,
  Play
} from 'lucide-react';
import { api } from '../services/api';

const SAMPLE_TEMPLATES = [
  {
    title: 'Credential Phishing (IP URL)',
    sender: 'support@o365-update-portal.xyz',
    recipients: ['pallen@enron.com'],
    reply_to: 'harvest@bad-server.xyz',
    subject: 'URGENT: Microsoft 365 Password Expires in 2 Hours',
    body: 'Dear customer, your corporate password is set to expire today. Please verify your credentials immediately at http://198.51.100.23/owa/login.php to prevent mailbox suspension.'
  },
  {
    title: 'CEO BEC Wire Transfer',
    sender: 'kenneth.lay@enron-executives.com',
    recipients: ['accounting@enron.com'],
    reply_to: 'exec.wire@anonymous-relay.net',
    subject: 'Confidential: Urgent Wire Transfer Needed Today',
    body: 'Hi, I am in an executive meeting and cannot take calls. Please process an immediate wire transfer of $340,000 for acquisition escrow. Account details: http://203.0.113.88/invoices/wire.pdf. Thanks, Ken.'
  },
  {
    title: 'Legitimate Enron Meeting',
    sender: 'phillip.allen@enron.com',
    recipients: ['john.arnold@enron.com'],
    reply_to: '',
    subject: 'Natural gas pipeline volume forecast for Q4',
    body: 'John, please review the latest storage capacity projections for the El Paso pipeline before our Monday team meeting. Best regards, Phillip.'
  }
];

export default function EmailInvestigation({ initialAlertId }) {
  // Input form state
  const [activeMode, setActiveMode] = useState('fields'); // 'fields' | 'raw'
  const [sender, setSender] = useState('');
  const [recipients, setRecipients] = useState('user@enron.com');
  const [replyTo, setReplyTo] = useState('');
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [rawEmail, setRawEmail] = useState('');
  const [selectedModel, setSelectedModel] = useState('one_class_svm');

  // Result state
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  // Load initial alert if directed from inbox
  useEffect(() => {
    if (initialAlertId) {
      api.getAlertDetail(initialAlertId)
        .then((alert) => {
          setScanResult({
            alert_id: alert.alert_id,
            risk_score: alert.risk_score,
            risk_category: alert.risk_category,
            is_threat: alert.is_threat,
            threshold: 0.4819,
            model_used: alert.model_used,
            explanation: alert.explanation,
            anomaly_indicators: alert.anomaly_indicators || [],
            suspicious_urls: alert.suspicious_urls || [],
            email_metadata: {
              sender: alert.sender,
              sender_domain: alert.sender_domain,
              recipients: alert.recipients,
              subject: alert.subject,
              body_snippet: alert.body_snippet,
              date: alert.timestamp
            },
            forensics: alert.forensics || {},
            scanned_at: alert.timestamp
          });
          setSender(alert.sender || '');
          setSubject(alert.subject || '');
          setBody(alert.body_snippet || '');
        })
        .catch(console.error);
    }
  }, [initialAlertId]);

  const handleApplyTemplate = (tmpl) => {
    setActiveMode('fields');
    setSender(tmpl.sender);
    setRecipients(tmpl.recipients.join(', '));
    setReplyTo(tmpl.reply_to);
    setSubject(tmpl.subject);
    setBody(tmpl.body);
  };

  const handleRunScan = async (e) => {
    e.preventDefault();
    setScanning(true);
    setErrorMsg(null);

    try {
      let payload = { model_name: selectedModel };
      if (activeMode === 'raw') {
        if (!rawEmail.trim()) {
          throw new Error('Please paste raw email headers and body text.');
        }
        payload.raw_email = rawEmail;
      } else {
        if (!sender.trim() || (!subject.trim() && !body.trim())) {
          throw new Error('Sender and at least Subject or Body are required.');
        }
        payload.sender = sender.trim();
        payload.recipients = recipients.split(',').map((r) => r.trim()).filter(Boolean);
        payload.reply_to = replyTo.trim() || undefined;
        payload.subject = subject.trim();
        payload.body = body.trim();
      }

      const res = await api.scanEmail(payload);
      setScanResult(res);
    } catch (err) {
      setErrorMsg(err.message || 'Scan failed.');
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Interactive Scanner Panel */}
      <div className="cyber-card p-5">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 mb-4 border-b border-slate-800/80 pb-4">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-wide flex items-center gap-2">
              <Search className="h-4 w-4 text-cyan-400" />
              <span>Real-Time Email Threat Inspector</span>
            </h2>
            <p className="text-[11px] text-slate-400">
              Submit raw RFC 2822 headers or structured fields for multi-dimensional anomaly detection
            </p>
          </div>

          {/* Quick Pre-fill Templates */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] text-slate-500 font-mono uppercase mr-1">Load Sample:</span>
            {SAMPLE_TEMPLATES.map((tmpl, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleApplyTemplate(tmpl)}
                className="px-2.5 py-1 rounded bg-slate-900 hover:bg-cyan-950 text-slate-300 hover:text-cyan-400 border border-slate-800 hover:border-cyan-800 text-[11px] font-mono transition-colors"
              >
                {tmpl.title}
              </button>
            ))}
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleRunScan} className="space-y-4">
          {/* Mode Switch & Model Selector */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800 text-xs font-mono">
              <button
                type="button"
                onClick={() => setActiveMode('fields')}
                className={`px-3 py-1 rounded-md transition-colors ${
                  activeMode === 'fields' ? 'bg-cyan-950 text-cyan-400 font-semibold' : 'text-slate-400 hover:text-white'
                }`}
              >
                Structured Fields
              </button>
              <button
                type="button"
                onClick={() => setActiveMode('raw')}
                className={`px-3 py-1 rounded-md transition-colors ${
                  activeMode === 'raw' ? 'bg-cyan-950 text-cyan-400 font-semibold' : 'text-slate-400 hover:text-white'
                }`}
              >
                Raw RFC 2822 MIME
              </button>
            </div>

            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="text-slate-400">Model Engine:</span>
              <select
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                className="px-3 py-1 rounded-lg bg-slate-900 border border-slate-800 text-cyan-400 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="isolation_forest">Isolation Forest (Unsupervised)</option>
                <option value="one_class_svm">One-Class SVM (Unsupervised)</option>
                <option value="local_outlier_factor">Local Outlier Factor (Novelty)</option>
                <option value="rule_based_baseline">Rule-Based Baseline (Deterministic)</option>
              </select>
            </div>
          </div>

          {activeMode === 'fields' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400">Sender (From Address)</label>
                <input
                  type="text"
                  placeholder="e.g. support@portal-update.xyz"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400">Recipients (Comma separated)</label>
                <input
                  type="text"
                  placeholder="e.g. pallen@enron.com, skilling@enron.com"
                  value={recipients}
                  onChange={(e) => setRecipients(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400">Reply-To Address (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. harvest@bad-server.xyz"
                  value={replyTo}
                  onChange={(e) => setReplyTo(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono text-slate-400">Subject</label>
                <input
                  type="text"
                  placeholder="e.g. ACTION REQUIRED: Immediate system update"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
                />
              </div>

              <div className="md:col-span-2 space-y-1">
                <label className="text-[11px] font-mono text-slate-400">Email Body Text</label>
                <textarea
                  rows={4}
                  placeholder="Paste or write email body here..."
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
                />
              </div>
            </div>
          ) : (
            <div className="space-y-1">
              <label className="text-[11px] font-mono text-slate-400">Raw RFC 2822 Email (Headers + Body)</label>
              <textarea
                rows={8}
                placeholder="From: ...&#10;To: ...&#10;Subject: ...&#10;&#10;Body text..."
                value={rawEmail}
                onChange={(e) => setRawEmail(e.target.value)}
                className="w-full p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/60"
              />
            </div>
          )}

          {errorMsg && (
            <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-400 text-xs font-mono">
              {errorMsg}
            </div>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={scanning}
              className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium text-xs flex items-center gap-2 shadow-lg shadow-cyan-500/20 disabled:opacity-50 transition-all font-mono"
            >
              <Play className={`h-3.5 w-3.5 fill-current ${scanning ? 'animate-spin' : ''}`} />
              <span>{scanning ? 'Analyzing Anomaly Vectors...' : 'Run Forensic Threat Scan'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Investigation Details View */}
      {scanResult && (
        <div className="space-y-6">
          {/* Risk Verdict Banner */}
          <div className={`p-5 rounded-xl border flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
            scanResult.is_threat
              ? 'bg-rose-950/30 border-rose-800/80'
              : 'bg-emerald-950/30 border-emerald-800/80'
          }`}>
            <div className="flex items-start gap-4">
              <div className={`p-3 rounded-xl ${
                scanResult.is_threat ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'
              }`}>
                {scanResult.is_threat ? (
                  <ShieldAlert className="h-7 w-7" />
                ) : (
                  <ShieldCheck className="h-7 w-7" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold tracking-wider uppercase ${
                    scanResult.risk_category === 'Critical' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                    scanResult.risk_category === 'High' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                    scanResult.risk_category === 'Medium' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                    'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  }`}>
                    {scanResult.risk_category} Risk
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    Model: <strong className="text-slate-200">{scanResult.model_used}</strong>
                  </span>
                </div>
                <h3 className="text-base font-semibold text-white mt-1">
                  {scanResult.is_threat ? 'Anomalous Threat Flagged' : 'Communication Appears Legitimate'}
                </h3>
                <p className="text-xs text-slate-300 mt-1 max-w-2xl">
                  {scanResult.explanation}
                </p>
              </div>
            </div>

            <div className="bg-slate-900/90 p-4 rounded-xl border border-slate-800 text-right font-mono min-w-[150px]">
              <div className="text-[10px] text-slate-400 uppercase">Threat Score</div>
              <div className={`text-2xl font-bold ${
                scanResult.is_threat ? 'text-rose-400' : 'text-emerald-400'
              }`}>
                {scanResult.risk_score.toFixed(4)}
              </div>
              <div className="text-[10px] text-slate-500">Threshold: {scanResult.threshold}</div>
            </div>
          </div>

          {/* Anomaly Indicators Breakdown */}
          {scanResult.anomaly_indicators?.length > 0 && (
            <div className="cyber-card p-5">
              <h4 className="text-xs font-semibold text-white tracking-wider uppercase mb-3 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                <span>Detected Anomaly Indicators ({scanResult.anomaly_indicators.length})</span>
              </h4>
              <div className="space-y-2">
                {scanResult.anomaly_indicators.map((ind, i) => (
                  <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-slate-900/80 border border-slate-800/80 text-xs">
                    <span className="h-2 w-2 rounded-full bg-rose-400 flex-shrink-0" />
                    <span className="text-slate-200 font-mono">{ind}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Forensic Deep Dive Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Header & Routing Forensics */}
            <div className="cyber-card p-5 space-y-4">
              <h4 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2">
                <Server className="h-4 w-4 text-cyan-400" />
                <span>Header & Routing Forensics</span>
              </h4>

              <div className="space-y-3 text-xs">
                <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-slate-800/60">
                  <span className="text-slate-400">Sender Domain:</span>
                  <span className="font-mono text-cyan-400">{scanResult.email_metadata?.sender_domain || 'Unknown'}</span>
                </div>
                <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-slate-800/60">
                  <span className="text-slate-400">Organization Boundary:</span>
                  <span className={`font-mono ${
                    scanResult.email_metadata?.sender_domain === 'enron.com' ? 'text-emerald-400' : 'text-amber-400'
                  }`}>
                    {scanResult.email_metadata?.sender_domain === 'enron.com' ? 'Internal (enron.com)' : 'External Origin'}
                  </span>
                </div>
                <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-slate-800/60">
                  <span className="text-slate-400">Reply-To Address:</span>
                  <span className="font-mono text-slate-300">{scanResult.email_metadata?.reply_to || 'None (Matches From)'}</span>
                </div>
                <div className="flex justify-between p-2.5 rounded bg-slate-900/60 border border-slate-800/60">
                  <span className="text-slate-400">Routing Hops:</span>
                  <span className="font-mono text-slate-300">{scanResult.forensics?.routing_analysis?.hop_count || 0}</span>
                </div>
              </div>
            </div>

            {/* URL Forensics & Geolocation Guard */}
            <div className="cyber-card p-5 space-y-4">
              <h4 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2">
                <Globe className="h-4 w-4 text-cyan-400" />
                <span>URL & Geolocation Intelligence</span>
              </h4>

              <div className="space-y-3 text-xs">
                {/* Geolocation Verdict */}
                <div className="p-3 rounded bg-slate-900/60 border border-slate-800/60">
                  <div className="text-[11px] text-slate-400 mb-1">Public IP Geolocation Status:</div>
                  {scanResult.forensics?.geolocation_intelligence?.available ? (
                    <div className="font-mono space-y-1 text-slate-200">
                      <div>IP: {scanResult.forensics.geolocation_intelligence.primary_public_ip}</div>
                      <div className="text-cyan-400">
                        {scanResult.forensics.geolocation_intelligence.city}, {scanResult.forensics.geolocation_intelligence.country} ({scanResult.forensics.geolocation_intelligence.asn})
                      </div>
                      <p className="text-[10px] text-slate-500 italic mt-1">
                        {scanResult.forensics.geolocation_intelligence.disclaimer}
                      </p>
                    </div>
                  ) : (
                    <div className="font-mono text-slate-400">
                      <span className="text-amber-400">Unavailable</span> - {scanResult.forensics?.geolocation_intelligence?.reason || 'No routable public IP in headers.'}
                      <p className="text-[10px] text-slate-500 italic mt-1">
                        OrgShield AI does not fabricate geographic coordinates for private RFC 1918 or missing IPs.
                      </p>
                    </div>
                  )}
                </div>

                {/* Detected URLs */}
                <div>
                  <div className="text-[11px] text-slate-400 mb-1.5">URLs Detected in Message:</div>
                  {scanResult.email_metadata?.urls?.length > 0 ? (
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {scanResult.email_metadata.urls.map((u, i) => (
                        <div key={i} className="flex items-center gap-2 p-2 rounded bg-slate-900 font-mono text-[11px] text-cyan-400 break-all border border-slate-800">
                          <LinkIcon className="h-3 w-3 flex-shrink-0" />
                          <span>{u}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-500 font-mono text-xs">No URLs found in body or headers.</span>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
