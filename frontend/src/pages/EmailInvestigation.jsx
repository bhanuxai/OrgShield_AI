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
  Play,
  Zap,
  Terminal
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
    title: 'Account Suspension Lure',
    sender: 'alert-4@wellsfargo-verify.loan',
    recipients: ['treasury@enron.com'],
    reply_to: 'security-action@phish-domain.org',
    subject: 'Urgent: Corporate Account Suspended Due to Suspicious Activity',
    body: 'Immediate action required. Unauthorized access attempts detected on your commercial account. Verify account credentials immediately at http://192.0.2.144/auth/verify to restore online trading access.'
  },
  {
    title: 'Malware Invoice (.zip)',
    sender: 'billing@vendor-invoices-service.info',
    recipients: ['accounts.payable@enron.com'],
    reply_to: 'dropzone@attacker-c2.net',
    subject: 'Overdue Invoice #INV-882914 - Immediate Remittance Required',
    body: 'Please find attached the past due invoice statement for services rendered in Q3. Download the remittance document package here: http://198.51.100.89/downloads/invoice_statement_oct2001.zip'
  },
  {
    title: 'Legitimate Internal Meeting',
    sender: 'phillip.allen@enron.com',
    recipients: ['john.arnold@enron.com'],
    reply_to: '',
    subject: 'Natural gas pipeline volume forecast for Q4',
    body: 'John, please review the latest storage capacity projections for the El Paso pipeline before our Monday team meeting. Best regards, Phillip.'
  },
  {
    title: 'Legitimate Platts Newsletter',
    sender: 'newsletter@platts.com',
    recipients: ['all_traders@enron.com'],
    reply_to: '',
    subject: 'Platts Energy Daily: Natural gas storage levels rise',
    body: 'Daily market summary for Henry Hub cash prices and NYMEX prompt month futures. Read full report on platts.com.'
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
            threshold: alert.threshold || 0.7912,
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
        .catch((err) => {
          console.error(err);
          setErrorMsg('Failed to load alert details: ' + (err.message || 'Network error'));
        });
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
      <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000]">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 mb-4 border-b-2 border-black pb-4">
          <div>
            <h2 className="text-sm font-black text-black tracking-tight uppercase flex items-center gap-2">
              <span className="p-1 bg-[#FFE600] border border-black shadow-[1px_1px_0px_#000]">
                <Search className="h-4 w-4 stroke-[2.5]" />
              </span>
              <span>Interactive Email Threat Inspector</span>
            </h2>
            <p className="text-[11px] text-slate-700 font-mono mt-0.5">
              Submit structured fields or raw RFC 2822 headers for multi-vector anomaly discovery
            </p>
          </div>

          {/* Quick Pre-fill Templates */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] text-black font-mono font-bold uppercase mr-1 bg-[#FFE600] px-1.5 py-0.5 border border-black">
              LOAD SCENARIO:
            </span>
            {SAMPLE_TEMPLATES.map((tmpl, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleApplyTemplate(tmpl)}
                className="brutal-btn px-2.5 py-1 bg-white hover:bg-[#FFE600] text-black text-[10px] font-mono font-bold"
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
            <div className="flex items-center border-2 border-black shadow-[2px_2px_0px_0px_#000] text-xs font-mono font-bold">
              <button
                type="button"
                onClick={() => setActiveMode('fields')}
                className={`px-3 py-1.5 transition-colors uppercase ${
                  activeMode === 'fields' ? 'bg-[#FFE600] text-black font-black' : 'bg-white text-black hover:bg-[#FFFDF0]'
                }`}
              >
                Structured Fields
              </button>
              <button
                type="button"
                onClick={() => setActiveMode('raw')}
                className={`px-3 py-1.5 border-l-2 border-black transition-colors uppercase ${
                  activeMode === 'raw' ? 'bg-[#FFE600] text-black font-black' : 'bg-white text-black hover:bg-[#FFFDF0]'
                }`}
              >
                Raw RFC 2822 MIME
              </button>
            </div>

            <div className="flex items-center gap-2 text-xs font-mono font-bold">
              <span className="text-black uppercase">Model Engine:</span>
              <select
                value={selectedModel}
                onChange={(e) => setSelectedModel(e.target.value)}
                className="px-3 py-1.5 border-2 border-black bg-white text-black font-mono font-bold shadow-[2px_2px_0px_0px_#000] focus:outline-none focus:bg-[#FFFDF0]"
              >
                <option value="isolation_forest">Isolation Forest (Unsupervised)</option>
                <option value="one_class_svm">One-Class SVM (RBF Boundary)</option>
                <option value="local_outlier_factor">Local Outlier Factor (Novelty)</option>
                <option value="rule_based_baseline">Rule-Based Baseline (Deterministic)</option>
              </select>
            </div>
          </div>

          {activeMode === 'fields' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-[11px] font-mono font-black uppercase text-black">Sender (From Address)</label>
                <input
                  type="text"
                  placeholder="e.g. support@portal-update.xyz"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                  className="w-full px-3 py-2 border-2 border-black bg-[#F4F0EA] text-xs font-mono font-bold text-black focus:outline-none focus:bg-[#FFFDF0] focus:shadow-[2px_2px_0px_#000]"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono font-black uppercase text-black">Recipients (Comma separated)</label>
                <input
                  type="text"
                  placeholder="e.g. pallen@enron.com, skilling@enron.com"
                  value={recipients}
                  onChange={(e) => setRecipients(e.target.value)}
                  className="w-full px-3 py-2 border-2 border-black bg-[#F4F0EA] text-xs font-mono font-bold text-black focus:outline-none focus:bg-[#FFFDF0] focus:shadow-[2px_2px_0px_#000]"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono font-black uppercase text-black">Reply-To Address (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. harvest@bad-server.xyz"
                  value={replyTo}
                  onChange={(e) => setReplyTo(e.target.value)}
                  className="w-full px-3 py-2 border-2 border-black bg-[#F4F0EA] text-xs font-mono font-bold text-black focus:outline-none focus:bg-[#FFFDF0] focus:shadow-[2px_2px_0px_#000]"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-mono font-black uppercase text-black">Subject Line</label>
                <input
                  type="text"
                  placeholder="e.g. ACTION REQUIRED: Immediate system update"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className="w-full px-3 py-2 border-2 border-black bg-[#F4F0EA] text-xs font-mono font-bold text-black focus:outline-none focus:bg-[#FFFDF0] focus:shadow-[2px_2px_0px_#000]"
                />
              </div>

              <div className="md:col-span-2 space-y-1">
                <label className="text-[11px] font-mono font-black uppercase text-black">Email Body Text</label>
                <textarea
                  rows={4}
                  placeholder="Paste or write email body here..."
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  className="w-full px-3 py-2 border-2 border-black bg-[#F4F0EA] text-xs font-mono font-bold text-black focus:outline-none focus:bg-[#FFFDF0] focus:shadow-[2px_2px_0px_#000]"
                />
              </div>
            </div>
          ) : (
            <div className="space-y-1">
              <label className="text-[11px] font-mono font-black uppercase text-black">Raw RFC 2822 Email (Headers + Body)</label>
              <textarea
                rows={8}
                placeholder="From: ...&#10;To: ...&#10;Subject: ...&#10;&#10;Body text..."
                value={rawEmail}
                onChange={(e) => setRawEmail(e.target.value)}
                className="w-full p-3 border-2 border-black bg-[#F4F0EA] text-xs font-mono font-bold text-black focus:outline-none focus:bg-[#FFFDF0] focus:shadow-[2px_2px_0px_#000]"
              />
            </div>
          )}

          {errorMsg && (
            <div className="p-3 border-2 border-black bg-[#FFE4E6] text-black text-xs font-mono font-bold shadow-[2px_2px_0px_#000] flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-[#FF3366] stroke-[2.5]" />
              <span>{errorMsg}</span>
            </div>
          )}

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={scanning}
              className="brutal-btn px-6 py-2.5 bg-[#FFE600] hover:bg-[#FFD600] text-black font-black text-xs flex items-center gap-2 shadow-[4px_4px_0px_0px_#000] disabled:opacity-50 font-mono tracking-wider uppercase"
            >
              <Play className={`h-4 w-4 stroke-[2.5] fill-black ${scanning ? 'animate-spin' : ''}`} />
              <span>{scanning ? 'SCANNING ANOMALY VECTORS...' : 'RUN FORENSIC THREAT SCAN'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Investigation Details View */}
      {scanResult && (
        <div className="space-y-6">
          {/* Risk Verdict Banner */}
          <div className={`p-5 border-2 border-black shadow-[6px_6px_0px_0px_#000000] flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
            scanResult.is_threat
              ? 'bg-[#FFE4E6]'
              : 'bg-[#DCFCE7]'
          }`}>
            <div className="flex items-start gap-4">
              <div className={`p-3 border-2 border-black shadow-[2px_2px_0px_0px_#000] flex-shrink-0 ${
                scanResult.is_threat ? 'bg-[#FF3366] text-white' : 'bg-[#00E599] text-black'
              }`}>
                {scanResult.is_threat ? (
                  <ShieldAlert className="h-8 w-8 stroke-[2.5]" />
                ) : (
                  <ShieldCheck className="h-8 w-8 stroke-[2.5]" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2.5 py-0.5 text-xs font-mono font-black uppercase border-2 border-black shadow-[2px_2px_0px_0px_#000] ${
                    scanResult.risk_category === 'Critical' ? 'bg-[#FF3366] text-white' :
                    scanResult.risk_category === 'High' ? 'bg-[#FF8800] text-black' :
                    scanResult.risk_category === 'Medium' ? 'bg-[#FFE600] text-black' :
                    'bg-[#00E599] text-black'
                  }`}>
                    {scanResult.risk_category} RISK LEVEL
                  </span>
                  <span className="text-xs font-mono font-bold text-black bg-white px-2 py-0.5 border border-black">
                    MODEL: <strong className="text-black uppercase">{scanResult.model_used}</strong>
                  </span>
                </div>
                <h3 className="text-lg font-black uppercase text-black mt-1.5 tracking-tight">
                  {scanResult.is_threat ? 'ANOMALOUS THREAT IDENTIFIED' : 'COMMUNICATION APPEARS NORMAL / BENIGN'}
                </h3>
                <p className="text-xs text-slate-800 font-mono font-medium mt-1 max-w-2xl">
                  {scanResult.explanation}
                </p>
              </div>
            </div>

            <div className="bg-white p-4 border-2 border-black shadow-[3px_3px_0px_0px_#000] text-right font-mono min-w-[170px] flex-shrink-0">
              <div className="text-[10px] text-black uppercase font-black">Threat Score</div>
              <div className={`text-3xl font-black ${
                scanResult.is_threat ? 'text-[#FF3366]' : 'text-[#00E599]'
              }`}>
                {scanResult.risk_score.toFixed(4)}
              </div>
              <div className="text-[10px] text-black font-bold border-t border-black/20 pt-1 mt-1">
                Threshold: {scanResult.threshold}
              </div>
            </div>
          </div>

          {/* Anomaly Indicators Breakdown */}
          {scanResult.anomaly_indicators?.length > 0 && (
            <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000]">
              <h4 className="text-xs font-black uppercase text-black tracking-wider mb-3 flex items-center gap-2 border-b-2 border-black pb-2">
                <span className="p-1 bg-[#FFE600] border border-black">
                  <AlertTriangle className="h-3.5 w-3.5 stroke-[2.5]" />
                </span>
                <span>Detected Anomaly Indicators ({scanResult.anomaly_indicators.length})</span>
              </h4>
              <div className="space-y-2">
                {scanResult.anomaly_indicators.map((ind, i) => (
                  <div key={i} className="flex items-center gap-3 p-2.5 border-2 border-black bg-[#FFFDF0] shadow-[2px_2px_0px_#000] text-xs">
                    <span className="h-2.5 w-2.5 bg-[#FF3366] border border-black flex-shrink-0" />
                    <span className="text-black font-mono font-bold">{ind}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Forensic Deep Dive Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Header & Routing Forensics */}
            <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000] space-y-4">
              <h4 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2 border-b-2 border-black pb-2">
                <span className="p-1 bg-[#00F0FF] border border-black">
                  <Server className="h-3.5 w-3.5 stroke-[2.5]" />
                </span>
                <span>Header & Routing Forensics</span>
              </h4>

              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between p-2.5 border border-black bg-[#F4F0EA]">
                  <span className="text-slate-700 font-bold">Sender Domain:</span>
                  <span className="font-black text-black bg-white px-1.5 border border-black">
                    {scanResult.email_metadata?.sender_domain || 'Unknown'}
                  </span>
                </div>
                <div className="flex justify-between p-2.5 border border-black bg-[#F4F0EA]">
                  <span className="text-slate-700 font-bold">Boundary Verification:</span>
                  <span className={`font-black px-1.5 border border-black ${
                    scanResult.email_metadata?.sender_domain === 'enron.com' ? 'bg-[#00E599] text-black' : 'bg-[#FFE600] text-black'
                  }`}>
                    {scanResult.email_metadata?.sender_domain === 'enron.com' ? 'Internal (enron.com)' : 'External Origin'}
                  </span>
                </div>
                <div className="flex justify-between p-2.5 border border-black bg-[#F4F0EA]">
                  <span className="text-slate-700 font-bold">Reply-To Address:</span>
                  <span className="font-bold text-black truncate max-w-[200px]">
                    {scanResult.email_metadata?.reply_to || 'None (Matches From)'}
                  </span>
                </div>
                <div className="flex justify-between p-2.5 border border-black bg-[#F4F0EA]">
                  <span className="text-slate-700 font-bold">Routing Hops:</span>
                  <span className="font-black text-black bg-white px-2 border border-black">
                    {scanResult.forensics?.routing_analysis?.hop_count || 0}
                  </span>
                </div>
              </div>
            </div>

            {/* URL Forensics & Geolocation Guard */}
            <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000] space-y-4">
              <h4 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2 border-b-2 border-black pb-2">
                <span className="p-1 bg-[#FFE600] border border-black">
                  <Globe className="h-3.5 w-3.5 stroke-[2.5]" />
                </span>
                <span>URL & Geolocation Intelligence</span>
              </h4>

              <div className="space-y-3 text-xs font-mono">
                {/* Geolocation Verdict */}
                <div className="p-3 border border-black bg-[#F4F0EA]">
                  <div className="text-[10px] text-slate-700 font-bold uppercase mb-1">Public IP Geolocation Status:</div>
                  {scanResult.forensics?.geolocation_intelligence?.available ? (
                    <div className="space-y-1 text-black font-bold">
                      <div>IP: {scanResult.forensics.geolocation_intelligence.primary_public_ip}</div>
                      <div className="text-black bg-[#FFE600] px-1 inline-block border border-black">
                        {scanResult.forensics.geolocation_intelligence.city}, {scanResult.forensics.geolocation_intelligence.country} ({scanResult.forensics.geolocation_intelligence.asn})
                      </div>
                      <p className="text-[10px] text-slate-600 italic mt-1 font-normal">
                        {scanResult.forensics.geolocation_intelligence.disclaimer}
                      </p>
                    </div>
                  ) : (
                    <div className="text-slate-700 font-bold">
                      <span className="bg-[#FFE600] text-black px-1.5 py-0.5 border border-black mr-1">UNAVAILABLE</span>
                      - {scanResult.forensics?.geolocation_intelligence?.reason || 'No routable public IP in headers.'}
                      <p className="text-[10px] text-slate-500 italic mt-1 font-normal">
                        OrgShield AI strictly avoids fabricating fake coordinates for RFC 1918 private IPs.
                      </p>
                    </div>
                  )}
                </div>

                {/* Detected URLs */}
                <div>
                  <div className="text-[10px] text-slate-700 font-bold uppercase mb-1">URLs Detected in Message:</div>
                  {scanResult.email_metadata?.urls?.length > 0 ? (
                    <div className="space-y-1.5 max-h-32 overflow-y-auto">
                      {scanResult.email_metadata.urls.map((u, i) => (
                        <div key={i} className="flex items-center gap-2 p-2 bg-white border border-black font-mono text-[11px] text-black break-all shadow-[1px_1px_0px_#000]">
                          <LinkIcon className="h-3.5 w-3.5 flex-shrink-0 text-[#FF3366] stroke-[2.5]" />
                          <span className="font-bold">{u}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-600 font-mono text-xs font-bold">No URLs found in body or headers.</span>
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
