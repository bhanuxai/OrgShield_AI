import React, { useState, useEffect } from 'react';
import {
  Settings as SettingsIcon,
  Save,
  CheckCircle2,
  Database,
  Cpu,
  Sliders,
  AlertCircle
} from 'lucide-react';
import { api } from '../services/api';

export default function Settings() {
  const [settings, setSettings] = useState({});
  const [datasetStats, setDatasetStats] = useState(null);
  const [modelsStatus, setModelsStatus] = useState(null);
  const [threshold, setThreshold] = useState(0.7912);
  const [activeModel, setActiveModel] = useState('one_class_svm');
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.getSettings(),
      api.getDatasetStats(),
      api.getModelsStatus()
    ])
      .then(([sData, dData, mData]) => {
        setSettings(sData);
        setDatasetStats(dData);
        setModelsStatus(mData);
        if (sData.detection_threshold?.value) {
          setThreshold(parseFloat(sData.detection_threshold.value));
        }
        if (sData.active_model?.value) {
          setActiveModel(sData.active_model.value);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    setSaving(true);
    setSaveSuccess(false);
    try {
      await api.updateSettings({
        detection_threshold: parseFloat(threshold),
        active_model: activeModel
      });
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      alert('Failed to save settings: ' + err.message);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 font-mono text-sm">
        Loading system configuration...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="cyber-card p-4 flex items-center justify-between">
        <div>
          <h2 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2">
            <SettingsIcon className="h-4 w-4 text-cyan-400" />
            <span>Platform Configuration & Dataset Telemetry</span>
          </h2>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
            Calibrate operational detection sensitivity and inspect baseline Enron corpus inventory
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ML Configuration Form */}
        <div className="cyber-card p-5 space-y-4">
          <h3 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2 border-b border-slate-800/80 pb-3">
            <Cpu className="h-4 w-4 text-cyan-400" />
            <span>Anomaly Model & Sensitivity Calibration</span>
          </h3>

          <form onSubmit={handleSaveSettings} className="space-y-4 text-xs font-mono">
            {/* Active Model Selector */}
            <div className="space-y-1.5">
              <label className="text-slate-400 font-medium">Active Threat Engine</label>
              <select
                value={activeModel}
                onChange={(e) => setActiveModel(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-cyan-400 focus:outline-none focus:border-cyan-500"
              >
                <option value="isolation_forest">Isolation Forest (Primary Unsupervised ML)</option>
                <option value="one_class_svm">One-Class SVM (RBF Kernel Support Frontier)</option>
                <option value="local_outlier_factor">Local Outlier Factor (k-NN Density Novelty)</option>
                <option value="rule_based_baseline">Rule-Based Baseline (Deterministic Blocklists)</option>
              </select>
              <p className="text-[10px] text-slate-500">
                Selected model will score all incoming API scan requests.
              </p>
            </div>

            {/* Threshold Slider & Input */}
            <div className="space-y-2 pt-2">
              <div className="flex justify-between items-center">
                <label className="text-slate-400 font-medium">Anomaly Decision Threshold (&tau;)</label>
                <span className="text-cyan-400 font-bold px-2 py-0.5 rounded bg-slate-900 border border-slate-800">
                  {Number(threshold).toFixed(4)}
                </span>
              </div>
              <input
                type="range"
                min="0.10"
                max="0.95"
                step="0.005"
                value={threshold}
                onChange={(e) => setThreshold(parseFloat(e.target.value))}
                className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
              <div className="flex justify-between text-[10px] text-slate-500">
                <span>0.10 (Aggressive / High Sensitivity)</span>
                <span>0.95 (Conservative / Low FP)</span>
              </div>
            </div>

            {saveSuccess && (
              <div className="p-2.5 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-400 flex items-center gap-2 text-[11px]">
                <CheckCircle2 className="h-4 w-4" />
                <span>Configuration updated successfully in database and active runtime engine.</span>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <button
                type="submit"
                disabled={saving}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium flex items-center gap-2 shadow-lg shadow-cyan-600/20 disabled:opacity-50 transition-colors"
              >
                <Save className="h-4 w-4" />
                <span>{saving ? 'Applying...' : 'Save Configuration'}</span>
              </button>
            </div>
          </form>
        </div>

        {/* Dataset Inventory Card */}
        <div className="cyber-card p-5 space-y-4">
          <h3 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2 border-b border-slate-800/80 pb-3">
            <Database className="h-4 w-4 text-cyan-400" />
            <span>Enron Email Corpus Inventory</span>
          </h3>

          <div className="space-y-2.5 text-xs font-mono">
            <div className="flex justify-between p-2.5 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-400">Maildir Root Path:</span>
              <span className="text-cyan-400 truncate max-w-[200px]" title={datasetStats?.dataset_root}>
                {datasetStats?.dataset_root || 'enron_mail_20150507_final/maildir'}
              </span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-400">Total Users in Dataset:</span>
              <span className="text-slate-200">{datasetStats?.total_users_in_dataset || 150}</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-400">Sampled Training Inventory:</span>
              <span className="text-slate-200">{datasetStats?.readable_emails_count || 6000}</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-400">Unique Senders Tracked:</span>
              <span className="text-slate-200">{datasetStats?.unique_senders_count || 1609}</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-400">Unique Recipients:</span>
              <span className="text-slate-200">{datasetStats?.unique_recipients_count || 8325}</span>
            </div>
            <div className="flex justify-between p-2.5 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-400">Corpus Contamination Detected:</span>
              <span className="text-amber-400">
                {datasetStats?.corpus_contamination_notes?.detected_count || 30} historical marketing/lottery emails
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
