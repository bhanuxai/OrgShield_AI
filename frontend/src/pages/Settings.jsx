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
  const [error, setError] = useState(null);

  const fetchSettings = () => {
    setLoading(true);
    setError(null);
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
      .catch((err) => {
        console.error(err);
        setError(err.message || 'Unable to retrieve settings from backend.');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchSettings();
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
      <div className="flex flex-col items-center justify-center h-64 font-mono">
        <div className="p-4 bg-[#FFE600] border-2 border-black shadow-[4px_4px_0px_0px_#000] font-black uppercase tracking-wider flex items-center gap-3">
          <div className="h-4 w-4 border-2 border-black border-t-transparent animate-spin rounded-full" />
          <span>LOADING SYSTEM CONFIGURATION...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="border-2 border-black bg-white p-6 text-center space-y-4 my-8 max-w-lg mx-auto shadow-[4px_4px_0px_0px_#000]">
        <div className="inline-flex p-3 bg-[#FF3366] text-white border-2 border-black shadow-[3px_3px_0px_0px_#000]">
          <AlertCircle className="h-6 w-6 stroke-[2.5]" />
        </div>
        <h3 className="text-base font-black uppercase text-black">Settings Pipeline Offline</h3>
        <p className="text-xs font-mono text-slate-700">{error}</p>
        <button
          onClick={fetchSettings}
          className="brutal-btn px-4 py-2 text-xs font-mono bg-[#FFE600] text-black"
        >
          RETRY CONNECTION
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="border-2 border-black bg-[#FFFDF0] p-4 shadow-[4px_4px_0px_0px_#000000] flex items-center justify-between">
        <div>
          <h2 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2">
            <span className="p-1 bg-[#FFE600] border border-black shadow-[1px_1px_0px_#000]">
              <SettingsIcon className="h-4 w-4 stroke-[2.5]" />
            </span>
            <span>Platform Configuration & Dataset Telemetry</span>
          </h2>
          <p className="text-[11px] text-slate-700 font-mono mt-0.5">
            Calibrate operational detection sensitivity and inspect baseline Enron corpus inventory
          </p>
        </div>
        <span className="text-xs font-mono font-bold bg-[#FFE600] px-2.5 py-1 border-2 border-black shadow-[2px_2px_0px_#000]">
          SYSTEM CONFIG
        </span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ML Configuration Form */}
        <div className="border-2 border-black bg-white p-5 space-y-4 shadow-[4px_4px_0px_0px_#000]">
          <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2 border-b-2 border-black pb-3">
            <span className="p-1 bg-[#00F0FF] border border-black">
              <Cpu className="h-3.5 w-3.5 stroke-[2.5]" />
            </span>
            <span>Anomaly Model & Sensitivity Calibration</span>
          </h3>

          <form onSubmit={handleSaveSettings} className="space-y-4 text-xs font-mono">
            {/* Active Model Selector */}
            <div className="space-y-1.5">
              <label className="text-black font-black uppercase text-[11px]">Active Threat Engine</label>
              <select
                value={activeModel}
                onChange={(e) => setActiveModel(e.target.value)}
                className="w-full px-3 py-2 border-2 border-black bg-[#F4F0EA] text-black font-mono font-bold shadow-[2px_2px_0px_#000] focus:outline-none focus:bg-[#FFFDF0]"
              >
                <option value="isolation_forest">Isolation Forest (Primary Unsupervised ML)</option>
                <option value="one_class_svm">One-Class SVM (RBF Kernel Support Frontier)</option>
                <option value="local_outlier_factor">Local Outlier Factor (k-NN Density Novelty)</option>
                <option value="rule_based_baseline">Rule-Based Baseline (Deterministic Blocklists)</option>
              </select>
              <p className="text-[10px] text-slate-600 font-medium">
                Selected model will score all incoming API scan requests.
              </p>
            </div>

            {/* Threshold Slider & Input */}
            <div className="space-y-2 pt-2 border-t-2 border-black">
              <div className="flex justify-between items-center">
                <label className="text-black font-black uppercase text-[11px]">Anomaly Decision Threshold (&tau;)</label>
                <span className="text-black font-black px-2.5 py-0.5 bg-[#FFE600] border-2 border-black shadow-[2px_2px_0px_#000]">
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
                className="w-full h-3 bg-white border-2 border-black appearance-none cursor-pointer accent-black"
              />
              <div className="flex justify-between text-[10px] text-slate-700 font-bold">
                <span>0.10 (Aggressive / High Sensitivity)</span>
                <span>0.95 (Conservative / Low FP)</span>
              </div>
            </div>

            {saveSuccess && (
              <div className="p-3 border-2 border-black bg-[#DCFCE7] text-black flex items-center gap-2 text-[11px] font-bold shadow-[2px_2px_0px_#000]">
                <CheckCircle2 className="h-4 w-4 stroke-[2.5]" />
                <span>Configuration updated successfully in database and active runtime engine.</span>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <button
                type="submit"
                disabled={saving}
                className="brutal-btn px-5 py-2.5 bg-[#FFE600] hover:bg-[#FFD600] text-black font-black flex items-center gap-2 shadow-[3px_3px_0px_0px_#000] disabled:opacity-50 uppercase tracking-wider text-xs"
              >
                <Save className="h-4 w-4 stroke-[2.5]" />
                <span>{saving ? 'APPLYING...' : 'SAVE CONFIGURATION'}</span>
              </button>
            </div>
          </form>
        </div>

        {/* Dataset Inventory Card */}
        <div className="border-2 border-black bg-white p-5 space-y-4 shadow-[4px_4px_0px_0px_#000]">
          <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2 border-b-2 border-black pb-3">
            <span className="p-1 bg-[#FFE600] border border-black">
              <Database className="h-3.5 w-3.5 stroke-[2.5]" />
            </span>
            <span>Enron Email Corpus Inventory</span>
          </h3>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between p-2.5 border-2 border-black bg-[#F4F0EA]">
              <span className="text-slate-700 font-bold">Maildir Root Path:</span>
              <span className="text-black font-black truncate max-w-[200px] bg-white px-1 border border-black" title={datasetStats?.dataset_root}>
                {datasetStats?.dataset_root || 'enron_mail_20150507_final/maildir'}
              </span>
            </div>
            <div className="flex justify-between p-2.5 border-2 border-black bg-[#F4F0EA]">
              <span className="text-slate-700 font-bold">Total Users in Dataset:</span>
              <span className="text-black font-black">{datasetStats?.total_users_in_dataset || 150}</span>
            </div>
            <div className="flex justify-between p-2.5 border-2 border-black bg-[#F4F0EA]">
              <span className="text-slate-700 font-bold">Sampled Training Inventory:</span>
              <span className="text-black font-black">{datasetStats?.readable_emails_count || 6000}</span>
            </div>
            <div className="flex justify-between p-2.5 border-2 border-black bg-[#F4F0EA]">
              <span className="text-slate-700 font-bold">Unique Senders Tracked:</span>
              <span className="text-black font-black">{datasetStats?.unique_senders_count || 1609}</span>
            </div>
            <div className="flex justify-between p-2.5 border-2 border-black bg-[#F4F0EA]">
              <span className="text-slate-700 font-bold">Unique Recipients:</span>
              <span className="text-black font-black">{datasetStats?.unique_recipients_count || 8325}</span>
            </div>
            <div className="flex justify-between p-2.5 border-2 border-black bg-[#F4F0EA]">
              <span className="text-slate-700 font-bold">Corpus Contamination Detected:</span>
              <span className="text-black font-black bg-[#FFE600] px-1 border border-black">
                {datasetStats?.corpus_contamination_notes?.detected_count || 30} marketing/lottery emails
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
