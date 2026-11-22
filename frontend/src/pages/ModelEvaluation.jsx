import React, { useState, useEffect } from 'react';
import {
  Binary,
  CheckCircle2,
  AlertTriangle,
  Info,
  ShieldCheck,
  TrendingUp,
  Cpu,
  Layers,
  Award
} from 'lucide-react';
import { api } from '../services/api';

export default function ModelEvaluation() {
  const [evalData, setEvalData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeModelTab, setActiveModelTab] = useState('one_class_svm');

  const fetchEvaluation = () => {
    setLoading(true);
    setError(null);
    api.getEvaluation()
      .then((data) => {
        setEvalData(data);
        if (data.best_ml_model_selected) {
          setActiveModelTab(data.best_ml_model_selected);
        }
      })
      .catch((err) => {
        console.error(err);
        setError(err.message || 'Unable to retrieve model evaluation benchmarks from backend.');
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchEvaluation();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400 font-mono text-sm">
        <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-cyan-400 mr-3"></div>
        Retrieving academic model evaluation benchmarks...
      </div>
    );
  }

  if (error || !evalData) {
    return (
      <div className="cyber-card p-8 text-center space-y-4 my-8 max-w-lg mx-auto">
        <div className="text-rose-400 font-mono text-xs font-semibold">
          {error || 'Model evaluation benchmark unavailable.'}
        </div>
        <button
          onClick={fetchEvaluation}
          className="px-4 py-2 text-xs font-mono rounded bg-cyan-950 border border-cyan-800 text-cyan-400 hover:bg-cyan-900 transition-colors"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const models = evalData.models || {};
  const activeMetrics = models[activeModelTab] || {};
  const cm = activeMetrics.confusion_matrix || {};

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="cyber-card p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2">
            <Binary className="h-4 w-4 text-cyan-400" />
            <span>Strict Unsupervised Evaluation Benchmark</span>
          </h2>
          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
            Zero phishing labels during training. Evaluated against held-out legitimate Enron test emails and curated phishing corpus.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            Normal Test: {activeMetrics.sample_counts?.normal_test_count || 759}
          </span>
          <span className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-rose-400">
            Phishing Test: {activeMetrics.sample_counts?.phishing_test_count || 100}
          </span>
        </div>
      </div>

      {/* Model Comparison Table */}
      <div className="cyber-card p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-xs font-semibold text-white tracking-wider uppercase">Comparative Model Benchmark</h3>
            <p className="text-[11px] text-slate-400">Head-to-head comparison across anomaly detection algorithms and deterministic baseline</p>
          </div>
          <span className="text-xs font-mono text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
            Operating Point FPR: 1.5%
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                <th className="py-2.5 px-3">Algorithm</th>
                <th className="py-2.5 px-3">Detection Rate</th>
                <th className="py-2.5 px-3">FP / 1,000 Normal</th>
                <th className="py-2.5 px-3">Precision</th>
                <th className="py-2.5 px-3">Recall</th>
                <th className="py-2.5 px-3">F1-Score</th>
                <th className="py-2.5 px-3">PR-AUC</th>
                <th className="py-2.5 px-3">ROC-AUC</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {Object.entries(models).map(([name, m]) => {
                const isSelected = activeModelTab === name;
                return (
                  <tr
                    key={name}
                    onClick={() => setActiveModelTab(name)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? 'bg-cyan-950/40 border-l-2 border-cyan-400 font-semibold' : 'hover:bg-slate-800/30'
                    }`}
                  >
                    <td className="py-3 px-3 text-cyan-400 capitalize">
                      {name.replace(/_/g, ' ')}
                      {name === (evalData.best_ml_model_selected || 'one_class_svm') && (
                        <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                          Primary ML
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-emerald-400 font-bold">{m.detection_rate_pct.toFixed(2)}%</td>
                    <td className="py-3 px-3 text-amber-400">{m.false_positives_per_1000.toFixed(2)}</td>
                    <td className="py-3 px-3 text-slate-300">{m.precision.toFixed(4)}</td>
                    <td className="py-3 px-3 text-slate-300">{m.recall.toFixed(4)}</td>
                    <td className="py-3 px-3 text-white font-bold">{m.f1_score.toFixed(4)}</td>
                    <td className="py-3 px-3 text-cyan-300">{m.pr_auc.toFixed(4)}</td>
                    <td className="py-3 px-3 text-slate-400">{m.roc_auc.toFixed(4)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Model Detail & Confusion Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Confusion Matrix Visualizer */}
        <div className="cyber-card p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h3 className="text-xs font-semibold text-white tracking-wider uppercase">
              Confusion Matrix: <span className="text-cyan-400 capitalize">{activeModelTab.replace(/_/g, ' ')}</span>
            </h3>
            <span className="text-xs font-mono text-slate-400">
              Threshold: {activeMetrics.threshold}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3 font-mono text-xs text-center">
            {/* True Negatives */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-center">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">True Negatives (TN)</span>
              <span className="text-2xl font-bold text-emerald-400 mt-1">{cm.true_negatives ?? 0}</span>
              <span className="text-[10px] text-slate-500 mt-0.5">Legitimate classified as normal</span>
            </div>

            {/* False Positives */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-center">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">False Positives (FP)</span>
              <span className="text-2xl font-bold text-amber-400 mt-1">{cm.false_positives ?? 0}</span>
              <span className="text-[10px] text-slate-500 mt-0.5">Legitimate falsely flagged</span>
            </div>

            {/* False Negatives */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-center">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">False Negatives (FN)</span>
              <span className="text-2xl font-bold text-rose-400 mt-1">{cm.false_negatives ?? 0}</span>
              <span className="text-[10px] text-slate-500 mt-0.5">Phishing missed</span>
            </div>

            {/* True Positives */}
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-center">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">True Positives (TP)</span>
              <span className="text-2xl font-bold text-cyan-400 mt-1">{cm.true_positives ?? 0}</span>
              <span className="text-[10px] text-slate-500 mt-0.5">Phishing correctly detected</span>
            </div>
          </div>
        </div>

        {/* Academic Calibration Protocol */}
        <div className="cyber-card p-5 space-y-3">
          <h3 className="text-xs font-semibold text-white tracking-wider uppercase flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyan-400" />
            <span>Academic Calibration & Leakage Prevention</span>
          </h3>

          <div className="text-xs text-slate-300 space-y-2.5 leading-relaxed">
            <p>
              In strict accordance with the INT396 problem statement, OrgShield AI trains purely on normal organizational communications from the Enron dataset.
            </p>
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1 font-mono text-[11px]">
              <div className="text-cyan-400 font-semibold">Validation Threshold Calibration:</div>
              <p className="text-slate-400">
                Operating thresholds (tau) are calibrated exclusively on normal validation emails by targeting a strict operational constraint of FPR &le; 1.5% (approx 15 false alarms per 1,000 legitimate emails).
              </p>
            </div>
            <p className="text-slate-400 text-[11px]">
              No phishing samples are used for feature selection, hyperparameter tuning, or threshold setting. The held-out phishing benchmark (100 documented attacks) is queried solely at final test evaluation.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
