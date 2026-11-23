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
      <div className="flex flex-col items-center justify-center h-64 font-mono">
        <div className="p-4 bg-[#FFE600] border-2 border-black shadow-[4px_4px_0px_0px_#000] font-black uppercase tracking-wider flex items-center gap-3">
          <div className="h-4 w-4 border-2 border-black border-t-transparent animate-spin rounded-full" />
          <span>LOADING ACADEMIC BENCHMARKS...</span>
        </div>
      </div>
    );
  }

  if (error || !evalData) {
    return (
      <div className="border-2 border-black bg-white p-6 text-center space-y-4 my-8 max-w-lg mx-auto shadow-[4px_4px_0px_0px_#000]">
        <div className="inline-flex p-3 bg-[#FF3366] text-white border-2 border-black shadow-[3px_3px_0px_0px_#000]">
          <AlertTriangle className="h-6 w-6 stroke-[2.5]" />
        </div>
        <h3 className="text-base font-black uppercase text-black">Evaluation Benchmark Offline</h3>
        <p className="text-xs font-mono text-slate-700">{error || 'Model evaluation benchmark unavailable.'}</p>
        <button
          onClick={fetchEvaluation}
          className="brutal-btn px-4 py-2 text-xs font-mono bg-[#FFE600] text-black"
        >
          RETRY CONNECTION
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
      <div className="border-2 border-black bg-[#FFFDF0] p-4 shadow-[4px_4px_0px_0px_#000000] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2">
            <span className="p-1 bg-[#FFE600] border border-black shadow-[1px_1px_0px_#000]">
              <Binary className="h-4 w-4 stroke-[2.5]" />
            </span>
            <span>Strict Unsupervised Evaluation Benchmark</span>
          </h2>
          <p className="text-[11px] text-slate-700 font-mono mt-0.5">
            Zero phishing labels during training. Evaluated against held-out legitimate Enron test emails and curated phishing corpus.
          </p>
        </div>
        <div className="flex items-center gap-2 font-mono text-xs font-bold flex-shrink-0">
          <span className="px-2.5 py-1 bg-white border-2 border-black shadow-[2px_2px_0px_#000] text-black">
            NORMAL TEST: {activeMetrics.sample_counts?.normal_test_count || 759}
          </span>
          <span className="px-2.5 py-1 bg-[#FFE4E6] border-2 border-black shadow-[2px_2px_0px_#000] text-[#FF3366]">
            PHISHING TEST: {activeMetrics.sample_counts?.phishing_test_count || 100}
          </span>
        </div>
      </div>

      {/* Model Comparison Table */}
      <div className="border-2 border-black bg-white p-5 shadow-[4px_4px_0px_0px_#000000]">
        <div className="flex items-center justify-between border-b-2 border-black pb-3 mb-4">
          <div>
            <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2">
              <span className="p-1 bg-[#FFE600] border border-black">
                <Award className="h-3.5 w-3.5 stroke-[2.5]" />
              </span>
              <span>Comparative Model Benchmark (Held-Out Test Set)</span>
            </h3>
            <p className="text-[11px] text-slate-600 font-mono mt-0.5">
              Head-to-head comparison across anomaly detection algorithms and deterministic baseline
            </p>
          </div>
          <span className="text-xs font-mono font-bold text-black bg-[#FFE600] px-2 py-0.5 border border-black shadow-[1px_1px_0px_#000]">
            TARGET FPR: 1.5%
          </span>
        </div>

        <div className="overflow-x-auto border-2 border-black">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="bg-[#FFE600] border-b-2 border-black text-black font-black uppercase text-[11px]">
                <th className="py-2.5 px-3 border-r-2 border-black">Algorithm</th>
                <th className="py-2.5 px-3 border-r-2 border-black">Detection Rate</th>
                <th className="py-2.5 px-3 border-r-2 border-black">FP / 1,000 Normal</th>
                <th className="py-2.5 px-3 border-r-2 border-black">Precision</th>
                <th className="py-2.5 px-3 border-r-2 border-black">Recall</th>
                <th className="py-2.5 px-3 border-r-2 border-black">F1-Score</th>
                <th className="py-2.5 px-3 border-r-2 border-black">PR-AUC</th>
                <th className="py-2.5 px-3">ROC-AUC</th>
              </tr>
            </thead>
            <tbody className="divide-y-2 divide-black bg-white">
              {Object.entries(models).map(([name, m]) => {
                const isSelected = activeModelTab === name;
                return (
                  <tr
                    key={name}
                    onClick={() => setActiveModelTab(name)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? 'bg-[#FFFDF0] font-black' : 'hover:bg-slate-50'
                    }`}
                  >
                    <td className="py-3 px-3 text-black font-black capitalize border-r-2 border-black flex items-center justify-between">
                      <span>{name.replace(/_/g, ' ')}</span>
                      {name === (evalData.best_ml_model_selected || 'one_class_svm') && (
                        <span className="ml-2 text-[9px] px-1.5 py-0.5 bg-black text-[#FFE600] border border-black font-black uppercase">
                          PRIMARY ML
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-black font-black bg-[#DCFCE7] border-r-2 border-black">
                      {m.detection_rate_pct.toFixed(2)}%
                    </td>
                    <td className="py-3 px-3 text-black font-bold border-r-2 border-black">
                      {m.false_positives_per_1000.toFixed(2)}
                    </td>
                    <td className="py-3 px-3 text-black font-medium border-r-2 border-black">
                      {m.precision.toFixed(4)}
                    </td>
                    <td className="py-3 px-3 text-black font-medium border-r-2 border-black">
                      {m.recall.toFixed(4)}
                    </td>
                    <td className="py-3 px-3 text-black font-black border-r-2 border-black">
                      {m.f1_score.toFixed(4)}
                    </td>
                    <td className="py-3 px-3 text-black font-bold bg-[#E0F2FE] border-r-2 border-black">
                      {m.pr_auc.toFixed(4)}
                    </td>
                    <td className="py-3 px-3 text-black font-medium">
                      {m.roc_auc.toFixed(4)}
                    </td>
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
        <div className="border-2 border-black bg-white p-5 space-y-4 shadow-[4px_4px_0px_0px_#000]">
          <div className="flex items-center justify-between border-b-2 border-black pb-3">
            <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2">
              <span className="h-2.5 w-2.5 bg-black" />
              <span>Confusion Matrix: <strong className="text-black capitalize">{activeModelTab.replace(/_/g, ' ')}</strong></span>
            </h3>
            <span className="text-xs font-mono font-bold bg-[#F4F0EA] px-2 py-0.5 border border-black">
              THRESHOLD: {activeMetrics.threshold}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3 font-mono text-xs text-center">
            {/* True Negatives */}
            <div className="p-4 border-2 border-black bg-[#DCFCE7] shadow-[3px_3px_0px_0px_#000] flex flex-col justify-center">
              <span className="text-[10px] text-black font-black uppercase tracking-wider">True Negatives (TN)</span>
              <span className="text-3xl font-black text-black mt-1">{cm.true_negatives ?? 0}</span>
              <span className="text-[10px] text-slate-700 font-bold mt-0.5">Legitimate marked as normal</span>
            </div>

            {/* False Positives */}
            <div className="p-4 border-2 border-black bg-[#FEF08A] shadow-[3px_3px_0px_0px_#000] flex flex-col justify-center">
              <span className="text-[10px] text-black font-black uppercase tracking-wider">False Positives (FP)</span>
              <span className="text-3xl font-black text-black mt-1">{cm.false_positives ?? 0}</span>
              <span className="text-[10px] text-slate-700 font-bold mt-0.5">Legitimate falsely flagged</span>
            </div>

            {/* False Negatives */}
            <div className="p-4 border-2 border-black bg-[#FFE4E6] shadow-[3px_3px_0px_0px_#000] flex flex-col justify-center">
              <span className="text-[10px] text-[#FF3366] font-black uppercase tracking-wider">False Negatives (FN)</span>
              <span className="text-3xl font-black text-[#FF3366] mt-1">{cm.false_negatives ?? 0}</span>
              <span className="text-[10px] text-slate-700 font-bold mt-0.5">Phishing missed</span>
            </div>

            {/* True Positives */}
            <div className="p-4 border-2 border-black bg-[#BAE6FD] shadow-[3px_3px_0px_0px_#000] flex flex-col justify-center">
              <span className="text-[10px] text-black font-black uppercase tracking-wider">True Positives (TP)</span>
              <span className="text-3xl font-black text-black mt-1">{cm.true_positives ?? 0}</span>
              <span className="text-[10px] text-slate-700 font-bold mt-0.5">Phishing correctly detected</span>
            </div>
          </div>
        </div>

        {/* Academic Calibration Protocol */}
        <div className="border-2 border-black bg-white p-5 space-y-3 shadow-[4px_4px_0px_0px_#000]">
          <h3 className="text-xs font-black uppercase text-black tracking-wider flex items-center gap-2 border-b-2 border-black pb-2">
            <span className="p-1 bg-[#00E599] border border-black">
              <ShieldCheck className="h-3.5 w-3.5 stroke-[2.5]" />
            </span>
            <span>Academic Calibration & Leakage Prevention</span>
          </h3>

          <div className="text-xs text-slate-800 space-y-3 leading-relaxed font-mono font-medium">
            <p>
              In strict accordance with the INT396 problem statement, OrgShield AI trains purely on normal organizational communications from the Enron dataset.
            </p>
            <div className="p-3 border-2 border-black bg-[#FFFDF0] shadow-[2px_2px_0px_#000] space-y-1">
              <div className="text-black font-black uppercase text-xs">Validation Threshold Calibration:</div>
              <p className="text-slate-700 text-[11px]">
                Operating thresholds (&tau;) are calibrated exclusively on normal validation emails by targeting a strict operational constraint of FPR &le; 1.5% (approx 15 false alarms per 1,000 legitimate emails).
              </p>
            </div>
            <p className="text-slate-600 text-[11px] font-normal">
              No phishing samples are used for feature selection, hyperparameter tuning, or threshold setting. The held-out phishing benchmark (100 documented attacks) is queried solely at final test evaluation.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
