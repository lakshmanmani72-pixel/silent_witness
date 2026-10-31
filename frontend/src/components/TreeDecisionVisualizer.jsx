import React, { useState, useEffect } from 'react';
import {
  GitCommit,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Cpu,
  Layers,
  Sparkles,
  ArrowDown,
  Info,
  Activity,
  Flame,
  Radio,
  RefreshCw
} from 'lucide-react';
import { endpoints } from '../services/api';

const TreeDecisionVisualizer = ({ latestThreat = null, latestFlow = null }) => {
  const [selectedScenario, setSelectedScenario] = useState('SYN_FLOOD'); // 'SYN_FLOOD' | 'PORT_SCAN' | 'BENIGN' | 'LIVE'
  const [explanationData, setExplanationData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('tree_path'); // 'tree_path' | 'feature_table'

  // Fetch tree decision explanation from backend API
  const fetchExplanation = async (type) => {
    setLoading(true);
    try {
      if (type === 'LIVE' && latestFlow) {
        const res = await endpoints.explainFlow(latestFlow.features || latestFlow, latestFlow.threat_type);
        setExplanationData(res.data);
      } else {
        const res = await endpoints.getTreeExplanation(type);
        setExplanationData(res.data);
      }
    } catch (err) {
      console.error('Failed to load tree explanation:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchExplanation(selectedScenario);
  }, [selectedScenario]);

  // When a new live threat arrives, offer to view its explanation
  useEffect(() => {
    if (latestThreat?.threat_type && selectedScenario === 'LIVE') {
      fetchExplanation('LIVE');
    }
  }, [latestThreat]);

  const treePath = explanationData?.tree_decision_path || [];
  const topFeatures = explanationData?.top_features || [];
  const probabilities = explanationData?.probabilities || { BENIGN: 0.0, SYN_FLOOD: 0.0, PORT_SCAN: 0.0 };

  return (
    <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-4">
      {/* Header & Scenario Selector */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 mb-4 border-b border-slate-100">
        <div>
          <h3 className="text-base font-semibold text-slate-800 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-purple-600" />
            Random Forest ML Decision Process & Tree Inspection
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Transparent white-box inspection of <strong>Tree #0</strong> from the 100-tree forest and feature attribution.
          </p>
        </div>

        {/* Scenario / Flow Selector Buttons */}
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setSelectedScenario('SYN_FLOOD')}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
              selectedScenario === 'SYN_FLOOD'
                ? 'bg-rose-600 text-white shadow-sm'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            SYN Flood Sample
          </button>
          <button
            onClick={() => setSelectedScenario('PORT_SCAN')}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
              selectedScenario === 'PORT_SCAN'
                ? 'bg-amber-600 text-white shadow-sm'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            Port Scan Sample
          </button>
          <button
            onClick={() => setSelectedScenario('BENIGN')}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
              selectedScenario === 'BENIGN'
                ? 'bg-emerald-600 text-white shadow-sm'
                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
            }`}
          >
            Benign Traffic Sample
          </button>
          {latestFlow && (
            <button
              onClick={() => setSelectedScenario('LIVE')}
              className={`px-2.5 py-1 rounded text-xs font-medium flex items-center gap-1 transition-colors ${
                selectedScenario === 'LIVE'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'bg-indigo-50 text-indigo-700 hover:bg-indigo-100'
              }`}
            >
              <Radio className="w-3 h-3 animate-pulse" />
              Active Flow
            </button>
          )}
        </div>
      </div>

      {/* Model Metadata & 3-Class Probabilities */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
        {/* ML Prediction & Confidence Card */}
        <div className="p-3 bg-purple-50/70 rounded-lg border border-purple-100">
          <div className="flex items-center justify-between text-xs text-purple-700 mb-1">
            <span className="font-medium">Forest Ensemble Classification</span>
            <span className="font-mono font-bold">100 Trees</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span
              className={`text-lg font-bold ${
                explanationData?.prediction === 'SYN_FLOOD'
                  ? 'text-rose-600'
                  : explanationData?.prediction === 'PORT_SCAN'
                  ? 'text-amber-600'
                  : 'text-emerald-600'
              }`}
            >
              {explanationData?.prediction || 'BENIGN'}
            </span>
            <span className="text-xs text-purple-600 font-medium">
              ({((explanationData?.confidence || 0) * 100).toFixed(1)}% Confidence)
            </span>
          </div>
          <div className="mt-1 text-[11px] text-purple-800 leading-snug">
            {explanationData?.rule_ml_agreement}
          </div>
        </div>

        {/* 3-Class Probability Bars */}
        <div className="md:col-span-2 p-3 bg-slate-50 rounded-lg border border-slate-200 flex flex-col justify-center gap-2">
          <div className="text-xs font-semibold text-slate-700 flex items-center justify-between">
            <span>Class Probabilities (Soft Voting across 100 Trees):</span>
            <span className="text-[10px] text-slate-400 font-mono">Macro F1: 99.9%</span>
          </div>

          <div className="space-y-1.5 text-xs">
            {/* BENIGN */}
            <div>
              <div className="flex justify-between text-[11px] mb-0.5">
                <span className="font-medium text-slate-600">BENIGN (Normal)</span>
                <span className="font-mono text-emerald-700 font-semibold">
                  {((probabilities.BENIGN || 0) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-emerald-500 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${(probabilities.BENIGN || 0) * 100}%` }}
                />
              </div>
            </div>

            {/* SYN_FLOOD */}
            <div>
              <div className="flex justify-between text-[11px] mb-0.5">
                <span className="font-medium text-slate-600">SYN_FLOOD (DoS Attack)</span>
                <span className="font-mono text-rose-700 font-semibold">
                  {((probabilities.SYN_FLOOD || 0) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-rose-500 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${(probabilities.SYN_FLOOD || 0) * 100}%` }}
                />
              </div>
            </div>

            {/* PORT_SCAN */}
            <div>
              <div className="flex justify-between text-[11px] mb-0.5">
                <span className="font-medium text-slate-600">PORT_SCAN (Reconnaissance)</span>
                <span className="font-mono text-amber-700 font-semibold">
                  {((probabilities.PORT_SCAN || 0) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-amber-500 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${(probabilities.PORT_SCAN || 0) * 100}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs: Tree #0 Decision Ladder vs Feature Attribution Table */}
      <div className="flex items-center gap-2 mb-3 border-b border-slate-200">
        <button
          onClick={() => setActiveTab('tree_path')}
          className={`pb-2 px-1 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === 'tree_path'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-700'
          }`}
        >
          Tree #0 Step-by-Step Decision Ladder ({treePath.length} Nodes)
        </button>
        <button
          onClick={() => setActiveTab('feature_table')}
          className={`pb-2 px-1 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === 'feature_table'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:text-slate-700'
          }`}
        >
          Forest Feature Attribution & Explanations ({topFeatures.length} Key Features)
        </button>
      </div>

      {/* Tab 1: Step-by-Step Tree Decision Path */}
      {activeTab === 'tree_path' && (
        <div className="space-y-2 max-h-[360px] overflow-y-auto pr-1">
          {treePath.map((step, idx) => {
            const isLeaf = step.is_leaf;
            return (
              <div
                key={idx}
                className={`p-2.5 rounded-lg border text-xs transition-all ${
                  isLeaf
                    ? 'bg-purple-50/80 border-purple-200 shadow-sm'
                    : 'bg-white border-slate-200 hover:border-slate-300'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-indigo-100 text-indigo-700 font-bold flex items-center justify-center text-[10px]">
                      {step.step}
                    </span>
                    <span className="font-semibold text-slate-800">
                      {isLeaf ? (
                        <span className="text-purple-700 flex items-center gap-1 font-bold">
                          <Sparkles className="w-3.5 h-3.5" />
                          Terminal Decision Leaf (Node {step.node_id})
                        </span>
                      ) : (
                        `Node ${step.node_id}: Testing ${step.feature}`
                      )}
                    </span>
                  </div>

                  {!isLeaf && (
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-mono font-medium flex items-center gap-1 ${
                        step.condition_satisfied
                          ? 'bg-emerald-100 text-emerald-800'
                          : 'bg-slate-100 text-slate-700'
                      }`}
                    >
                      {step.condition_satisfied ? (
                        <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                      ) : (
                        <XCircle className="w-3 h-3 text-slate-400" />
                      )}
                      Condition {step.condition_satisfied ? 'Met (Branch Left)' : 'Not Met (Branch Right)'}
                    </span>
                  )}
                </div>

                {isLeaf ? (
                  <div className="mt-1 text-slate-700">
                    <p className="font-medium text-purple-900">
                      {step.description}
                    </p>
                    <div className="flex items-center gap-4 mt-1.5 text-[11px] text-slate-500 font-mono">
                      <span>Dominant Class: <strong>{step.predicted_class}</strong></span>
                      <span>Gini Impurity: {step.impurity}</span>
                      <span>Node Samples: {step.samples}</span>
                    </div>
                  </div>
                ) : (
                  <div>
                    <div className="bg-slate-50 p-2 rounded border border-slate-100 font-mono text-[11px] text-slate-700 flex flex-wrap items-center justify-between gap-2">
                      <span>
                        Rule Check: <strong>{step.feature}</strong> {step.operator} {step.threshold}
                      </span>
                      <span>
                        Flow Observed Value: <strong className="text-indigo-600">{step.observed_value}</strong>
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1 italic">
                      Why this matters: {step.description}
                    </p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Tab 2: Feature Attribution Table */}
      {activeTab === 'feature_table' && (
        <div className="overflow-x-auto max-h-[360px]">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-600 uppercase text-[10px] tracking-wider">
                <th className="py-2 px-3">Feature Name</th>
                <th className="py-2 px-3">RF Importance</th>
                <th className="py-2 px-3">Observed In Flow</th>
                <th className="py-2 px-3">SOC Domain Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {topFeatures.map((feat, idx) => (
                <tr key={idx} className="hover:bg-slate-50/70">
                  <td className="py-2 px-3 font-semibold text-slate-800">{feat.feature}</td>
                  <td className="py-2 px-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-indigo-600 w-12 text-right">
                        {feat.importance_pct}%
                      </span>
                      <div className="w-16 bg-slate-200 h-1.5 rounded-full overflow-hidden">
                        <div
                          className="bg-indigo-600 h-1.5 rounded-full"
                          style={{ width: `${Math.min(feat.importance_pct * 3, 100)}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="py-2 px-3 font-mono font-medium text-slate-900">
                    {feat.observed_value !== null ? feat.observed_value : '—'}
                  </td>
                  <td className="py-2 px-3 text-slate-600 text-[11px] max-w-xs">{feat.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default TreeDecisionVisualizer;

