import React, { useState } from 'react';
import { Play, RotateCcw, AlertTriangle, ShieldCheck, Database, FastForward, Sliders } from 'lucide-react';
import { Scenario, ScenarioStep } from '../types/tripwire';

// Import raw scenario definitions
import attackScenario from '../../../agent/scenarios/attack.json';
import legitimateScenario from '../../../agent/scenarios/legitimate.json';
import crossSession1 from '../../../agent/scenarios/cross_session_1.json';
import crossSession2 from '../../../agent/scenarios/cross_session_2.json';

interface Props {
  isRunning: boolean;
  onRunStep: (step: ScenarioStep, principalId: string, agentId: string) => Promise<void>;
  onReset: (initialScore?: number) => void;
  toolExecutionCounts: Record<string, number>;
}

export const ScenarioRunner: React.FC<Props> = ({
  isRunning,
  onRunStep,
  onReset,
  toolExecutionCounts,
}) => {
  const [selectedScenarioKey, setSelectedScenarioKey] = useState<string>('attack');
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [autoPlaying, setAutoPlaying] = useState<boolean>(false);
  const [stepDelayMs, setStepDelayMs] = useState<number>(700);

  const scenarios: Record<string, Scenario> = {
    attack: attackScenario as unknown as Scenario,
    legitimate: legitimateScenario as unknown as Scenario,
    cross_session_1: crossSession1 as unknown as Scenario,
    cross_session_2: crossSession2 as unknown as Scenario,
  };

  const activeScenario = scenarios[selectedScenarioKey];

  const handleSelectScenario = (key: string) => {
    setSelectedScenarioKey(key);
    setCurrentStepIndex(0);
    setAutoPlaying(false);
    // If switching to Session 2, simulate inheriting accumulated score from Session 1 (0.42)
    if (key === 'cross_session_2') {
      onReset(0.42);
    } else {
      onReset(0.0);
    }
  };

  const handleNextStep = async () => {
    if (!activeScenario || currentStepIndex >= activeScenario.steps.length) return;
    const step = activeScenario.steps[currentStepIndex];
    await onRunStep(step, activeScenario.principal_id, activeScenario.agent_id);
    setCurrentStepIndex((prev) => prev + 1);
  };

  const handleRunAll = async () => {
    if (!activeScenario) return;
    setAutoPlaying(true);
    for (let i = currentStepIndex; i < activeScenario.steps.length; i++) {
      const step = activeScenario.steps[i];
      await onRunStep(step, activeScenario.principal_id, activeScenario.agent_id);
      setCurrentStepIndex(i + 1);
      await new Promise((resolve) => setTimeout(resolve, stepDelayMs));
    }
    setAutoPlaying(false);
  };

  const isCompleted = activeScenario && currentStepIndex >= activeScenario.steps.length;

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">Scenario Demonstrator (Judge Showcase)</h3>
          <p className="text-[11px] text-slate-400">1-Click reproducible test vectors for attack &amp; legitimate workflows</p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => {
              setCurrentStepIndex(0);
              setAutoPlaying(false);
              onReset(selectedScenarioKey === 'cross_session_2' ? 0.42 : 0.0);
            }}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition text-xs flex items-center space-x-1 cursor-pointer border border-slate-700"
            title="Reset Simulation State"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="text-[11px]">Reset</span>
          </button>
        </div>
      </div>

      {/* Scenario Selector Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
        <button
          onClick={() => handleSelectScenario('attack')}
          className={`p-3 rounded-xl border text-left transition flex flex-col justify-between cursor-pointer ${
            selectedScenarioKey === 'attack'
              ? 'bg-rose-950/40 border-rose-600/70 text-rose-200 ring-1 ring-rose-500/50'
              : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 text-slate-300'
          }`}
        >
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span className="text-xs font-bold">1. Boiling Frog Attack</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-2">
            6-step escalation: read logs -&gt; modify customer -&gt; drop table (BLOCKED).
          </p>
        </button>

        <button
          onClick={() => handleSelectScenario('legitimate')}
          className={`p-3 rounded-xl border text-left transition flex flex-col justify-between cursor-pointer ${
            selectedScenarioKey === 'legitimate'
              ? 'bg-emerald-950/40 border-emerald-600/70 text-emerald-200 ring-1 ring-emerald-500/50'
              : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 text-slate-300'
          }`}
        >
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="text-xs font-bold">2. Legitimate Report</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-2">
            In-scope operational workflow that completes smoothly without false positives.
          </p>
        </button>

        <button
          onClick={() => handleSelectScenario('cross_session_1')}
          className={`p-3 rounded-xl border text-left transition flex flex-col justify-between cursor-pointer ${
            selectedScenarioKey.startsWith('cross_session')
              ? 'bg-indigo-950/40 border-indigo-600/70 text-indigo-200 ring-1 ring-indigo-500/50'
              : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 text-slate-300'
          }`}
        >
          <div className="flex items-center space-x-2">
            <Database className="w-4 h-4 text-indigo-400 shrink-0" />
            <span className="text-xs font-bold">3. Cross-Session Memory</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-2">
            Session 1 context persists into Session 2, intercepting multi-day attacks early.
          </p>
        </button>
      </div>

      {/* Cross-session phase selector */}
      {selectedScenarioKey.startsWith('cross_session') && (
        <div className="flex items-center justify-between bg-slate-950/90 p-2.5 rounded-lg border border-indigo-900/50 text-xs">
          <span className="text-slate-400 text-[11px] font-semibold">Active Session Phase:</span>
          <div className="flex space-x-2">
            <button
              onClick={() => handleSelectScenario('cross_session_1')}
              className={`px-3 py-1 rounded text-[11px] font-semibold transition cursor-pointer ${
                selectedScenarioKey === 'cross_session_1'
                  ? 'bg-indigo-600 text-white shadow'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              Session 1 (Recon &amp; Setup)
            </button>
            <button
              onClick={() => handleSelectScenario('cross_session_2')}
              className={`px-3 py-1 rounded text-[11px] font-semibold transition cursor-pointer ${
                selectedScenarioKey === 'cross_session_2'
                  ? 'bg-indigo-600 text-white shadow'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              Session 2 (Infiltration Catch)
            </button>
          </div>
        </div>
      )}

      {/* Speed Slider & Queue */}
      <div className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-4 space-y-3">
        <div className="flex justify-between items-center text-xs">
          <span className="text-slate-400">
            Step Queue: <span className="font-mono text-slate-200 font-bold">{currentStepIndex} / {activeScenario?.steps.length || 0}</span>
          </span>
          <div className="flex items-center space-x-2 text-[11px] text-slate-400">
            <Sliders className="w-3.5 h-3.5 text-slate-500" />
            <span>Delay:</span>
            <select
              value={stepDelayMs}
              onChange={(e) => setStepDelayMs(Number(e.target.value))}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-0.5 text-slate-300 font-mono text-[10px]"
            >
              <option value={400}>Fast (0.4s)</option>
              <option value={700}>Normal (0.7s)</option>
              <option value={1200}>Slow (1.2s)</option>
            </select>
          </div>
        </div>

        {/* Step Preview Chips */}
        <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
          {activeScenario?.steps.map((s, idx) => {
            const isDone = idx < currentStepIndex;
            const isCurrent = idx === currentStepIndex;
            return (
              <div
                key={idx}
                className={`p-2 rounded text-xs flex items-center justify-between font-mono border transition ${
                  isCurrent
                    ? 'bg-indigo-950/60 border-indigo-500/70 text-indigo-200'
                    : isDone
                    ? 'bg-slate-900/40 border-slate-800/40 text-slate-500 line-through'
                    : 'bg-slate-950/40 border-slate-800/60 text-slate-400'
                }`}
              >
                <div className="flex items-center space-x-2 truncate">
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                    #{s.step}
                  </span>
                  <span className="font-bold">{s.action}</span>
                  <span className="text-slate-500 text-[11px] truncate">({s.resource})</span>
                </div>
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded shrink-0 ${
                    s.expected_reversibility === 'DESTRUCTIVE'
                      ? 'text-rose-400 bg-rose-950/50'
                      : s.expected_reversibility === 'WRITE'
                      ? 'text-amber-400 bg-amber-950/50'
                      : 'text-emerald-400 bg-emerald-950/50'
                  }`}
                >
                  {s.expected_reversibility}
                </span>
              </div>
            );
          })}
        </div>

        {/* Action Dispatch Buttons */}
        <div className="grid grid-cols-2 gap-3 pt-2">
          <button
            disabled={isCompleted || isRunning || autoPlaying}
            onClick={handleNextStep}
            className="py-2.5 px-4 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white font-bold rounded-lg transition text-xs flex items-center justify-center space-x-2 cursor-pointer shadow-md shadow-indigo-600/20"
          >
            <Play className="w-4 h-4" />
            <span>Step Next Action (#{currentStepIndex + 1})</span>
          </button>

          <button
            disabled={isCompleted || isRunning || autoPlaying}
            onClick={handleRunAll}
            className="py-2.5 px-4 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-200 font-semibold rounded-lg border border-slate-700 transition text-xs flex items-center justify-center space-x-2 cursor-pointer"
          >
            <FastForward className="w-4 h-4 text-indigo-400" />
            <span>{autoPlaying ? 'Running Scenario...' : 'Auto-Run Scenario'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
