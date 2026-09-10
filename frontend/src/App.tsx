import React, { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  Terminal,
  Play,
  RotateCcw,
  Lock,
  Layers,
  Sparkles,
} from 'lucide-react';
import {
  ActionProposal,
  ActionDecision,
  TrajectoryEvent,
  AuditEvent,
  ScenarioStep,
  RiskBandType,
} from './types/tripwire';
import { defaultTripwireClient, TripwireClient } from './api/client';
import { TrajectoryChart } from './components/TrajectoryChart';
import { DecisionCard } from './components/DecisionCard';
import { ActionTimeline } from './components/ActionTimeline';
import { ConfirmationModal } from './components/ConfirmationModal';
import { AuditTable } from './components/AuditTable';
import { ScenarioRunner } from './components/ScenarioRunner';
import { ToolRegistryView } from './components/ToolRegistryView';
import { CustomActionSandbox } from './components/CustomActionSandbox';
import { ArchitectureView } from './components/ArchitectureView';

export default function App() {
  const [activeTab, setActiveTab] = useState<
    'dashboard' | 'scenarios' | 'sandbox' | 'audit' | 'tools' | 'architecture'
  >('dashboard');
  const [backendOnline, setBackendOnline] = useState<boolean>(false);

  // Runtime State
  const [sessionId, setSessionId] = useState<string>('session_001');
  const [principalId, setPrincipalId] = useState<string>('user_001');
  const [currentScore, setCurrentScore] = useState<number>(0.0);
  const [currentRiskBand, setCurrentRiskBand] = useState<RiskBandType>('LOW');

  const [currentProposal, setCurrentProposal] = useState<ActionProposal | null>(null);
  const [currentDecision, setCurrentDecision] = useState<ActionDecision | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<TrajectoryEvent | null>(null);
  const [events, setEvents] = useState<TrajectoryEvent[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [toolExecutionCounts, setToolExecutionCounts] = useState<Record<string, number>>({});

  // HITL Modal State
  const [isConfirmModalOpen, setIsConfirmModalOpen] = useState<boolean>(false);
  const [pendingConfirmDecision, setPendingConfirmDecision] = useState<ActionDecision | null>(null);
  const [pendingConfirmProposal, setPendingConfirmProposal] = useState<ActionProposal | null>(null);

  // Poll backend health
  useEffect(() => {
    const check = async () => {
      const res = await defaultTripwireClient.checkHealth();
      setBackendOnline(res.backendOnline);
    };
    check();
    const interval = setInterval(check, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleReset = (initialScore: number = 0.0) => {
    TripwireClient.resetSimState(initialScore);
    setCurrentScore(initialScore);
    setCurrentRiskBand(initialScore > 0.65 ? 'HIGH' : initialScore >= 0.35 ? 'MEDIUM' : 'LOW');
    setCurrentProposal(null);
    setCurrentDecision(null);
    setSelectedEvent(null);
    setEvents([]);
    setToolExecutionCounts({});
    setSessionId(`session_${Date.now().toString().slice(-4)}`);
  };

  const handleDispatchProposal = async (proposal: ActionProposal) => {
    setPrincipalId(proposal.principal_id);
    setCurrentProposal(proposal);

    // Call Tripwire
    const decision = await defaultTripwireClient.proposeAction(proposal);
    setCurrentDecision(decision);
    setCurrentScore(decision.trajectory_score);
    setCurrentRiskBand(decision.risk_band);

    const isAllowed = decision.decision === 'ALLOW';
    const isConfirm = decision.decision === 'CONFIRM' || decision.decision === 'HARD_CONFIRM';

    // Record Trajectory Event
    const newEvent: TrajectoryEvent = {
      step: events.length + 1,
      action: proposal.action,
      resource: proposal.resource,
      reversibility: decision.reversibility,
      trajectory_score: decision.trajectory_score,
      risk_band: decision.risk_band,
      decision: decision.decision,
      reason: decision.reason,
      timestamp: new Date().toISOString(),
    };
    setEvents((prev) => [...prev, newEvent]);

    // Record Audit Event
    const newAuditEvent: AuditEvent = {
      action_id: decision.action_id,
      principal_id: proposal.principal_id,
      session_id: sessionId,
      agent_id: proposal.agent_id,
      action: proposal.action,
      resource: proposal.resource,
      reversibility: decision.reversibility,
      trajectory_score: decision.trajectory_score,
      risk_band: decision.risk_band,
      decision: decision.decision,
      reason: decision.reason,
      timestamp: new Date().toISOString(),
      parameters: proposal.parameters,
      execution_status: isAllowed ? 'EXECUTED' : isConfirm ? 'PENDING_APPROVAL' : 'NOT_EXECUTED',
    };
    setAuditEvents((prev) => [newAuditEvent, ...prev]);

    // Protected Tool Handling
    if (isAllowed) {
      setToolExecutionCounts((prev) => ({
        ...prev,
        [proposal.action]: (prev[proposal.action] || 0) + 1,
      }));
    } else if (isConfirm) {
      setPendingConfirmDecision(decision);
      setPendingConfirmProposal(proposal);
      setIsConfirmModalOpen(true);
    }
  };

  const handleStepAction = async (step: ScenarioStep, principal: string, agentId: string) => {
    await handleDispatchProposal({
      principal_id: principal,
      session_id: sessionId,
      agent_id: agentId,
      action: step.action,
      resource: step.resource,
      parameters: step.parameters,
    });
  };

  const handleHumanConfirm = async (approvedBy: string, approve: boolean) => {
    if (!pendingConfirmDecision || !pendingConfirmProposal) return;

    const res = await defaultTripwireClient.confirmAction(
      pendingConfirmDecision.action_id,
      approvedBy,
      approve
    );

    if (res.decision === 'ALLOW') {
      setToolExecutionCounts((prev) => ({
        ...prev,
        [pendingConfirmProposal.action]: (prev[pendingConfirmProposal.action] || 0) + 1,
      }));

      setAuditEvents((prev) =>
        prev.map((a) =>
          a.action_id === pendingConfirmDecision.action_id
            ? { ...a, decision: 'ALLOW', execution_status: 'EXECUTED', reason: `Approved by human operator (${approvedBy})` }
            : a
        )
      );
    } else {
      setAuditEvents((prev) =>
        prev.map((a) =>
          a.action_id === pendingConfirmDecision.action_id
            ? { ...a, decision: 'BLOCK', execution_status: 'NOT_EXECUTED', reason: `Denied by human operator (${approvedBy})` }
            : a
        )
      );
    }

    setPendingConfirmDecision(null);
    setPendingConfirmProposal(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-40">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-indigo-500/20 border border-indigo-500/40 rounded-xl text-indigo-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-indigo-400 via-sky-300 to-emerald-400 bg-clip-text text-transparent">
                TRIPWIRE
              </h1>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-indigo-950 text-indigo-300 border border-indigo-700/50 font-mono font-bold tracking-wider">
                RUNTIME SECURITY HARNESS
              </span>
            </div>
            <p className="text-xs text-slate-400">Model-Agnostic AI Agent Authorization, Reversibility &amp; Trajectory Middleware</p>
          </div>
        </div>

        {/* Indicators */}
        <div className="flex items-center space-x-3 text-xs">
          <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg">
            <span className={`w-2 h-2 rounded-full ${backendOnline ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse'}`}></span>
            <span className="text-slate-400">Harness Engine:</span>
            <span className={`font-semibold ${backendOnline ? 'text-emerald-300' : 'text-amber-300'}`}>
              {backendOnline ? 'FastAPI Connected' : 'Simulated Harness'}
            </span>
          </div>
          <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg">
            <span className="text-slate-400">Active Session:</span>
            <span className="font-mono text-indigo-300 font-bold">{sessionId}</span>
          </div>
        </div>
      </header>

      {/* Navigation Subheader */}
      <div className="border-b border-slate-800 bg-slate-900/40 px-6 overflow-x-auto">
        <div className="flex space-x-6 min-w-max">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 transition cursor-pointer ${
              activeTab === 'dashboard'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Overview &amp; Trajectory Monitor</span>
          </button>
          <button
            onClick={() => setActiveTab('scenarios')}
            className={`py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 transition cursor-pointer ${
              activeTab === 'scenarios'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Play className="w-4 h-4" />
            <span>Interactive Scenario Runner</span>
          </button>
          <button
            onClick={() => setActiveTab('sandbox')}
            className={`py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 transition cursor-pointer ${
              activeTab === 'sandbox'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-4 h-4" />
            <span>Custom Action Sandbox</span>
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 transition cursor-pointer ${
              activeTab === 'audit'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Audit Forensics ({auditEvents.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('tools')}
            className={`py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 transition cursor-pointer ${
              activeTab === 'tools'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Protected Tools &amp; Invariants</span>
          </button>
          <button
            onClick={() => setActiveTab('architecture')}
            className={`py-3 text-xs font-semibold border-b-2 flex items-center space-x-2 transition cursor-pointer ${
              activeTab === 'architecture'
                ? 'border-indigo-500 text-indigo-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Architecture &amp; Decision Matrix</span>
          </button>
        </div>
      </div>

      {/* Main View Area */}
      <main className="flex-1 p-6 max-w-7xl mx-auto w-full">
        {activeTab === 'dashboard' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              <TrajectoryChart
                events={events}
                currentScore={currentScore}
                currentRiskBand={currentRiskBand}
                selectedEvent={selectedEvent}
                onSelectEvent={(evt) => setSelectedEvent(evt)}
              />
              <ActionTimeline
                events={events}
                onSelectEvent={(evt) => setSelectedEvent(evt)}
              />
            </div>

            <div className="space-y-6">
              <DecisionCard
                currentProposal={currentProposal}
                currentDecision={currentDecision}
                onRequestConfirm={() => setIsConfirmModalOpen(true)}
              />
              <ScenarioRunner
                isRunning={false}
                onRunStep={handleStepAction}
                onReset={handleReset}
                toolExecutionCounts={toolExecutionCounts}
              />
            </div>
          </div>
        )}

        {activeTab === 'scenarios' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1 space-y-6">
              <ScenarioRunner
                isRunning={false}
                onRunStep={handleStepAction}
                onReset={handleReset}
                toolExecutionCounts={toolExecutionCounts}
              />
              <ToolRegistryView executionCounts={toolExecutionCounts} />
            </div>

            <div className="lg:col-span-2 space-y-6">
              <TrajectoryChart
                events={events}
                currentScore={currentScore}
                currentRiskBand={currentRiskBand}
                selectedEvent={selectedEvent}
                onSelectEvent={(evt) => setSelectedEvent(evt)}
              />
              <DecisionCard
                currentProposal={currentProposal}
                currentDecision={currentDecision}
                onRequestConfirm={() => setIsConfirmModalOpen(true)}
              />
              <ActionTimeline
                events={events}
                onSelectEvent={(evt) => setSelectedEvent(evt)}
              />
            </div>
          </div>
        )}

        {activeTab === 'sandbox' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1 space-y-6">
              <CustomActionSandbox
                onPropose={handleDispatchProposal}
                currentSessionId={sessionId}
              />
              <ToolRegistryView executionCounts={toolExecutionCounts} />
            </div>

            <div className="lg:col-span-2 space-y-6">
              <TrajectoryChart
                events={events}
                currentScore={currentScore}
                currentRiskBand={currentRiskBand}
                selectedEvent={selectedEvent}
                onSelectEvent={(evt) => setSelectedEvent(evt)}
              />
              <DecisionCard
                currentProposal={currentProposal}
                currentDecision={currentDecision}
                onRequestConfirm={() => setIsConfirmModalOpen(true)}
              />
              <ActionTimeline
                events={events}
                onSelectEvent={(evt) => setSelectedEvent(evt)}
              />
            </div>
          </div>
        )}

        {activeTab === 'audit' && (
          <div className="space-y-6">
            <AuditTable auditEvents={auditEvents} />
          </div>
        )}

        {activeTab === 'tools' && (
          <div className="max-w-3xl mx-auto space-y-6">
            <ToolRegistryView executionCounts={toolExecutionCounts} />
          </div>
        )}

        {activeTab === 'architecture' && (
          <ArchitectureView />
        )}
      </main>

      {/* Human-in-the-Loop Confirmation Modal */}
      <ConfirmationModal
        isOpen={isConfirmModalOpen}
        decision={pendingConfirmDecision}
        proposal={pendingConfirmProposal}
        onConfirm={handleHumanConfirm}
        onClose={() => setIsConfirmModalOpen(false)}
      />
    </div>
  );
}
