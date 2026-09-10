import React from 'react';
import { ActionDecision, ActionProposal } from '../types/tripwire';
import { ShieldCheck, ShieldAlert, ShieldX, HelpCircle, AlertOctagon, Terminal } from 'lucide-react';

interface Props {
  currentProposal: ActionProposal | null;
  currentDecision: ActionDecision | null;
  onRequestConfirm?: (decision: ActionDecision) => void;
}

export const DecisionCard: React.FC<Props> = ({ currentProposal, currentDecision, onRequestConfirm }) => {
  if (!currentProposal && !currentDecision) {
    return (
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 text-center text-slate-500 text-xs">
        <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-slate-600" />
        No active action under evaluation. Agent is idle.
      </div>
    );
  }

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return {
          icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
          classes: 'bg-emerald-950/80 text-emerald-300 border-emerald-600/50',
          label: 'ALLOW',
        };
      case 'CONFIRM':
        return {
          icon: <HelpCircle className="w-5 h-5 text-amber-400" />,
          classes: 'bg-amber-950/80 text-amber-300 border-amber-600/50',
          label: 'CONFIRM (Human Sign-off)',
        };
      case 'HARD_CONFIRM':
        return {
          icon: <ShieldAlert className="w-5 h-5 text-orange-400" />,
          classes: 'bg-orange-950/80 text-orange-300 border-orange-600/50',
          label: 'HARD CONFIRM (Dual Re-validation)',
        };
      case 'BLOCK':
      default:
        return {
          icon: <ShieldX className="w-5 h-5 text-rose-400" />,
          classes: 'bg-rose-950/80 text-rose-300 border-rose-600/50',
          label: 'BLOCK (Protected Execution Halted)',
        };
    }
  };

  const getReversibilityBadge = (rev: string) => {
    switch (rev) {
      case 'DESTRUCTIVE':
        return 'bg-rose-950 text-rose-300 border-rose-700/50';
      case 'WRITE':
        return 'bg-amber-950 text-amber-300 border-amber-700/50';
      case 'READ':
      default:
        return 'bg-emerald-950 text-emerald-300 border-emerald-700/50';
    }
  };

  const badge = currentDecision ? getDecisionBadge(currentDecision.decision) : null;

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-indigo-400" />
          <h3 className="text-sm font-semibold text-slate-100">Live Decision Gate</h3>
        </div>
        {badge && (
          <span className={`px-3 py-1 rounded-full text-xs font-bold border flex items-center space-x-1.5 ${badge.classes}`}>
            {badge.icon}
            <span>{badge.label}</span>
          </span>
        )}
      </div>

      {currentProposal && (
        <div className="bg-slate-950/70 p-3.5 rounded-lg border border-slate-800/80 space-y-2 text-xs">
          <div className="flex justify-between items-center text-slate-400">
            <span>Proposed Action</span>
            <span className="font-mono text-indigo-300 font-bold">{currentProposal.action}</span>
          </div>
          <div className="flex justify-between items-center text-slate-400">
            <span>Target Resource</span>
            <span className="font-mono text-slate-200">{currentProposal.resource}</span>
          </div>
          <div className="flex justify-between items-center text-slate-400">
            <span>Principal Identity</span>
            <span className="font-mono text-slate-300">{currentProposal.principal_id}</span>
          </div>
          {currentProposal.parameters && Object.keys(currentProposal.parameters).length > 0 && (
            <div className="pt-2 border-t border-slate-800/60">
              <span className="text-slate-500 block mb-1">Payload:</span>
              <pre className="p-2 rounded bg-slate-900 text-slate-300 font-mono text-[11px] overflow-x-auto">
                {JSON.stringify(currentProposal.parameters, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {currentDecision && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="bg-slate-950/50 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Reversibility Class</span>
              <span className={`inline-block mt-1 px-2 py-0.5 rounded text-[11px] font-semibold border ${getReversibilityBadge(currentDecision.reversibility)}`}>
                {currentDecision.reversibility}
              </span>
            </div>
            <div className="bg-slate-950/50 p-2.5 rounded border border-slate-800">
              <span className="text-slate-500 block text-[10px] uppercase">Action ID</span>
              <span className="font-mono text-slate-300 mt-1 block truncate">{currentDecision.action_id}</span>
            </div>
          </div>

          <div className="bg-slate-950/80 p-3 rounded border border-slate-800/80">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block mb-1 font-semibold">Security Reason</span>
            <p className="text-xs text-slate-300 font-sans leading-relaxed">{currentDecision.reason}</p>
          </div>

          {(currentDecision.decision === 'CONFIRM' || currentDecision.decision === 'HARD_CONFIRM') && onRequestConfirm && (
            <button
              onClick={() => onRequestConfirm(currentDecision)}
              className="w-full py-2.5 px-4 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold rounded-lg transition text-xs flex items-center justify-center space-x-2 shadow-md shadow-amber-500/20 cursor-pointer"
            >
              <AlertOctagon className="w-4 h-4" />
              <span>Review &amp; Authorize Action (HITL Gate)</span>
            </button>
          )}
        </div>
      )}
    </div>
  );
};
