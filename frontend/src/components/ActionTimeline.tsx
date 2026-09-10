import React from 'react';
import { TrajectoryEvent, DecisionType, ReversibilityType } from '../types/tripwire';
import { CheckCircle2, AlertTriangle, ShieldX, HelpCircle, ChevronRight } from 'lucide-react';

interface Props {
  events: TrajectoryEvent[];
  onSelectEvent?: (event: TrajectoryEvent) => void;
}

export const ActionTimeline: React.FC<Props> = ({ events, onSelectEvent }) => {
  const getDecisionIcon = (decision: DecisionType) => {
    switch (decision) {
      case 'ALLOW':
        return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
      case 'CONFIRM':
      case 'HARD_CONFIRM':
        return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />;
      case 'BLOCK':
      default:
        return <ShieldX className="w-4 h-4 text-rose-400 shrink-0" />;
    }
  };

  const getDecisionBadge = (decision: DecisionType) => {
    switch (decision) {
      case 'ALLOW':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-700/50';
      case 'CONFIRM':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/50';
      case 'HARD_CONFIRM':
        return 'bg-orange-950/80 text-orange-300 border-orange-700/50';
      case 'BLOCK':
      default:
        return 'bg-rose-950/80 text-rose-300 border-rose-700/50';
    }
  };

  const getReversibilityBadge = (rev: ReversibilityType) => {
    switch (rev) {
      case 'DESTRUCTIVE':
        return 'text-rose-400 bg-rose-950/60 border-rose-800/40';
      case 'WRITE':
        return 'text-amber-400 bg-amber-950/60 border-amber-800/40';
      case 'READ':
      default:
        return 'text-emerald-400 bg-emerald-950/60 border-emerald-800/40';
    }
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">Forensic Action Timeline</h3>
          <p className="text-[11px] text-slate-400">Step-by-step proposal audit with trajectory scoring</p>
        </div>
        <span className="text-xs font-mono text-slate-500">{events.length} steps evaluated</span>
      </div>

      <div className="mt-4 space-y-2.5 max-h-96 overflow-y-auto pr-1">
        {events.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs">
            No evaluated actions in this session timeline yet.
          </div>
        ) : (
          events.map((evt, idx) => (
            <div
              key={idx}
              onClick={() => onSelectEvent && onSelectEvent(evt)}
              className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-lg hover:border-slate-700 transition cursor-pointer flex items-center justify-between group"
            >
              <div className="flex items-center space-x-3">
                {getDecisionIcon(evt.decision)}
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs font-bold text-slate-200">
                      {evt.step}. {evt.action}
                    </span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-semibold border ${getReversibilityBadge(evt.reversibility)}`}>
                      {evt.reversibility}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                    Target: <span className="text-slate-300">{evt.resource}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center space-x-3 text-right">
                <div>
                  <span className="text-[10px] text-slate-500 block font-mono">Score</span>
                  <span className="font-mono text-xs font-bold text-slate-200">
                    {evt.trajectory_score.toFixed(3)}
                  </span>
                </div>
                <span className={`px-2 py-0.5 rounded text-[11px] font-bold border font-mono ${getDecisionBadge(evt.decision)}`}>
                  {evt.decision}
                </span>
                <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-300 transition" />
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
