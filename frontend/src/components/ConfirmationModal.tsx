import React, { useState } from 'react';
import { ActionDecision, ActionProposal } from '../types/tripwire';
import { AlertOctagon, CheckCircle, XCircle, ShieldAlert } from 'lucide-react';

interface Props {
  isOpen: boolean;
  decision: ActionDecision | null;
  proposal: ActionProposal | null;
  onConfirm: (approvedBy: string, approve: boolean) => void;
  onClose: () => void;
}

export const ConfirmationModal: React.FC<Props> = ({
  isOpen,
  decision,
  proposal,
  onConfirm,
  onClose,
}) => {
  const [approverId, setApproverId] = useState('admin_security_01');

  if (!isOpen || !decision || !proposal) return null;

  const isHardConfirm = decision.decision === 'HARD_CONFIRM';

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-5 animate-in fade-in zoom-in-95 duration-150">
        {/* Modal Header */}
        <div className="flex items-start space-x-3">
          <div className={`p-3 rounded-xl ${isHardConfirm ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'}`}>
            {isHardConfirm ? <ShieldAlert className="w-6 h-6" /> : <AlertOctagon className="w-6 h-6" />}
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100">
              {isHardConfirm ? 'HARD CONFIRMATION GATE' : 'HUMAN APPROVAL REQUIRED'}
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Tripwire has gated this action from autonomous execution pending cryptographic or human verification.
            </p>
          </div>
        </div>

        {/* Action Details Summary */}
        <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 space-y-2.5 text-xs">
          <div className="flex justify-between items-center text-slate-400">
            <span>Action Name:</span>
            <span className="font-mono text-indigo-300 font-bold">{proposal.action}</span>
          </div>
          <div className="flex justify-between items-center text-slate-400">
            <span>Target Resource:</span>
            <span className="font-mono text-slate-200">{proposal.resource}</span>
          </div>
          <div className="flex justify-between items-center text-slate-400">
            <span>Reversibility Class:</span>
            <span className="font-semibold text-rose-400 font-mono">{decision.reversibility}</span>
          </div>
          <div className="flex justify-between items-center text-slate-400">
            <span>Trajectory Risk Score:</span>
            <span className="font-mono text-amber-400 font-bold">{decision.trajectory_score.toFixed(3)} ({decision.risk_band})</span>
          </div>
          <div className="pt-2 border-t border-slate-800/80 text-slate-300">
            <span className="text-slate-500 text-[10px] uppercase font-bold block mb-1">Harness Intercept Reason:</span>
            <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/60 p-2 rounded border border-slate-800">
              {decision.reason}
            </p>
          </div>
        </div>

        {/* Approver Input */}
        <div className="space-y-1.5 text-xs">
          <label className="text-slate-400 font-medium">Authorizing Principal / SOC Approver ID:</label>
          <input
            type="text"
            value={approverId}
            onChange={(e) => setApproverId(e.target.value)}
            className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
            placeholder="e.g. admin_sec_ops"
          />
        </div>

        {/* Action Buttons */}
        <div className="grid grid-cols-2 gap-3 pt-2">
          <button
            onClick={() => {
              onConfirm(approverId, false);
              onClose();
            }}
            className="py-2.5 px-4 bg-slate-800 hover:bg-rose-950/80 hover:text-rose-300 text-slate-300 font-semibold rounded-lg border border-slate-700 hover:border-rose-700/50 transition text-xs flex items-center justify-center space-x-2 cursor-pointer"
          >
            <XCircle className="w-4 h-4 text-rose-400" />
            <span>DENY (Block Execution)</span>
          </button>

          <button
            onClick={() => {
              onConfirm(approverId, true);
              onClose();
            }}
            className="py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold rounded-lg transition text-xs flex items-center justify-center space-x-2 shadow-lg shadow-emerald-600/20 cursor-pointer"
          >
            <CheckCircle className="w-4 h-4" />
            <span>APPROVE &amp; REVALIDATE</span>
          </button>
        </div>
      </div>
    </div>
  );
};
