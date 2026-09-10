import React from 'react';
import { Shield, ShieldAlert, Cpu, Database, CheckCircle, Lock, ArrowRight, Activity, Terminal } from 'lucide-react';

export const ArchitectureView: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="max-w-3xl space-y-3">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-indigo-950/80 text-indigo-300 border border-indigo-700/50 text-xs font-mono">
            <Shield className="w-3.5 h-3.5" />
            <span>PS1: RUNTIME SECURITY HARNESS FOR AI AGENTS</span>
          </div>
          <h2 className="text-xl font-bold text-slate-100">
            Defense-in-Depth Middleware for Autonomous AI Workflows
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            When organizations deploy AI agents, they harden the model with system prompts and jailbreak filters—building a well-defended front door on a house with no walls. Tripwire sits between the AI agent and protected tools, enforcing authorization boundaries, reversibility gates, and cross-session behavioral trajectory monitoring that foundation models cannot self-enforce.
          </p>
        </div>
      </div>

      {/* 3 Core Pillars */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Pillar 1 */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="p-2.5 w-fit rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Lock className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-slate-100">1. Authorization Context Propagation</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Every agent action carries a non-forgeable principal scope token. Any unauthorized or out-of-scope tool call is blocked at the middleware layer before touching databases or cloud APIs.
          </p>
        </div>

        {/* Pillar 2 */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="p-2.5 w-fit rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-slate-100">2. Action Reversibility Gates</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Actions are classified into <span className="text-emerald-400 font-mono">READ</span>, <span className="text-amber-400 font-mono">WRITE</span>, and <span className="text-rose-400 font-mono">DESTRUCTIVE</span> tiers. Destructive operations mandate explicit Human-in-the-Loop (HITL) confirmation.
          </p>
        </div>

        {/* Pillar 3 */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3">
          <div className="p-2.5 w-fit rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <Activity className="w-5 h-5" />
          </div>
          <h3 className="text-sm font-bold text-slate-100">3. Cross-Session Trajectory Monitor</h3>
          <p className="text-xs text-slate-400 leading-relaxed">
            Tracks behavioral drift and asymmetric EMA scoring across turns and sessions. Catches "Boiling Frog" multi-day escalation attacks where individual steps appear routine in isolation.
          </p>
        </div>
      </div>

      {/* Decision Matrix Reference */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-indigo-400" />
          <span>Frozen Decision Matrix (Pre-Implementation Contract Section 9)</span>
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase">
                <th className="pb-3 font-semibold">Authorization</th>
                <th className="pb-3 font-semibold">Risk Band</th>
                <th className="pb-3 font-semibold">Reversibility</th>
                <th className="pb-3 font-semibold">Decision</th>
                <th className="pb-3 font-semibold">Tool Execution Outcome</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              <tr>
                <td className="py-2.5 text-rose-400 font-bold">DENIED</td>
                <td className="py-2.5 text-slate-400">Any</td>
                <td className="py-2.5 text-slate-400">Any</td>
                <td className="py-2.5"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-700/50">BLOCK</span></td>
                <td className="py-2.5 text-slate-400">Execution = 0</td>
              </tr>
              <tr>
                <td className="py-2.5 text-emerald-400 font-bold">ALLOWED</td>
                <td className="py-2.5 text-emerald-400">LOW (&lt; 0.35)</td>
                <td className="py-2.5 text-emerald-300">READ</td>
                <td className="py-2.5"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700/50">ALLOW</span></td>
                <td className="py-2.5 text-slate-400">Immediate Execution</td>
              </tr>
              <tr>
                <td className="py-2.5 text-emerald-400 font-bold">ALLOWED</td>
                <td className="py-2.5 text-emerald-400">LOW (&lt; 0.35)</td>
                <td className="py-2.5 text-amber-300">WRITE</td>
                <td className="py-2.5"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700/50">ALLOW</span></td>
                <td className="py-2.5 text-slate-400">Immediate Execution</td>
              </tr>
              <tr>
                <td className="py-2.5 text-emerald-400 font-bold">ALLOWED</td>
                <td className="py-2.5 text-emerald-400">LOW (&lt; 0.35)</td>
                <td className="py-2.5 text-rose-300">DESTRUCTIVE</td>
                <td className="py-2.5"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-700/50">CONFIRM</span></td>
                <td className="py-2.5 text-slate-400">Requires Human Sign-off</td>
              </tr>
              <tr>
                <td className="py-2.5 text-emerald-400 font-bold">ALLOWED</td>
                <td className="py-2.5 text-amber-400">MEDIUM (0.35 - 0.65)</td>
                <td className="py-2.5 text-emerald-300">READ</td>
                <td className="py-2.5"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-700/50">ALLOW</span></td>
                <td className="py-2.5 text-slate-400">Immediate Execution</td>
              </tr>
              <tr>
                <td className="py-2.5 text-emerald-400 font-bold">ALLOWED</td>
                <td className="py-2.5 text-amber-400">MEDIUM (0.35 - 0.65)</td>
                <td className="py-2.5 text-amber-300">WRITE</td>
                <td className="py-2.5"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-700/50">CONFIRM</span></td>
                <td className="py-2.5 text-slate-400">Requires Human Sign-off</td>
              </tr>
              <tr>
                <td className="py-2.5 text-emerald-400 font-bold">ALLOWED</td>
                <td className="py-2.5 text-amber-400">MEDIUM (0.35 - 0.65)</td>
                <td className="py-2.5 text-rose-300">DESTRUCTIVE</td>
                <td className="py-2.5"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950 text-orange-300 border border-orange-700/50">HARD_CONFIRM</span></td>
                <td className="py-2.5 text-slate-400">Requires Dual Re-validation</td>
              </tr>
              <tr className="bg-rose-950/20">
                <td className="py-2.5 text-emerald-400 font-bold">ALLOWED</td>
                <td className="py-2.5 text-rose-400 font-bold">HIGH (&gt; 0.65)</td>
                <td className="py-2.5 text-slate-300">ANY</td>
                <td className="py-2.5"><span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-700/50">BLOCK</span></td>
                <td className="py-2.5 text-rose-300 font-semibold">Autonomous Halt (0 Executions)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
