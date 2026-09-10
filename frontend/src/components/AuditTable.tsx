import React, { useState } from 'react';
import { AuditEvent, DecisionType } from '../types/tripwire';
import { Terminal, Download, Search, Filter } from 'lucide-react';

interface Props {
  auditEvents: AuditEvent[];
}

export const AuditTable: React.FC<Props> = ({ auditEvents }) => {
  const [filterDecision, setFilterDecision] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const filteredEvents = auditEvents.filter((evt) => {
    const matchesFilter = filterDecision === 'ALL' || evt.decision === filterDecision;
    const matchesSearch =
      evt.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      evt.resource.toLowerCase().includes(searchTerm.toLowerCase()) ||
      evt.principal_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      evt.reason.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(auditEvents, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `tripwire_audit_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-700/50';
      case 'CONFIRM':
      case 'HARD_CONFIRM':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/50';
      case 'BLOCK':
      default:
        return 'bg-rose-950/80 text-rose-300 border-rose-700/50';
    }
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800 gap-3">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-indigo-500/20 text-indigo-400 rounded-lg">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Tripwire Audit &amp; Forensics Trail</h3>
            <p className="text-[11px] text-slate-400">Tamper-evident log of all intercepted proposals and decisions</p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={handleExportJson}
            disabled={auditEvents.length === 0}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded-lg text-xs flex items-center space-x-1.5 transition cursor-pointer border border-slate-700"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Audit JSON</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 text-xs">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by action, resource, principal, reason..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 font-mono text-xs"
          />
        </div>

        <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
          {['ALL', 'ALLOW', 'CONFIRM', 'BLOCK'].map((btn) => (
            <button
              key={btn}
              onClick={() => setFilterDecision(btn)}
              className={`px-3 py-1 rounded text-[11px] font-semibold transition cursor-pointer ${
                filterDecision === btn ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {btn}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        {filteredEvents.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            No matching audit records found.
          </div>
        ) : (
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase">
                <th className="pb-3 font-semibold">Timestamp</th>
                <th className="pb-3 font-semibold">Principal</th>
                <th className="pb-3 font-semibold">Action</th>
                <th className="pb-3 font-semibold">Resource</th>
                <th className="pb-3 font-semibold">Class</th>
                <th className="pb-3 font-semibold">Score</th>
                <th className="pb-3 font-semibold">Decision</th>
                <th className="pb-3 font-semibold">Exec Status</th>
                <th className="pb-3 font-semibold">Approved By</th>
                <th className="pb-3 font-semibold">Executed At</th>
                <th className="pb-3 font-semibold">Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEvents.map((evt, idx) => (
                <tr key={idx} className="hover:bg-slate-950/50 transition">
                  <td className="py-2.5 text-slate-400 text-[11px] whitespace-nowrap">
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-2.5 text-slate-300 font-semibold">{evt.principal_id}</td>
                  <td className="py-2.5 text-indigo-300 font-bold">{evt.action}</td>
                  <td className="py-2.5 text-slate-400 truncate max-w-xs">{evt.resource}</td>
                  <td className="py-2.5">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        evt.reversibility === 'DESTRUCTIVE'
                          ? 'text-rose-400 bg-rose-950/60 border border-rose-800/40'
                          : evt.reversibility === 'WRITE'
                          ? 'text-amber-400 bg-amber-950/60 border border-amber-800/40'
                          : 'text-emerald-400 bg-emerald-950/60 border border-emerald-800/40'
                      }`}
                    >
                      {evt.reversibility}
                    </span>
                  </td>
                  <td className="py-2.5 text-slate-200 font-bold">{evt.trajectory_score.toFixed(3)}</td>
                  <td className="py-2.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getDecisionBadge(evt.decision)}`}>
                      {evt.decision}
                    </span>
                  </td>
                  <td className="py-2.5">
                    {evt.execution_status && (
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${
                        evt.execution_status === 'EXECUTED' ? 'bg-emerald-950/50 text-emerald-400 border border-emerald-800/30' :
                        evt.execution_status === 'NOT_EXECUTED' ? 'bg-slate-900 text-slate-500' :
                        'bg-amber-950/50 text-amber-400'
                      }`}>
                        {evt.execution_status}
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 text-slate-300 font-mono text-[10px]">{evt.approved_by || '-'}</td>
                  <td className="py-2.5 text-slate-400 text-[10px] whitespace-nowrap">
                    {evt.executed_at ? new Date(evt.executed_at).toLocaleTimeString() : '-'}
                  </td>
                  <td className="py-2.5 text-slate-300 max-w-md font-sans text-xs">{evt.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
