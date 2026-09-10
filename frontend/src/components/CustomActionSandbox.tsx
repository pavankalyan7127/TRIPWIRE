import React, { useState } from 'react';
import { Send, Terminal, Sparkles, AlertCircle } from 'lucide-react';
import { ActionProposal, ReversibilityType } from '../types/tripwire';

interface Props {
  onPropose: (proposal: ActionProposal) => Promise<void>;
  currentSessionId: string;
}

export const CustomActionSandbox: React.FC<Props> = ({ onPropose, currentSessionId }) => {
  const [principalId, setPrincipalId] = useState<string>('operator_custom');
  const [agentId, setAgentId] = useState<string>('agent_custom_01');
  const [action, setAction] = useState<string>('search_customers');
  const [resource, setResource] = useState<string>('db_records:customer_table');
  const [parametersJson, setParametersJson] = useState<string>('{\n  "query": "active_users"\n}');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [jsonError, setJsonError] = useState<string | null>(null);

  const predefinedActions = [
    { label: 'Read Logs', action: 'read_logs', resource: 'logs', params: '{}' },
    { label: 'Read Customer', action: 'read_customer', resource: 'db_records:customer_table', params: '{"id": "cust_101"}' },
    { label: 'Update Record', action: 'update_customer', resource: 'db_records:customer_table', params: '{"id": "cust_101", "role": "admin"}' },
    { label: 'Export Database', action: 'export_customers', resource: 'db_records:customer_table', params: '{"destination": "s3://vault/data.csv"}' },
    { label: 'Change Perms', action: 'change_permissions', resource: 'system:permissions', params: '{"rules": ["*"]}' },
    { label: 'Drop Table', action: 'drop_table', resource: 'db_schema:core', params: '{"table": "customer_table"}' },
  ];

  const handleSelectPreset = (preset: typeof predefinedActions[0]) => {
    setAction(preset.action);
    setResource(preset.resource);
    setParametersJson(preset.params);
    setJsonError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setJsonError(null);

    let parsedParams: Record<string, any> = {};
    if (parametersJson.trim()) {
      try {
        parsedParams = JSON.parse(parametersJson);
      } catch (err: any) {
        setJsonError(`Invalid JSON payload: ${err.message}`);
        return;
      }
    }

    setIsSubmitting(true);
    await onPropose({
      principal_id: principalId,
      session_id: currentSessionId,
      agent_id: agentId,
      action,
      resource,
      parameters: parsedParams,
    });
    setIsSubmitting(false);
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-indigo-400" />
          <h3 className="text-sm font-semibold text-slate-100">Interactive Action Sandbox</h3>
        </div>
        <span className="text-[11px] font-mono text-indigo-400 flex items-center space-x-1">
          <Sparkles className="w-3 h-3" />
          <span>Live Evaluation</span>
        </span>
      </div>

      {/* Preset Action Buttons */}
      <div className="space-y-1.5">
        <span className="text-[10px] text-slate-400 uppercase font-semibold">Quick Presets:</span>
        <div className="flex flex-wrap gap-1.5">
          {predefinedActions.map((p) => (
            <button
              key={p.action}
              type="button"
              onClick={() => handleSelectPreset(p)}
              className="px-2.5 py-1 rounded-md bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-slate-300 transition cursor-pointer"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="space-y-3 text-xs">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-slate-400 block mb-1">Principal ID</label>
            <input
              type="text"
              value={principalId}
              onChange={(e) => setPrincipalId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
              required
            />
          </div>
          <div>
            <label className="text-slate-400 block mb-1">Agent ID</label>
            <input
              type="text"
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
              required
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-slate-400 block mb-1">Action Name</label>
            <input
              type="text"
              value={action}
              onChange={(e) => setAction(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-indigo-300 font-mono text-xs font-semibold focus:outline-none focus:border-indigo-500"
              placeholder="e.g. drop_table"
              required
            />
          </div>
          <div>
            <label className="text-slate-400 block mb-1">Target Resource</label>
            <input
              type="text"
              value={resource}
              onChange={(e) => setResource(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-200 font-mono text-xs focus:outline-none focus:border-indigo-500"
              placeholder="e.g. db_schema:core"
              required
            />
          </div>
        </div>

        <div>
          <label className="text-slate-400 block mb-1">Payload JSON (Parameters)</label>
          <textarea
            rows={3}
            value={parametersJson}
            onChange={(e) => setParametersJson(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 font-mono text-xs text-slate-300 focus:outline-none focus:border-indigo-500"
          />
          {jsonError && (
            <p className="text-[11px] text-rose-400 flex items-center space-x-1 mt-1">
              <AlertCircle className="w-3 h-3 shrink-0" />
              <span>{jsonError}</span>
            </p>
          )}
        </div>

        <button
          type="submit"
          disabled={isSubmitting}
          className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white font-bold rounded-lg transition flex items-center justify-center space-x-2 cursor-pointer shadow-md shadow-indigo-600/20"
        >
          <Send className="w-3.5 h-3.5" />
          <span>{isSubmitting ? 'Evaluating with Tripwire...' : 'Dispatch Action Proposal'}</span>
        </button>
      </form>
    </div>
  );
};
