import React from 'react';
import { Lock, CheckCircle2, ShieldAlert } from 'lucide-react';

interface Props {
  executionCounts: Record<string, number>;
}

export const ToolRegistryView: React.FC<Props> = ({ executionCounts }) => {
  const tools = [
    {
      name: 'read_logs',
      resource: 'logs',
      reversibility: 'READ',
      scope: 'logs:read',
      desc: 'Read system audit logs',
    },
    {
      name: 'search_customers',
      resource: 'db_records:customer_table',
      reversibility: 'READ',
      scope: 'customer:read',
      desc: 'Search customer records',
    },
    {
      name: 'read_customer',
      resource: 'db_records:customer_table',
      reversibility: 'READ',
      scope: 'customer:read',
      desc: 'Read customer details',
    },
    {
      name: 'export_customers',
      resource: 'db_records:customer_table',
      reversibility: 'WRITE',
      scope: 'customer:write',
      desc: 'Export bulk records to external storage',
    },
    {
      name: 'update_customer',
      resource: 'db_records:customer_table',
      reversibility: 'WRITE',
      scope: 'customer:write',
      desc: 'Modify customer attributes',
    },
    {
      name: 'change_permissions',
      resource: 'system:permissions',
      reversibility: 'DESTRUCTIVE',
      scope: 'permissions:write',
      desc: 'Modify RBAC access permissions',
    },
    {
      name: 'drop_table',
      resource: 'db_schema:core',
      reversibility: 'DESTRUCTIVE',
      scope: 'schema:admin',
      desc: 'Permanently drop relational database table',
    },
  ];

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <Lock className="w-4 h-4 text-indigo-400" />
          <h3 className="text-sm font-semibold text-slate-100">Protected Tool Registry &amp; Invariants</h3>
        </div>
        <span className="text-[11px] font-mono text-emerald-400">Zero-Bypass Architecture</span>
      </div>

      <p className="text-xs text-slate-400">
        Tool handlers execute <span className="text-slate-200 font-semibold">strictly</span> after passing Tripwire authorization and trajectory gates. Invocations remain 0 on blocked attempts.
      </p>

      <div className="space-y-2">
        {tools.map((t) => {
          const count = executionCounts[t.name] || 0;
          return (
            <div
              key={t.name}
              className="p-2.5 bg-slate-950/70 border border-slate-800/80 rounded-lg flex items-center justify-between text-xs font-mono"
            >
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-slate-200">{t.name}</span>
                  <span
                    className={`px-1.5 py-0.2 rounded text-[10px] font-semibold ${
                      t.reversibility === 'DESTRUCTIVE'
                        ? 'text-rose-400 bg-rose-950/60 border border-rose-800/40'
                        : t.reversibility === 'WRITE'
                        ? 'text-amber-400 bg-amber-950/60 border border-amber-800/40'
                        : 'text-emerald-400 bg-emerald-950/60 border border-emerald-800/40'
                    }`}
                  >
                    {t.reversibility}
                  </span>
                </div>
                <span className="text-slate-500 text-[11px] block mt-0.5">Scope: {t.scope}</span>
              </div>

              <div className="text-right">
                <span className="text-[10px] text-slate-500 block uppercase">Invocations</span>
                <span
                  className={`font-bold font-mono text-xs px-2 py-0.5 rounded ${
                    count > 0 ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/50' : 'bg-slate-900 text-slate-500'
                  }`}
                >
                  {count}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
