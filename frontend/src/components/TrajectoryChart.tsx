import React, { useState } from 'react';
import { TrajectoryEvent, RiskBandType } from '../types/tripwire';
import { TrendingUp, Info, ShieldAlert } from 'lucide-react';

interface Props {
  events: TrajectoryEvent[];
  currentScore: number;
  currentRiskBand: RiskBandType;
  selectedEvent?: TrajectoryEvent | null;
  onSelectEvent?: (event: TrajectoryEvent) => void;
}

export const TrajectoryChart: React.FC<Props> = ({
  events,
  currentScore,
  currentRiskBand,
  selectedEvent,
  onSelectEvent,
}) => {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const getRiskColor = (band: RiskBandType) => {
    switch (band) {
      case 'HIGH':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'MEDIUM':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'LOW':
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  const getScoreColor = (score: number) => {
    if (score > 0.65) return '#f43f5e';
    if (score >= 0.35) return '#fbbf24';
    return '#10b981';
  };

  // SVG dimensions
  const width = 640;
  const height = 180;
  const padding = 40;

  const points = events.map((e, idx) => {
    const x = padding + (idx / Math.max(1, events.length - 1)) * (width - 2 * padding);
    const y = height - padding - e.trajectory_score * (height - 2 * padding);
    return { x, y, score: e.trajectory_score, step: e.step, event: e };
  });

  const polylinePoints = points.map((p) => `${p.x},${p.y}`).join(' ');

  const activeEvent = selectedEvent || (hoveredIndex !== null ? events[hoveredIndex] : null);

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800">
        <div className="flex items-center space-x-2">
          <div className="p-1.5 bg-indigo-500/20 text-indigo-400 rounded-lg">
            <TrendingUp className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Behavioral Trajectory Monitor</h3>
            <p className="text-[11px] text-slate-400">Cross-session score progression &amp; asymmetric EMA decay</p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <div className="text-right">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Risk Score</span>
            <span className="text-lg font-mono font-bold" style={{ color: getScoreColor(currentScore) }}>
              {currentScore.toFixed(3)}
            </span>
          </div>
          <span className={`px-2.5 py-1 rounded-full text-xs font-semibold border ${getRiskColor(currentRiskBand)}`}>
            {currentRiskBand} RISK
          </span>
        </div>
      </div>

      {/* Threshold Bands */}
      <div className="grid grid-cols-3 gap-2 text-[11px] font-mono">
        <div className="p-2 rounded bg-emerald-950/30 border border-emerald-800/40 text-emerald-300 flex items-center justify-between">
          <span>LOW (&lt; 0.35)</span>
          <span className="text-[10px] text-emerald-400/70">ALLOW</span>
        </div>
        <div className="p-2 rounded bg-amber-950/30 border border-amber-800/40 text-amber-300 flex items-center justify-between">
          <span>MED (0.35 - 0.65)</span>
          <span className="text-[10px] text-amber-400/70">CONFIRM</span>
        </div>
        <div className="p-2 rounded bg-rose-950/30 border border-rose-800/40 text-rose-300 flex items-center justify-between">
          <span>HIGH (&gt; 0.65)</span>
          <span className="text-[10px] text-rose-400/70">BLOCK</span>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="bg-slate-950/90 rounded-xl p-3 border border-slate-800/80 relative">
        {events.length === 0 ? (
          <div className="h-44 flex flex-col items-center justify-center text-slate-500 text-xs">
            <TrendingUp className="w-8 h-8 mb-2 animate-pulse text-slate-600" />
            <span>No trajectory data yet. Run a scenario to observe live EMA scoring curve.</span>
          </div>
        ) : (
          <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-44 select-none">
            {/* 0.65 HIGH line */}
            <line
              x1={padding}
              y1={height - padding - 0.65 * (height - 2 * padding)}
              x2={width - padding}
              y2={height - padding - 0.65 * (height - 2 * padding)}
              stroke="#e11d48"
              strokeDasharray="4 4"
              strokeWidth="1"
              opacity="0.6"
            />
            <text
              x={width - padding - 50}
              y={height - padding - 0.65 * (height - 2 * padding) - 4}
              fill="#f43f5e"
              fontSize="9"
              fontFamily="monospace"
            >
              HIGH: 0.65
            </text>

            {/* 0.35 MEDIUM line */}
            <line
              x1={padding}
              y1={height - padding - 0.35 * (height - 2 * padding)}
              x2={width - padding}
              y2={height - padding - 0.35 * (height - 2 * padding)}
              stroke="#d97706"
              strokeDasharray="4 4"
              strokeWidth="1"
              opacity="0.6"
            />
            <text
              x={width - padding - 50}
              y={height - padding - 0.35 * (height - 2 * padding) - 4}
              fill="#fbbf24"
              fontSize="9"
              fontFamily="monospace"
            >
              MED: 0.35
            </text>

            {/* Trajectory Polyline */}
            {points.length > 1 && (
              <polyline
                fill="none"
                stroke="#6366f1"
                strokeWidth="2.5"
                points={polylinePoints}
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            )}

            {/* Nodes */}
            {points.map((p, i) => (
              <g
                key={i}
                className="cursor-pointer transition-transform duration-100"
                onMouseEnter={() => setHoveredIndex(i)}
                onMouseLeave={() => setHoveredIndex(null)}
                onClick={() => onSelectEvent && onSelectEvent(p.event)}
              >
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={hoveredIndex === i ? '7' : '5'}
                  fill={getScoreColor(p.score)}
                  stroke="#0f172a"
                  strokeWidth="2"
                />
                <text
                  x={p.x}
                  y={p.y - 12}
                  fill="#cbd5e1"
                  fontSize="9"
                  fontFamily="monospace"
                  textAnchor="middle"
                >
                  {p.score.toFixed(2)}
                </text>
                <text
                  x={p.x}
                  y={height - 10}
                  fill="#64748b"
                  fontSize="9"
                  fontFamily="monospace"
                  textAnchor="middle"
                >
                  Step {p.step}
                </text>
              </g>
            ))}
          </svg>
        )}
      </div>

      {/* Selected Step Signal Inspector */}
      {activeEvent && (
        <div className="bg-slate-950/80 rounded-lg p-3 border border-indigo-900/40 text-xs space-y-1.5">
          <div className="flex justify-between items-center">
            <span className="font-semibold text-indigo-300">
              Step #{activeEvent.step}: {activeEvent.action}
            </span>
            <span className="font-mono text-slate-400">Score: {activeEvent.trajectory_score.toFixed(3)}</span>
          </div>
          <p className="text-[11px] text-slate-300">{activeEvent.reason}</p>
        </div>
      )}
    </div>
  );
};
