/**
 * TRIPWIRE — Shared Contract Types
 * Person B: Type definitions adhering to TRIPWIRE_PRE_IMPLEMENTATION_CONTRACT_PACK.md
 */

export type DecisionType = 'ALLOW' | 'CONFIRM' | 'HARD_CONFIRM' | 'BLOCK';
export type RiskBandType = 'LOW' | 'MEDIUM' | 'HIGH';
export type ReversibilityType = 'READ' | 'WRITE' | 'DESTRUCTIVE';

export interface ActionProposal {
  principal_id: string;
  session_id: string;
  agent_id: string;
  action: string;
  resource: string;
  parameters?: Record<string, any>;
}

export interface ActionDecision {
  action_id: string;
  decision: DecisionType;
  trajectory_score: number;
  risk_band: RiskBandType;
  reversibility: ReversibilityType;
  reason: string;
}

export interface TrajectoryEvent {
  step: number;
  action: string;
  resource: string;
  reversibility: ReversibilityType;
  trajectory_score: number;
  risk_band: RiskBandType;
  decision: DecisionType;
  step_score?: number;
  reason?: string;
  timestamp?: string;
}

export interface SessionTrajectory {
  session_id: string;
  principal_id: string;
  trajectory_score: number;
  risk_band: RiskBandType;
  events: TrajectoryEvent[];
}

export interface AuditEvent {
  action_id: string;
  principal_id: string;
  session_id: string;
  agent_id: string;
  action: string;
  resource: string;
  reversibility: ReversibilityType;
  trajectory_score: number;
  risk_band: RiskBandType;
  decision: DecisionType;
  reason: string;
  timestamp: string;
  parameters?: Record<string, any>;
  execution_status?: 'EXECUTED' | 'NOT_EXECUTED' | 'PENDING_APPROVAL';
  approved_by?: string;
  executed_at?: string;
}

export interface ScenarioStep {
  step: number;
  action: string;
  resource: string;
  parameters: Record<string, any>;
  expected_reversibility: ReversibilityType;
  description: string;
}

export interface Scenario {
  scenario_name: string;
  description: string;
  principal_id: string;
  agent_id: string;
  steps: ScenarioStep[];
}
