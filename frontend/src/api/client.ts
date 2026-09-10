/**
 * TRIPWIRE — API Client
 * Connects frontend to Tripwire Backend (FastAPI on http://localhost:8000/api/v1)
 */

import {
  ActionProposal,
  ActionDecision,
  SessionTrajectory,
  AuditEvent,
  DecisionType,
  RiskBandType,
  ReversibilityType,
} from '../types/tripwire';

const API_BASE = 'http://localhost:8000/api/v1';
const HEALTH_URL = 'http://localhost:8000/health';

export class TripwireClient {
  private baseUrl: string;
  private healthUrl: string;

  constructor(baseUrl: string = API_BASE, healthUrl: string = HEALTH_URL) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.healthUrl = healthUrl.replace(/\/$/, '');
  }

  /**
   * Health Check — Queries authoritative backend health endpoint (/health)
   */
  async checkHealth(): Promise<{ status: string; backendOnline: boolean }> {
    try {
      const res = await fetch(this.healthUrl, { signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        return { status: 'ONLINE', backendOnline: true };
      }
      return { status: 'OFFLINE', backendOnline: false };
    } catch {
      return { status: 'OFFLINE', backendOnline: false };
    }
  }

  /**
   * POST /api/v1/sessions
   */
  async createSession(
    principalId: string,
    agentId: string
  ): Promise<{
    session_id: string;
    principal_id: string;
    agent_id: string;
    trajectory_score: number;
    risk_band: RiskBandType;
  }> {
    try {
      const res = await fetch(`${this.baseUrl}/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ principal_id: principalId, agent_id: agentId }),
      });
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {
      console.warn('Backend unavailable, using client-side fallback session', e);
    }

    // Contract-compliant local fallback
    return {
      session_id: `session_${Date.now().toString().slice(-4)}`,
      principal_id: principalId,
      agent_id: agentId,
      trajectory_score: 0.0,
      risk_band: 'LOW',
    };
  }

  /**
   * POST /api/v1/actions/propose
   */
  async proposeAction(proposal: ActionProposal): Promise<ActionDecision> {
    try {
      const res = await fetch(`${this.baseUrl}/actions/propose`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(proposal),
      });
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {
      console.warn('Backend unavailable, evaluating with contract simulation rules', e);
    }

    // Fallback contract simulation engine
    return this.simulateProposal(proposal);
  }

  /**
   * POST /api/v1/actions/{action_id}/confirm
   * Human approval execution endpoint — called ONLY on human APPROVE.
   */
  async confirmAction(
    actionId: string,
    approvedBy: string = 'admin_001'
  ): Promise<{
    action_id: string;
    decision: DecisionType;
    approved_by: string;
    execution_status: 'EXECUTED' | 'NOT_EXECUTED';
  }> {
    try {
      const res = await fetch(`${this.baseUrl}/actions/${actionId}/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved_by: approvedBy }),
      });
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {
      console.warn('Backend unavailable, simulating confirmation', e);
    }

    return {
      action_id: actionId,
      decision: 'ALLOW',
      approved_by: approvedBy,
      execution_status: 'EXECUTED',
    };
  }

  /**
   * GET /api/v1/sessions/{session_id}/trajectory
   */
  async getTrajectory(sessionId: string): Promise<SessionTrajectory | null> {
    try {
      const res = await fetch(`${this.baseUrl}/sessions/${sessionId}/trajectory`);
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {
      console.warn('Backend trajectory fetch error', e);
    }
    return null;
  }

  /**
   * GET /api/v1/audit/{session_id}
   */
  async getAudit(sessionId: string): Promise<{ session_id: string; events: AuditEvent[] } | null> {
    try {
      const res = await fetch(`${this.baseUrl}/audit/${sessionId}`);
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {
      console.warn('Backend audit fetch error', e);
    }
    return null;
  }

  /**
   * Contract-accurate local simulator adhering to Frozen Decision Matrix and EMA formula
   */
  private static simScore: number = 0.0;
  private static seenResources: Set<string> = new Set();
  private static actionCount: number = 0;

  static resetSimState(initialScore: number = 0.0) {
    TripwireClient.simScore = initialScore;
    TripwireClient.seenResources.clear();
    TripwireClient.actionCount = 0;
  }

  private simulateProposal(proposal: ActionProposal): ActionDecision {
    const action = proposal.action;
    TripwireClient.actionCount += 1;
    TripwireClient.seenResources.add(proposal.resource);

    // 1. Classification
    let reversibility: ReversibilityType = 'READ';
    let destLevel = 0;
    if (['change_permissions', 'drop_table'].includes(action)) {
      reversibility = 'DESTRUCTIVE';
      destLevel = 2;
    } else if (['update_customer', 'export_customers'].includes(action)) {
      reversibility = 'WRITE';
      destLevel = 1;
    }

    // 2. Trajectory Formula from Contract Section 14
    // step_score = 0.30*scope_drift + 0.35*destructiveness_growth + 0.15*velocity + 0.20*footprint_breadth
    const scopeDrift = reversibility === 'DESTRUCTIVE' ? 1.0 : reversibility === 'WRITE' ? 0.5 : 0.0;
    const destGrowth = destLevel / 2.0;
    const velocity = Math.min(1.0, TripwireClient.actionCount / 6.0);
    const footprintBreadth = Math.min(1.0, TripwireClient.seenResources.size / 3.0);

    const stepScore =
      0.3 * scopeDrift +
      0.35 * destGrowth +
      0.15 * velocity +
      0.2 * footprintBreadth;

    // Asymmetric EMA (Section 15)
    let newScore: number;
    if (stepScore >= TripwireClient.simScore) {
      newScore = TripwireClient.simScore + 0.6 * (stepScore - TripwireClient.simScore);
    } else {
      newScore = TripwireClient.simScore + 0.2 * (stepScore - TripwireClient.simScore);
    }
    TripwireClient.simScore = Math.min(1.0, Math.max(0.0, newScore));

    // Risk Band (Section 16)
    let riskBand: RiskBandType = 'LOW';
    if (TripwireClient.simScore > 0.65) {
      riskBand = 'HIGH';
    } else if (TripwireClient.simScore >= 0.35) {
      riskBand = 'MEDIUM';
    }

    // Decision Matrix (Section 9)
    let decision: DecisionType = 'ALLOW';
    let reason = 'Authorized within current trajectory boundaries';

    if (riskBand === 'HIGH') {
      decision = 'BLOCK';
      reason = 'Behavioral trajectory exceeds high-risk threshold (score > 0.65)';
    } else if (riskBand === 'MEDIUM') {
      if (reversibility === 'DESTRUCTIVE') {
        decision = 'HARD_CONFIRM';
        reason = 'High-impact destructive action in elevated risk context requires human confirmation';
      } else if (reversibility === 'WRITE') {
        decision = 'CONFIRM';
        reason = 'State modification in medium-risk trajectory requires confirmation';
      } else {
        decision = 'ALLOW';
        reason = 'Read operation permitted in medium-risk band';
      }
    } else {
      // LOW
      if (reversibility === 'DESTRUCTIVE') {
        decision = 'CONFIRM';
        reason = 'Destructive action requires explicit human sign-off';
      } else {
        decision = 'ALLOW';
        reason = 'Standard authorized operation within normal baseline';
      }
    }

    return {
      action_id: `act_${Date.now().toString().slice(-6)}`,
      decision,
      trajectory_score: Number(TripwireClient.simScore.toFixed(3)),
      risk_band: riskBand,
      reversibility,
      reason,
    };
  }
}

export const defaultTripwireClient = new TripwireClient();
