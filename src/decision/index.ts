import { randomUUID } from 'crypto';
import type {
  DecisionConfig,
  TeamConfig,
  BlastRadiusResult,
  SecurityFinding,
  PolicyResult,
  Decision,
  DecisionFactor,
  DecisionAction,
  TeamThresholds
} from '../types.js';

export class DecisionEngine {
  private decisionConfig: DecisionConfig;
  private teamConfig: TeamConfig;

  constructor(decisionConfig: DecisionConfig, teamConfig: TeamConfig) {
    this.decisionConfig = decisionConfig;
    this.teamConfig = teamConfig;
  }

  async make({
    blastRadius,
    securityFindings,
    policyResults,
    approvals,
    ciStatus
  }: {
    blastRadius: BlastRadiusResult;
    securityFindings: SecurityFinding[];
    policyResults: PolicyResult[];
    approvals?: Array<{ user: string; submittedAt: string; id: number }>;
    ciStatus?: { state: string; totalCount: number; statuses: Array<{ context: string; state: string; description: string | null }> };
  }): Promise<Decision> {
    const factors: DecisionFactor[] = [];
    let confidence = 0;

    // Factor 1: Security findings (highest weight)
    const securityFactor = this.evaluateSecurity(securityFindings);
    factors.push(securityFactor);
    confidence += securityFactor.score * 0.35;

    // Factor 2: Blast radius
    const blastFactor = this.evaluateBlastRadius(blastRadius);
    factors.push(blastFactor);
    confidence += blastFactor.score * 0.25;

    // Factor 3: Policy violations
    const policyFactor = this.evaluatePolicies(policyResults);
    factors.push(policyFactor);
    confidence += policyFactor.score * 0.25;

    // Factor 4: Approvals (if available)
    if (approvals) {
      const approvalFactor = this.evaluateApprovals(approvals);
      factors.push(approvalFactor);
      confidence += approvalFactor.score * 0.1;
    }

    // Factor 5: CI status (if available)
    if (ciStatus) {
      const ciFactor = this.evaluateCIStatus(ciStatus);
      factors.push(ciFactor);
      confidence += ciFactor.score * 0.05;
    }

    // Determine action
    let action = this.determineAction(blastRadius, securityFindings, policyResults, ciStatus);

    // Check confidence threshold
    if (confidence < this.decisionConfig.minConfidence) {
      action = 'require_review';
    }

    // Generate recommendations
    const recommendations = this.generateRecommendations(action, securityFindings, policyResults, ciStatus);

    return {
      decisionId: randomUUID(),
      action,
      confidence: Math.min(1, Math.max(0, confidence)),
      reasoning: {
        summary: this.buildSummary(action),
        factors
      },
      recommendations,
      nextSteps: this.generateNextSteps(action, securityFindings, ciStatus)
    };
  }

  private evaluateSecurity(findings: SecurityFinding[]): DecisionFactor {
    if (findings.length === 0) {
      return {
        factor: 'security_findings',
        impact: 'none',
        score: 1.0,
        details: 'No security findings'
      };
    }

    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;

    if (critical > 0) {
      return {
        factor: 'security_findings',
        impact: 'critical',
        score: 0.0,
        details: `${critical} critical security finding(s)`
      };
    }

    if (high > 0) {
      return {
        factor: 'security_findings',
        impact: 'high',
        score: 0.2,
        details: `${high} high severity security finding(s)`
      };
    }

    return {
      factor: 'security_findings',
      impact: 'medium',
      score: 0.6,
      details: `${findings.length} security finding(s) of lower severity`
    };
  }

  private evaluateBlastRadius(blastRadius: BlastRadiusResult): DecisionFactor {
    const score = blastRadius.score;

    if (score <= 20) {
      return {
        factor: 'blast_radius',
        impact: 'low',
        score: 1.0,
        details: `Blast radius ${score}: minimal impact`
      };
    } else if (score <= 40) {
      return {
        factor: 'blast_radius',
        impact: 'low-medium',
        score: 0.8,
        details: `Blast radius ${score}: low to medium impact`
      };
    } else if (score <= 60) {
      return {
        factor: 'blast_radius',
        impact: 'medium',
        score: 0.6,
        details: `Blast radius ${score}: medium impact`
      };
    } else if (score <= 80) {
      return {
        factor: 'blast_radius',
        impact: 'medium-high',
        score: 0.4,
        details: `Blast radius ${score}: medium to high impact`
      };
    } else {
      return {
        factor: 'blast_radius',
        impact: 'high',
        score: 0.2,
        details: `Blast radius ${score}: high impact`
      };
    }
  }

  private evaluatePolicies(results: PolicyResult[]): DecisionFactor {
    const passed = results.filter(r => r.status === 'passed').length;
    const failed = results.filter(r => r.status === 'failed').length;
    const warning = results.filter(r => r.status === 'warning').length;
    const total = results.length;

    if (total === 0) {
      return {
        factor: 'policy_compliance',
        impact: 'none',
        score: 0.8,
        details: 'No policies applicable'
      };
    }

    const passRate = passed / total;

    if (failed > 0) {
      return {
        factor: 'policy_compliance',
        impact: 'critical',
        score: 0.0,
        details: `${failed} policy violation(s) detected`
      };
    }

    if (warning > 0) {
      return {
        factor: 'policy_compliance',
        impact: 'medium',
        score: 0.7,
        details: `${warning} policy warning(s)`
      };
    }

    return {
      factor: 'policy_compliance',
        impact: 'none',
        score: 1.0,
        details: `All ${total} policies passed (${(passRate * 100).toFixed(0)}%)`
      };
  }

  private evaluateApprovals(approvals: Array<{ user: string; submittedAt: string; id: number }>): DecisionFactor {
    const count = approvals.length;

    if (count === 0) {
      return {
        factor: 'approvals',
        impact: 'none',
        score: 0.5,
        details: 'No approvals yet'
      };
    }

    if (count >= 2) {
      return {
        factor: 'approvals',
        impact: 'none',
        score: 1.0,
        details: `${count} approval(s) from team members`
      };
    }

    return {
      factor: 'approvals',
      impact: 'low',
      score: 0.7,
      details: `${count} approval(s)`
    };
  }

  private evaluateCIStatus(ciStatus: { state: string; totalCount: number; statuses: Array<{ context: string; state: string }> }): DecisionFactor {
    const state = ciStatus.state.toLowerCase();

    if (state === 'success') {
      return {
        factor: 'ci_status',
        impact: 'none',
        score: 1.0,
        details: 'All CI checks passed'
      };
    }

    if (state === 'pending') {
      return {
        factor: 'ci_status',
        impact: 'medium',
        score: 0.5,
        details: 'CI checks in progress'
      };
    }

    if (state === 'failure') {
      const failedCount = ciStatus.statuses.filter(s => s.state === 'failure' || s.state === 'error').length;
      return {
        factor: 'ci_status',
        impact: 'high',
        score: 0.0,
        details: `${failedCount} CI check(s) failed`
      };
    }

    return {
      factor: 'ci_status',
      impact: 'low',
      score: 0.6,
      details: `CI status: ${state}`
    };
  }

  private determineAction(
    blastRadius: BlastRadiusResult,
    securityFindings: SecurityFinding[],
    policyResults: PolicyResult[],
    ciStatus?: { state: string; totalCount: number; statuses: Array<{ context: string; state: string }> }
  ): DecisionAction {
    const thresholds = this.teamConfig.thresholds as TeamThresholds;

    // Check for critical security issues - always block
    const criticalSec = securityFindings.filter(f => f.severity === 'critical').length;
    if (criticalSec > 0) {
      return 'block';
    }

    // Check for blocked policies
    const blockedPolicies = policyResults.filter(r => r.action === 'block').length;
    if (blockedPolicies > 0) {
      return 'block';
    }

    // Check CI status - block if failed
    if (ciStatus && (ciStatus.state === 'failure' || ciStatus.state === 'error')) {
      return 'block';
    }

    // Use blast radius thresholds
    const score = blastRadius.score;

    if (score <= thresholds.autoApprove) {
      return 'auto_approve';
    } else if (score <= thresholds.autoApproveWithComment) {
      return 'auto_approve_comment';
    } else if (score <= thresholds.requiresReview) {
      return 'require_review';
    } else if (score <= thresholds.requiresSeniorReview) {
      return 'require_senior_review';
    } else {
      return 'block';
    }
  }

  private buildSummary(action: DecisionAction): string {
    const actionText: Record<DecisionAction, string> = {
      auto_approve: 'Safe change - auto-approved',
      auto_approve_comment: 'Safe change - auto-approved with comment',
      require_review: 'Requires human review',
      require_senior_review: 'Requires senior review',
      block: 'Change blocked - review required'
    };

    return actionText[action];
  }

  private generateRecommendations(
    action: DecisionAction,
    securityFindings: SecurityFinding[],
    policyResults: PolicyResult[],
    ciStatus?: { state: string; totalCount: number; statuses: Array<{ context: string; state: string }> }
  ): string[] {
    const recommendations: string[] = [];

    if (securityFindings.length > 0) {
      recommendations.push('Review and fix security findings before merging');
    }

    if (policyResults.some(r => r.status === 'failed')) {
      recommendations.push('Address policy violations before merging');
    }

    if (ciStatus && ciStatus.state === 'failure') {
      recommendations.push('Fix failing CI checks before merging');
    }

    if (ciStatus && ciStatus.state === 'pending') {
      recommendations.push('Wait for CI checks to complete');
    }

    if (action === 'auto_approve') {
      recommendations.push('Consider running tests manually for extra confidence');
    }

    if (action === 'require_review') {
      recommendations.push('Request review from at least one team member');
    }

    if (action === 'require_senior_review') {
      recommendations.push('Request review from senior engineer or tech lead');
    }

    if (action === 'block') {
      recommendations.push('Address all blocking issues before attempting merge');
    }

    return recommendations;
  }

  private generateNextSteps(action: DecisionAction, securityFindings: SecurityFinding[], ciStatus?: { state: string }): string[] {
    const steps: string[] = [];

    if (securityFindings.length > 0) {
      const critical = securityFindings.filter(f => f.severity === 'critical');
      if (critical.length > 0) {
        steps.push('Immediately fix critical security vulnerabilities');
      }
    }

    if (ciStatus && ciStatus.state === 'failure') {
      steps.push('Fix failing CI checks');
    }

    if (ciStatus && ciStatus.state === 'pending') {
      steps.push('Wait for CI checks to complete');
    }

    if (action === 'block') {
      steps.push('Re-run analysis after fixes');
    }

    if (action === 'require_review' || action === 'require_senior_review') {
      steps.push('Update PR description with changes made');
      steps.push('Request review from appropriate team members');
    }

    if (action === 'auto_approve' || action === 'auto_approve_comment') {
      steps.push('Monitor CI checks for any failures');
    }

    return steps;
  }
}
