import { randomUUID } from 'crypto';

export class DecisionEngine {
  constructor(decisionConfig, teamConfig) {
    this.decisionConfig = decisionConfig;
    this.teamConfig = teamConfig;
  }

  async make({ pr, blastRadius, securityFindings, policyResults }) {
    const factors = [];
    let confidence = 0;

    // Factor 1: Security findings (highest weight)
    const securityFactor = this.evaluateSecurity(securityFindings);
    factors.push(securityFactor);
    confidence += securityFactor.score * 0.4;

    // Factor 2: Blast radius
    const blastFactor = this.evaluateBlastRadius(blastRadius);
    factors.push(blastFactor);
    confidence += blastFactor.score * 0.3;

    // Factor 3: Policy violations
    const policyFactor = this.evaluatePolicies(policyResults);
    factors.push(policyFactor);
    confidence += policyFactor.score * 0.3;

    // Determine action
    let action = this.determineAction(blastRadius, securityFindings, policyResults);

    // Check confidence threshold
    if (confidence < this.decisionConfig.minConfidence) {
      action = 'require_review';
    }

    // Generate recommendations
    const recommendations = this.generateRecommendations(
      action,
      securityFindings,
      policyResults
    );

    return {
      decisionId: randomUUID(),
      action,
      confidence: Math.min(1, Math.max(0, confidence)),
      reasoning: {
        summary: this.buildSummary(action, factors),
        factors
      },
      recommendations,
      nextSteps: this.generateNextSteps(action, securityFindings)
    };
  }

  evaluateSecurity(findings) {
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

  evaluateBlastRadius(blastRadius) {
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

  evaluatePolicies(results) {
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

  determineAction(blastRadius, securityFindings, policyResults) {
    const thresholds = this.teamConfig.thresholds;

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

  buildSummary(action, factors) {
    const actionText = {
      'auto_approve': 'Safe change - auto-approved',
      'auto_approve_comment': 'Safe change - auto-approved with comment',
      'require_review': 'Requires human review',
      'require_senior_review': 'Requires senior review',
      'block': 'Change blocked - review required'
    };

    return actionText[action];
  }

  generateRecommendations(action, securityFindings, policyResults) {
    const recommendations = [];

    if (securityFindings.length > 0) {
      recommendations.push('Review and fix security findings before merging');
    }

    if (policyResults.some(r => r.status === 'failed')) {
      recommendations.push('Address policy violations before merging');
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

  generateNextSteps(action, securityFindings) {
    const steps = [];

    if (securityFindings.length > 0) {
      const critical = securityFindings.filter(f => f.severity === 'critical');
      if (critical.length > 0) {
        steps.push('Immediately fix critical security vulnerabilities');
      }
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
