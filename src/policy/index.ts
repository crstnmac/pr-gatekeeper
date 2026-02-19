import type {
  PoliciesConfig,
  PullRequest,
  BlastRadiusResult,
  SecurityFinding,
  PolicyResult,
  PolicyStatus,
  PolicyValidation,
  Severity,
  PolicyAction
} from '../types.js';

interface PolicyRule {
  ruleId: string;
  name: string;
  category: string;
  conditions?: {
    targetBranch?: string | string[];
  };
  validations: PolicyValidationConfig[];
}

interface PolicyValidationConfig {
  type: string;
  action?: PolicyAction;
  maxScore?: number;
  block?: boolean;
  paths?: string[];
  maxFiles?: number;
}

export class PolicyEvaluator {
  private config: PoliciesConfig;
  private rules: PolicyRule[];

  constructor(config: PoliciesConfig) {
    this.config = config;
    this.rules = this.initRules();
  }

  async evaluate(
    pr: PullRequest,
    context: {
      blastRadius: BlastRadiusResult;
      securityFindings: SecurityFinding[];
    }
  ): Promise<PolicyResult[]> {
    if (!this.config.enabled) {
      return [];
    }

    const results: PolicyResult[] = [];

    for (const rule of this.rules) {
      const result = await this.evaluateRule(rule, pr, context);
      results.push(result);
    }

    return results;
  }

  private async evaluateRule(
    rule: PolicyRule,
    pr: PullRequest,
    context: {
      blastRadius: BlastRadiusResult;
      securityFindings: SecurityFinding[];
    }
  ): Promise<PolicyResult> {
    // Check if rule applies
    if (!this.ruleApplies(rule, pr)) {
      return {
        ruleId: rule.ruleId,
        name: rule.name,
        status: 'skipped',
        reason: 'Rule conditions not met',
        validations: [],
        message: ''
      };
    }

    // Run validations
    const validations: PolicyValidation[] = [];
    for (const validation of rule.validations) {
      const result = await this.runValidation(validation, pr, context);
      validations.push(result);
    }

    // Determine overall result
    const failed = validations.filter(v => v.status === 'failed');
    const blocked = failed.some(v => v.action === 'block');

    const status: PolicyStatus = blocked ? 'failed' : failed.length > 0 ? 'warning' : 'passed';
    const action: PolicyAction = blocked ? 'block' : status === 'warning' ? 'warn' : null;

    return {
      ruleId: rule.ruleId,
      name: rule.name,
      status,
      action,
      validations,
      message: this.buildRuleMessage(rule, status)
    };
  }

  private ruleApplies(rule: PolicyRule, pr: PullRequest): boolean {
    if (!rule.conditions) return true;

    // Check target branch
    if (rule.conditions.targetBranch) {
      const targets = Array.isArray(rule.conditions.targetBranch)
        ? rule.conditions.targetBranch
        : [rule.conditions.targetBranch];
      if (!targets.includes(pr.targetBranch)) {
        return false;
      }
    }

    return true;
  }

  private async runValidation(
    validation: PolicyValidationConfig,
    pr: PullRequest,
    context: {
      blastRadius: BlastRadiusResult;
      securityFindings: SecurityFinding[];
    }
  ): Promise<PolicyValidation> {
    switch (validation.type) {
      case 'blast_radius':
        return this.validateBlastRadius(validation, context.blastRadius);
      case 'security':
        return this.validateSecurity(validation, context.securityFindings);
      case 'blocked_path':
        return this.validateBlockedPath(validation, pr);
      case 'file_count':
        return this.validateFileCount(validation, pr);
      case 'jira_ticket':
        return this.validateJiraTicket(validation, pr);
      case 'changelog':
        return this.validateChangelog(validation, pr);
      default:
        return {
          type: validation.type,
          status: 'skipped',
          reason: 'Unknown validation type'
        };
    }
  }

  private validateBlastRadius(
    validation: PolicyValidationConfig,
    blastRadius: BlastRadiusResult
  ): PolicyValidation {
    const threshold = validation.maxScore || 60;

    if (blastRadius.score > threshold) {
      return {
        type: 'blast_radius',
        status: 'failed',
        action: validation.action || 'warn',
        message: `Blast radius score ${blastRadius.score} exceeds threshold ${threshold}`
      };
    }

    return {
      type: 'blast_radius',
      status: 'passed',
      action: undefined
    };
  }

  private validateSecurity(
    validation: PolicyValidationConfig,
    findings: SecurityFinding[]
  ): PolicyValidation {
    const severityThreshold: Severity = validation.block === true ? 'critical' : 'medium';
    const severityOrder: Severity[] = ['low', 'medium', 'high', 'critical'];
    const thresholdIndex = severityOrder.indexOf(severityThreshold);

    const severeFindings = findings.filter(f =>
      severityOrder.indexOf(f.severity) >= thresholdIndex
    );

    if (severeFindings.length > 0) {
      return {
        type: 'security',
        status: 'failed',
        action: validation.block === true ? 'block' : 'warn',
        message: `Found ${severeFindings.length} ${severityThreshold}+ severity security issues`
      };
    }

    return {
      type: 'security',
      status: 'passed',
      action: undefined
    };
  }

  private validateBlockedPath(
    validation: PolicyValidationConfig,
    pr: PullRequest
  ): PolicyValidation {
    const blockedPaths = validation.paths || [];

    for (const file of pr.files) {
      for (const pattern of blockedPaths) {
        if (this.matchPattern(file.filename, pattern)) {
          return {
            type: 'blocked_path',
            status: 'failed',
            action: 'block',
            message: `File ${file.filename} matches blocked pattern ${pattern}`
          };
        }
      }
    }

    return {
      type: 'blocked_path',
      status: 'passed',
      action: undefined
    };
  }

  private validateFileCount(
    validation: PolicyValidationConfig,
    pr: PullRequest
  ): PolicyValidation {
    const maxFiles = validation.maxFiles || 50;

    if (pr.files.length > maxFiles) {
      return {
        type: 'file_count',
        status: 'failed',
        action: 'warn',
        message: `${pr.files.length} files changed exceeds threshold ${maxFiles}`
      };
    }

    return {
      type: 'file_count',
      status: 'passed',
      action: undefined
    };
  }

  private validateJiraTicket(validation: PolicyValidationConfig, pr: PullRequest): PolicyValidation {
    // Check if PR body contains Jira ticket reference
    const body = (pr.body || '').toLowerCase();

    // Jira ticket patterns: PROJ-123, [PROJ-123], (PROJ-123)
    const jiraPatterns = [
      /\b[a-z]+-\d+\b/i,           // PROJ-123
      /\[[a-z]+-\d+\]/i,        // [PROJ-123]
      /\([a-z]+-\d+\)/i         // (PROJ-123)
    ];

    const hasTicket = jiraPatterns.some(pattern => pattern.test(body));

    if (!hasTicket) {
      return {
        type: 'jira_ticket',
        status: 'failed',
        action: validation.action || 'block',
        message: 'PR description must include a Jira ticket reference (e.g., PROJ-123)'
      };
    }

    return {
      type: 'jira_ticket',
      status: 'passed',
      action: undefined
    };
  }

  private validateChangelog(validation: PolicyValidationConfig, pr: PullRequest): PolicyValidation {
    const body = pr.body || '';

    // Look for changelog indicators
    const changelogIndicators = [
      /##\s*changelog/i,
      /###\s*changelog/i,
      /changelog:\s*/i,
      /changes:\s*/i,
      /what's new:/i,
      /what changed:/i
    ];

    const hasChangelog = changelogIndicators.some(pattern => pattern.test(body));

    if (!hasChangelog) {
      return {
        type: 'changelog',
        status: 'failed',
        action: validation.action || 'block',
        message: 'PR description must include a changelog section'
      };
    }

    return {
      type: 'changelog',
      status: 'passed',
      action: undefined
    };
  }

  private buildRuleMessage(rule: PolicyRule, status: PolicyStatus): string {
    if (status === 'passed') {
      return `✅ ${rule.name}: passed`;
    } else if (status === 'warning') {
      return `⚠️  ${rule.name}: warning`;
    } else {
      return `🚫 ${rule.name}: blocked`;
    }
  }

  private initRules(): PolicyRule[] {
    const rules: PolicyRule[] = [];

    // SOC 2: No Secrets
    if (this.config.frameworks.includes('SOC2')) {
      rules.push({
        ruleId: 'soc2-no-secrets',
        name: 'SOC 2: No Hardcoded Secrets',
        category: 'security',
        conditions: { targetBranch: ['main', 'production', 'master'] },
        validations: [
          {
            type: 'security',
            block: true
          }
        ]
      });
    }

    // SOC 2: Blast Radius Check
    if (this.config.frameworks.includes('SOC2')) {
      rules.push({
        ruleId: 'soc2-blast-radius',
        name: 'SOC 2: Blast Radius Check',
        category: 'workflow',
        conditions: { targetBranch: ['main', 'production', 'master'] },
        validations: [
          {
            type: 'blast_radius',
            maxScore: 80,
            action: 'warn'
          }
        ]
      });
    }

    // Branch Protection
    rules.push({
      ruleId: 'branch-protection',
      name: 'Branch Protection',
      category: 'workflow',
      conditions: { targetBranch: ['main', 'production', 'master'] },
      validations: [
        {
          type: 'file_count',
          maxFiles: 100,
          action: 'warn'
        }
      ]
    });

    // Jira Ticket Requirement
    if (this.config.requireJiraTicket) {
      rules.push({
        ruleId: 'jira-ticket-required',
        name: 'Jira Ticket Required',
        category: 'workflow',
        conditions: { targetBranch: ['main', 'production', 'master'] },
        validations: [
          {
            type: 'jira_ticket',
            action: 'block'
          }
        ]
      });
    }

    // Changelog Requirement
    if (this.config.requireChangelog) {
      rules.push({
        ruleId: 'changelog-required',
        name: 'Changelog Required',
        category: 'documentation',
        conditions: { targetBranch: ['main', 'production', 'master'] },
        validations: [
          {
            type: 'changelog',
            action: 'block'
          }
        ]
      });
    }

    return rules;
  }

  private matchPattern(filename: string, pattern: string): boolean {
    const regexPattern = pattern
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '.');

    const regex = new RegExp(regexPattern);
    return regex.test(filename);
  }
}
