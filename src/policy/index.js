export class PolicyEvaluator {
  constructor(config) {
    this.config = config;
    this.rules = this.initRules();
  }

  async evaluate(pr, context) {
    if (!this.config.enabled) {
      return [];
    }

    const results = [];

    for (const rule of this.rules) {
      const result = await this.evaluateRule(rule, pr, context);
      results.push(result);
    }

    return results;
  }

  async evaluateRule(rule, pr, context) {
    // Check if rule applies
    if (!this.ruleApplies(rule, pr)) {
      return {
        ruleId: rule.ruleId,
        name: rule.name,
        status: 'skipped',
        reason: 'Rule conditions not met'
      };
    }

    // Run validations
    const validations = [];
    for (const validation of rule.validations) {
      const result = await this.runValidation(validation, pr, context);
      validations.push(result);
    }

    // Determine overall result
    const failed = validations.filter(v => v.status === 'failed');
    const blocked = failed.some(v => v.severity === 'block');

    const status = blocked ? 'failed' : failed.length > 0 ? 'warning' : 'passed';
    const action = blocked ? 'block' : status === 'warning' ? 'warn' : null;

    return {
      ruleId: rule.ruleId,
      name: rule.name,
      status,
      action,
      validations,
      message: this.buildRuleMessage(rule, status)
    };
  }

  ruleApplies(rule, pr) {
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

  async runValidation(validation, pr, context) {
    switch (validation.type) {
      case 'blast_radius':
        return this.validateBlastRadius(validation, context.blastRadius);
      case 'security':
        return this.validateSecurity(validation, context.securityFindings);
      case 'blocked_path':
        return this.validateBlockedPath(validation, pr);
      case 'file_count':
        return this.validateFileCount(validation, pr);
      default:
        return {
          type: validation.type,
          status: 'skipped',
          reason: 'Unknown validation type'
        };
    }
  }

  validateBlastRadius(validation, blastRadius) {
    const threshold = validation.maxScore || 60;

    if (blastRadius.score > threshold) {
      return {
        type: 'blast_radius',
        status: 'failed',
        severity: validation.severity || 'warn',
        message: `Blast radius score ${blastRadius.score} exceeds threshold ${threshold}`
      };
    }

    return {
      type: 'blast_radius',
      status: 'passed'
    };
  }

  validateSecurity(validation, findings) {
    const severityThreshold = validation.severity || 'medium';
    const severityOrder = ['low', 'medium', 'high', 'critical'];
    const thresholdIndex = severityOrder.indexOf(severityThreshold);

    const severeFindings = findings.filter(f =>
      severityOrder.indexOf(f.severity) >= thresholdIndex
    );

    if (severeFindings.length > 0) {
      return {
        type: 'security',
        status: 'failed',
        severity: validation.block ? 'block' : 'warn',
        message: `Found ${severeFindings.length} ${severityThreshold}+ severity security issues`
      };
    }

    return {
      type: 'security',
      status: 'passed'
    };
  }

  validateBlockedPath(validation, pr) {
    const blockedPaths = validation.paths || [];

    for (const file of pr.files) {
      for (const pattern of blockedPaths) {
        if (this.matchPattern(file.filename, pattern)) {
          return {
            type: 'blocked_path',
            status: 'failed',
            severity: 'block',
            message: `File ${file.filename} matches blocked pattern ${pattern}`
          };
        }
      }
    }

    return {
      type: 'blocked_path',
      status: 'passed'
    };
  }

  validateFileCount(validation, pr) {
    const maxFiles = validation.maxFiles || 50;

    if (pr.files.length > maxFiles) {
      return {
        type: 'file_count',
        status: 'failed',
        severity: 'warn',
        message: `${pr.files.length} files changed exceeds threshold ${maxFiles}`
      };
    }

    return {
      type: 'file_count',
      status: 'passed'
    };
  }

  buildRuleMessage(rule, status) {
    if (status === 'passed') {
      return `✅ ${rule.name}: passed`;
    } else if (status === 'warning') {
      return `⚠️  ${rule.name}: warning`;
    } else {
      return `🚫 ${rule.name}: blocked`;
    }
  }

  initRules() {
    const rules = [];

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
            severity: 'critical',
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
            severity: 'warn'
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
          severity: 'warn'
        }
      ]
    });

    return rules;
  }

  matchPattern(filename, pattern) {
    const regexPattern = pattern
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '.');

    const regex = new RegExp(regexPattern);
    return regex.test(filename);
  }
}
