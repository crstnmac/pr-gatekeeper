import { GitHubClient } from '../github/index.js';
import { BlastRadiusCalculator } from '../blast-radius/index.js';
import { SecurityScanner } from '../security/index.js';
import { PolicyEvaluator } from '../policy/index.js';
import { DecisionEngine } from '../decision/index.js';
import { AuditLogger } from '../audit/index.js';
import type { Config, AnalysisResult } from '../types.js';

export class PRGatekeeper {
  private github: GitHubClient;
  private blastRadius: BlastRadiusCalculator;
  private security: SecurityScanner;
  private policy: PolicyEvaluator;
  private decision: DecisionEngine;
  private audit: AuditLogger;

  constructor(config: Config) {
    this.github = new GitHubClient(config.github);
    this.blastRadius = new BlastRadiusCalculator(config.team);
    this.security = new SecurityScanner(config.security);
    this.policy = new PolicyEvaluator(config.policies);
    this.decision = new DecisionEngine(config.decision, config.team);
    this.audit = new AuditLogger(config.audit);
  }

  async analyze({ owner, repo, prNumber }: { owner: string; repo: string; prNumber: number }): Promise<AnalysisResult> {
    // 1. Fetch PR from GitHub
    console.log('📥 Fetching PR data...');
    const pr = await this.github.getPR(owner, repo, prNumber);

    // 2. Calculate blast radius
    console.log('📊 Calculating blast radius...');
    const blastRadius = await this.blastRadius.calculate(pr);

    // 3. Scan for security issues
    console.log('🔒 Scanning for security issues...');
    const securityFindings = await this.security.scan(pr);

    // 4. Evaluate policies
    console.log('📋 Evaluating policies...');
    const policyResults = await this.policy.evaluate(pr, {
      blastRadius,
      securityFindings
    });

    // 5. Make decision
    console.log('🤖 Making decision...');
    const decision = await this.decision.make({
      blastRadius,
      securityFindings,
      policyResults
    });

    // 6. Log to audit
    console.log('📝 Logging to audit...');
    await this.audit.log({
      pr,
      blastRadius,
      securityFindings,
      policyResults,
      decision
    });

    return {
      pr,
      blastRadius,
      securityFindings,
      policyResults,
      decision
    };
  }
}
