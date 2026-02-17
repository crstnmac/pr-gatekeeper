import type {
  TeamConfig,
  PullRequest,
  BlastRadiusResult,
  CodeImpactDetails,
  TestImpactDetails,
  DependencyImpactDetails,
  BlastImpactLevel,
  RiskSignal
} from '../types.js';

export class BlastRadiusCalculator {
  private config: TeamConfig;

  constructor(teamConfig: TeamConfig) {
    this.config = teamConfig;
  }

  async calculate(pr: PullRequest): Promise<BlastRadiusResult> {
    const codeImpact = this.calculateCodeImpact(pr);
    const testImpact = await this.calculateTestImpact(pr);
    const dependencyImpact = this.calculateDependencyImpact(pr);
    const riskSignals = this.detectRiskSignals(pr);

    // Calculate base score
    let score = codeImpact.score + testImpact.score + dependencyImpact.score;

    // Apply risk signal multipliers
    for (const signal of riskSignals) {
      score *= signal.multiplier;
    }

    // Clamp to 0-100
    score = Math.min(100, Math.max(0, Math.round(score)));

    return {
      score,
      codeImpact: codeImpact.level,
      testImpact: testImpact.level,
      dependencyImpact: dependencyImpact.level,
      riskSignals,
      details: {
        codeImpact,
        testImpact,
        dependencyImpact
      }
    };
  }

  private calculateCodeImpact(pr: PullRequest): CodeImpactDetails {
    const fileCount = pr.files.length;
    const lineCount = pr.additions + pr.deletions;
    const criticalPathImpact = this.calculateCriticalPathImpact(pr.files);
    const safePathReduction = this.calculateSafePathReduction(pr.files);

    let score = 0;

    // Files changed (0-15 points)
    if (fileCount <= 2) score += 5;
    else if (fileCount <= 5) score += 10;
    else if (fileCount <= 10) score += 13;
    else score += 15;

    // Lines touched (0-15 points)
    if (lineCount <= 50) score += 3;
    else if (lineCount <= 200) score += 7;
    else if (lineCount <= 500) score += 11;
    else score += 15;

    // Critical path impact (0-10 points)
    score += criticalPathImpact;

    // Safe path reduction (subtract up to 10 points)
    score = Math.max(0, score - safePathReduction);

    // Determine level
    let level: BlastImpactLevel = 'low';
    if (score > 10) level = 'medium';
    if (score > 20) level = 'high';
    if (score > 30) level = 'critical';

    return {
      score,
      level,
      fileCount,
      lineCount,
      criticalPathImpact,
      safePathReduction
    };
  }

  private calculateCriticalPathImpact(files: PullRequest['files']): number {
    let impact = 0;

    for (const file of files) {
      for (const [pattern, config] of Object.entries(this.config.criticalPaths)) {
        if (this.matchPattern(file.filename, pattern)) {
          impact += config.baseScore || 10;
          // Apply multiplier
          impact *= config.multiplier || 1.0;
        }
      }
    }

    return Math.min(10, impact);
  }

  private calculateSafePathReduction(files: PullRequest['files']): number {
    let reduction = 0;

    for (const file of files) {
      for (const [pattern, config] of Object.entries(this.config.safePaths)) {
        if (this.matchPattern(file.filename, pattern)) {
          reduction += 5 * (config.multiplier || 1.0);
        }
      }
    }

    return Math.min(10, Math.round(reduction));
  }

  private detectRiskSignals(pr: PullRequest): RiskSignal[] {
    const signals: RiskSignal[] = [];

    // Check for blocked paths
    for (const blockedPath of this.config.blockedPaths) {
      for (const file of pr.files) {
        if (this.matchPattern(file.filename, blockedPath)) {
          signals.push({
            type: 'blocked_path',
            pattern: blockedPath,
            multiplier: 2.0,
            file: file.filename
          });
        }
      }
    }

    // Check for config files
    const configPatterns = ['.env', 'docker', 'k8s', 'kubernetes', 'terraform', 'infrastructure'];
    for (const file of pr.files) {
      const filename = file.filename.toLowerCase();
      if (configPatterns.some(p => filename.includes(p))) {
        signals.push({
          type: 'config_change',
          multiplier: 1.5,
          file: file.filename
        });
      }
    }

    // Check for auth changes
    const authPatterns = ['auth', 'login', 'password', 'credential'];
    for (const file of pr.files) {
      const filename = file.filename.toLowerCase();
      if (authPatterns.some(p => filename.includes(p))) {
        signals.push({
          type: 'auth_change',
          multiplier: 2.5,
          file: file.filename
        });
      }
    }

    return signals;
  }

  private async calculateTestImpact(pr: PullRequest): Promise<TestImpactDetails> {
    // For MVP, we'll use simple heuristics
    // In production, this would query test results from CI
    const testFiles = pr.files.filter(
      f =>
        f.filename.includes('test') ||
        f.filename.includes('spec') ||
        f.filename.includes('__tests__')
    );

    let score = 0;

    // Tests modified (0-15 points)
    if (testFiles.length === 0) score += 0;
    else if (testFiles.length <= 3) score += 3;
    else if (testFiles.length <= 10) score += 7;
    else score += 15;

    // Tests added vs deleted (0-15 points)
    const testAdditions = testFiles.reduce((sum, f) => sum + f.additions, 0);
    if (testAdditions > 0) score += Math.min(10, testAdditions / 50);

    let level: BlastImpactLevel = 'low';
    if (score > 5) level = 'medium';
    if (score > 10) level = 'high';

    return {
      score: Math.min(30, Math.round(score)),
      level,
      testFiles: testFiles.length,
      testAdditions
    };
  }

  private calculateDependencyImpact(pr: PullRequest): DependencyImpactDetails {
    // For MVP, detect package files
    const depFiles = pr.files.filter(
      f =>
        f.filename.includes('package.json') ||
        f.filename.includes('package-lock.json') ||
        f.filename.includes('requirements.txt') ||
        f.filename.includes('pom.xml') ||
        f.filename.includes('build.gradle')
    );

    let score = 0;

    if (depFiles.length === 0) {
      score = 0;
    } else {
      // Check for dependency changes in patches
      for (const file of depFiles) {
        if (file.patch) {
          // Count dependency additions
          const addedDeps = (file.patch.match(/^\+/gm) || []).length;
          score += Math.min(20, addedDeps);
        }
      }
    }

    let level: BlastImpactLevel = 'low';
    if (score > 5) level = 'medium';
    if (score > 15) level = 'high';

    return {
      score: Math.min(30, Math.round(score)),
      level,
      depFiles: depFiles.length
    };
  }

  private matchPattern(filename: string, pattern: string): boolean {
    // Simple glob matching for MVP
    const regexPattern = pattern
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '.');

    const regex = new RegExp(regexPattern);
    return regex.test(filename);
  }
}
