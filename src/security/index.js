export class SecurityScanner {
  constructor(config) {
    this.config = config;
    this.secretPatterns = this.initSecretPatterns();
    this.injectionPatterns = this.initInjectionPatterns();
  }

  async scan(pr) {
    const findings = [];

    if (this.config.enabled) {
      if (this.config.scanSecrets) {
        const secretFindings = this.scanSecrets(pr);
        findings.push(...secretFindings);
      }

      if (this.config.scanInjections) {
        const injectionFindings = this.scanInjections(pr);
        findings.push(...injectionFindings);
      }

      if (this.config.scanDependencies) {
        const depFindings = await this.scanDependencies(pr);
        findings.push(...depFindings);
      }
    }

    return findings;
  }

  scanSecrets(pr) {
    const findings = [];

    for (const file of pr.files) {
      if (!file.patch) continue;

      const lines = file.patch.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Only check added lines
        if (!line.startsWith('+') || line.startsWith('+++')) continue;

        const content = line.substring(1);

        for (const [patternName, pattern] of Object.entries(this.secretPatterns)) {
          const match = content.match(pattern.regex);
          if (match) {
            const severity = pattern.confidence === 'high' ? 'critical' : 'high';
            findings.push({
              type: 'secret',
              pattern: patternName,
              severity,
              confidence: pattern.confidence,
              location: `${file.filename}:${i + 1}`,
              snippet: this.maskValue(match[1] || match[0]),
              description: pattern.description
            });
          }
        }
      }
    }

    return findings;
  }

  scanInjections(pr) {
    const findings = [];

    for (const file of pr.files) {
      if (!file.patch || !file.filename.endsWith('.js') && !file.filename.endsWith('.ts')) {
        continue;
      }

      const lines = file.patch.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line.startsWith('+') || line.startsWith('+++')) continue;

        const content = line.substring(1);

        for (const [patternName, pattern] of Object.entries(this.injectionPatterns)) {
          const match = content.match(pattern.regex);
          if (match) {
            findings.push({
              type: 'injection',
              pattern: patternName,
              severity: pattern.severity,
              confidence: 'medium',
              location: `${file.filename}:${i + 1}`,
              snippet: content.substring(0, 60),
              description: pattern.description
            });
          }
        }
      }
    }

    return findings;
  }

  async scanDependencies(pr) {
    const findings = [];

    // For MVP, just detect dependency file changes
    // In production, integrate with Snyk, npm audit, etc.
    const depFiles = pr.files.filter(f =>
      f.filename.includes('package.json') ||
      f.filename.includes('package-lock.json')
    );

    for (const file of depFiles) {
      findings.push({
        type: 'dependency',
        severity: 'medium',
        confidence: 'low',
        location: file.filename,
        snippet: 'Dependency file changed - run vulnerability scan',
        description: 'Dependency changes detected. Run npm audit or equivalent scanner.'
      });
    }

    return findings;
  }

  initSecretPatterns() {
    return {
      awsAccessKey: {
        regex: /AKIA[0-9A-Z]{16}/,
        confidence: 'high',
        description: 'AWS Access Key detected'
      },
      awsSecretKey: {
        regex: /[0-9a-zA-Z/+]{40}/,
        confidence: 'high',
        description: 'Possible AWS Secret Key'
      },
      githubPat: {
        regex: /ghp_[a-zA-Z0-9]{36}/,
        confidence: 'high',
        description: 'GitHub Personal Access Token detected'
      },
      slackToken: {
        regex: /xox[baprs]-[a-zA-Z0-9-]+/,
        confidence: 'high',
        description: 'Slack Token detected'
      },
      genericApiKey: {
        regex: /(?:api|token|secret|key)\s*[=:]\s*['"`][a-zA-Z0-9_-]{20,}['"`]/i,
        confidence: 'medium',
        description: 'Possible API key or secret'
      },
      databaseUrl: {
        regex: /(mongodb|mysql|postgres|redis):\/\/[^:\s]+:[^@\s]+@/,
        confidence: 'high',
        description: 'Database connection string with credentials'
      }
    };
  }

  initInjectionPatterns() {
    return {
      sqlInjection: {
        regex: /(?:execute|exec|query)\s*\(\s*['"`][\s\S]*?\$\{[\s\S]*?\}/i,
        severity: 'critical',
        description: 'Possible SQL injection via template literal'
      },
      commandInjection: {
        regex: /(?:exec|spawn)\s*\(\s*['"`][\s\S]*?\$\{[\s\S]*?\}/i,
        severity: 'critical',
        description: 'Possible command injection via template literal'
      },
      unsafeInnerHTML: {
        regex: /\.innerHTML\s*=\s*[\s\S]*?\$/,
        severity: 'high',
        description: 'Possible XSS via innerHTML'
      },
      dangerousExec: {
        regex: /(?:execSync|exec)\s*\(\s*[\s\S]*?\+/,
        severity: 'high',
        description: 'Possible command injection via concatenation'
      }
    };
  }

  maskValue(value) {
    if (!value || value.length < 8) return value;
    return value.substring(0, 4) + '****' + value.substring(value.length - 4);
  }
}
