import { describe, it } from 'node:test';
import assert from 'node:assert';

describe('Blast Radius Calculator', () => {
  it('should calculate minimal impact for small PR', async () => {
    const { BlastRadiusCalculator } = await import('../dist/blast-radius/index.js');

    const config = {
      teamId: 'test',
      thresholds: {
        autoApprove: 20,
        autoApproveWithComment: 40,
        requiresReview: 60,
        requiresSeniorReview: 80
      },
      criticalPaths: {},
      safePaths: {},
      blockedPaths: []
    };

    const pr = {
      number: 1,
      title: 'Small change',
      body: 'Fix typo',
      author: 'test',
      sourceBranch: 'feature',
      targetBranch: 'main',
      changedFiles: 2,
      additions: 10,
      deletions: 5,
      url: 'https://example.com',
      files: [
        {
          filename: 'docs/README.md',
          status: 'modified',
          additions: 5,
          deletions: 2,
          changes: 7,
          patch: '+ hello\n- goodbye'
        }
      ]
    };

    const calculator = new BlastRadiusCalculator(config);
    const result = await calculator.calculate(pr);

    assert.strictEqual(result.score, 5); // 5 files + 3 lines - 5 (docs safe)
    assert.strictEqual(result.codeImpact, 'low');
    assert.strictEqual(result.testImpact, 'low');
    assert.strictEqual(result.dependencyImpact, 'low');
  });

  it('should detect critical path impact', async () => {
    const { BlastRadiusCalculator } = await import('../dist/blast-radius/index.js');

    const config = {
      teamId: 'test',
      thresholds: {
        autoApprove: 20,
        autoApproveWithComment: 40,
        requiresReview: 60,
        requiresSeniorReview: 80
      },
      criticalPaths: {
        'auth/**/*': { baseScore: 60, multiplier: 2.0 }
      },
      safePaths: {},
      blockedPaths: []
    };

    const pr = {
      number: 1,
      title: 'Auth change',
      body: 'Update auth',
      author: 'test',
      sourceBranch: 'feature',
      targetBranch: 'main',
      changedFiles: 1,
      additions: 5,
      deletions: 0,
      url: 'https://example.com',
      files: [
        {
          filename: 'auth/login.ts',
          status: 'modified',
          additions: 5,
          deletions: 0,
          changes: 5
        }
      ]
    };

    const calculator = new BlastRadiusCalculator(config);
    const result = await calculator.calculate(pr);

    assert.strictEqual(result.codeImpact, 'critical');
    assert.ok(result.score >= 60);
  });

  it('should apply safe path reduction', async () => {
    const { BlastRadiusCalculator } = await import('../dist/blast-radius/index.js');

    const config = {
      teamId: 'test',
      thresholds: {
        autoApprove: 20,
        autoApproveWithComment: 40,
        requiresReview: 60,
        requiresSeniorReview: 80
      },
      criticalPaths: {},
      safePaths: {
        'docs/**/*': { multiplier: 0.1 }
      },
      blockedPaths: []
    };

    const pr = {
      number: 1,
      title: 'Docs change',
      body: 'Update docs',
      author: 'test',
      sourceBranch: 'feature',
      targetBranch: 'main',
      changedFiles: 10,
      additions: 100,
      deletions: 0,
      url: 'https://example.com',
      files: [
        {
          filename: 'docs/api.md',
          status: 'modified',
          additions: 100,
          deletions: 0,
          changes: 100
        }
      ]
    };

    const calculator = new BlastRadiusCalculator(config);
    const result = await calculator.calculate(pr);

    assert.ok(result.score < 20); // Safe paths reduce score
    assert.strictEqual(result.codeImpact, 'low');
  });

  it('should detect blocked paths', async () => {
    const { BlastRadiusCalculator } = await import('../dist/blast-radius/index.js');

    const config = {
      teamId: 'test',
      thresholds: {
        autoApprove: 20,
        autoApproveWithComment: 40,
        requiresReview: 60,
        requiresSeniorReview: 80
      },
      criticalPaths: {},
      safePaths: {},
      blockedPaths: ['infra/*']
    };

    const pr = {
      number: 1,
      title: 'Infra change',
      body: 'Update infra',
      author: 'test',
      sourceBranch: 'feature',
      targetBranch: 'main',
      changedFiles: 1,
      additions: 5,
      deletions: 0,
      url: 'https://example.com',
      files: [
        {
          filename: 'infra/config.yaml',
          status: 'modified',
          additions: 5,
          deletions: 0,
          changes: 5
        }
      ]
    };

    const calculator = new BlastRadiusCalculator(config);
    const result = await calculator.calculate(pr);

    assert.strictEqual(result.riskSignals.length, 1);
    assert.strictEqual(result.riskSignals[0].type, 'blocked_path');
  });
});
