import { describe, it } from 'node:test';
import assert from 'node:assert';

describe('Security Scanner', () => {
  it('should detect AWS access key', async () => {
    const { SecurityScanner } = await import('../dist/security/index.js');

    const config = {
      enabled: true,
      scanSecrets: true,
      scanDependencies: false,
      scanInjections: false
    };

    const pr = {
      number: 1,
      title: 'Add key',
      body: 'Add key',
      author: 'test',
      sourceBranch: 'feature',
      targetBranch: 'main',
      changedFiles: 1,
      additions: 5,
      deletions: 0,
      url: 'https://example.com',
      files: [
        {
          filename: 'config.ts',
          status: 'added',
          additions: 2,
          deletions: 0,
          changes: 2,
          patch: '+ const key = "AKIAIOSFODNN7EXAMPLE"\n'
        }
      ]
    };

    const scanner = new SecurityScanner(config);
    const findings = await scanner.scan(pr);

    assert.ok(findings.length > 0);
    assert.strictEqual(findings[0].type, 'secret');
    assert.strictEqual(findings[0].severity, 'critical');
    assert.ok(findings[0].location.includes('config.ts'));
  });

  it('should detect GitHub token', async () => {
    const { SecurityScanner } = await import('../dist/security/index.js');

    const config = {
      enabled: true,
      scanSecrets: true,
      scanDependencies: false,
      scanInjections: false
    };

    const pr = {
      number: 1,
      title: 'Add token',
      body: 'Add token',
      author: 'test',
      sourceBranch: 'feature',
      targetBranch: 'main',
      changedFiles: 1,
      additions: 5,
      deletions: 0,
      url: 'https://example.com',
      files: [
        {
          filename: 'config.ts',
          status: 'added',
          additions: 2,
          deletions: 0,
          changes: 2,
          patch: '+ const token = "ghp_1234567890abcdefghijklmnop"\n'
        }
      ]
    };

    const scanner = new SecurityScanner(config);
    const findings = await scanner.scan(pr);

    assert.ok(findings.length > 0);
    assert.strictEqual(findings[0].type, 'secret');
    assert.ok(findings[0].pattern.includes('githubPat'));
  });

  it('should detect SQL injection', async () => {
    const { SecurityScanner } = await import('../dist/security/index.js');

    const config = {
      enabled: true,
      scanSecrets: false,
      scanDependencies: false,
      scanInjections: true
    };

    const pr = {
      number: 1,
      title: 'Add query',
      body: 'Add query',
      author: 'test',
      sourceBranch: 'feature',
      targetBranch: 'main',
      changedFiles: 1,
      additions: 5,
      deletions: 0,
      url: 'https://example.com',
      files: [
        {
          filename: 'db.ts',
          status: 'added',
          additions: 2,
          deletions: 0,
          changes: 2,
          patch: '+ const query = execute(`SELECT * FROM users WHERE id = ${userId}`)\n'
        }
      ]
    };

    const scanner = new SecurityScanner(config);
    const findings = await scanner.scan(pr);

    assert.ok(findings.length > 0);
    assert.strictEqual(findings[0].type, 'injection');
    assert.strictEqual(findings[0].severity, 'critical');
  });

  it('should return empty findings when nothing found', async () => {
    const { SecurityScanner } = await import('../dist/security/index.js');

    const config = {
      enabled: true,
      scanSecrets: true,
      scanDependencies: false,
      scanInjections: true
    };

    const pr = {
      number: 1,
      title: 'Safe change',
      body: 'Safe change',
      author: 'test',
      sourceBranch: 'feature',
      targetBranch: 'main',
      changedFiles: 1,
      additions: 5,
      deletions: 0,
      url: 'https://example.com',
      files: [
        {
          filename: 'utils.ts',
          status: 'added',
          additions: 3,
          deletions: 0,
          changes: 3,
          patch: '+ const add = (a: number, b: number) => a + b\n'
        }
      ]
    };

    const scanner = new SecurityScanner(config);
    const findings = await scanner.scan(pr);

    assert.strictEqual(findings.length, 0);
  });

  it('should be disabled when config.enabled = false', async () => {
    const { SecurityScanner } = await import('../dist/security/index.js');

    const config = {
      enabled: false,
      scanSecrets: true,
      scanDependencies: true,
      scanInjections: true
    };

    const pr = {
      number: 1,
      title: 'Test',
      body: 'Test',
      author: 'test',
      sourceBranch: 'feature',
      targetBranch: 'main',
      changedFiles: 1,
      additions: 5,
      deletions: 0,
      url: 'https://example.com',
      files: [
        {
          filename: 'secret.ts',
          status: 'added',
          additions: 1,
          deletions: 0,
          changes: 1,
          patch: '+ const key = "AKIAIOSFODNN7EXAMPLE"\n'
        }
      ]
    };

    const scanner = new SecurityScanner(config);
    const findings = await scanner.scan(pr);

    assert.strictEqual(findings.length, 0);
  });
});
