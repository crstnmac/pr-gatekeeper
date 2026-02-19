import { describe, it } from 'node:test';
import assert from 'node:assert';

describe('Config Validation', () => {
  it('should validate threshold ordering', async () => {
    const { validateConfig } = await import('../dist/config/index.js');

    // Valid thresholds
    const validConfig = {
      github: { token: 'test-token' },
      team: {
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
      }
    };

    const result = validateConfig(validConfig);
    assert.strictEqual(result.team.thresholds.autoApprove, 20);
    assert.strictEqual(result.team.thresholds.requiresSeniorReview, 80);
  });

  it('should throw error for invalid threshold ordering', async () => {
    const { validateConfig } = await import('../dist/config/index.js');

    const invalidConfig = {
      github: { token: 'test-token' },
      team: {
        teamId: 'test',
        thresholds: {
          autoApprove: 40,
          autoApproveWithComment: 20, // Wrong order!
          requiresReview: 60,
          requiresSeniorReview: 80
        },
        criticalPaths: {},
        safePaths: {},
        blockedPaths: []
      }
    };

    assert.throws(
      () => validateConfig(invalidConfig),
      /autoApproveWithComment must be less than/
    );
  });

  it('should throw error for thresholds out of range', async () => {
    const { validateConfig } = await import('../dist/config/index.js');

    const invalidConfig = {
      github: { token: 'test-token' },
      team: {
        teamId: 'test',
        thresholds: {
          autoApprove: -5, // Invalid!
          autoApproveWithComment: 40,
          requiresReview: 60,
          requiresSeniorReview: 80
        },
        criticalPaths: {},
        safePaths: {},
        blockedPaths: []
      }
    };

    assert.throws(
      () => validateConfig(invalidConfig),
      /must be between 0 and 100/
    );
  });

  it('should set default values', async () => {
    const { validateConfig } = await import('../dist/config/index.js');

    const minimalConfig = {
      github: { token: 'test-token' }
    };

    const result = validateConfig(minimalConfig);

    assert.strictEqual(result.team.teamId, 'default');
    assert.strictEqual(result.security.enabled, true);
    assert.strictEqual(result.policies.enabled, true);
    assert.strictEqual(result.decision.minConfidence, 0.7);
    assert.strictEqual(result.audit.logPath, './audit-logs');
  });
});
