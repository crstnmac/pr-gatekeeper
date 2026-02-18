import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import type { Config } from '../types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function loadConfig(configPath?: string): Promise<Config> {
  const defaultConfigPath = path.join(__dirname, '../../config.json');
  const configFilePath = configPath || defaultConfigPath;

  try {
    const configContent = await fs.readFile(configFilePath, 'utf-8');
    const config = JSON.parse(configContent) as Partial<Config>;
    return validateConfig(config);
  } catch (error) {
    if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
      throw new Error(
        `Config file not found at ${configFilePath}. Copy config.example.json to config.json and configure.`
      );
    }
    throw new Error(`Failed to load config: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function validateConfig(config: Partial<Config>): Config {
  if (!config.github || !config.github.token) {
    throw new Error('Missing required config: github.token');
  }

  // Set defaults and validate thresholds
  const thresholds = {
    autoApprove: 20,
    autoApproveWithComment: 40,
    requiresReview: 60,
    requiresSeniorReview: 80,
    ...config.team?.thresholds
  };

  // Validate threshold ordering
  if (thresholds.autoApprove >= thresholds.autoApproveWithComment) {
    throw new Error('Invalid thresholds: autoApprove must be less than autoApproveWithComment');
  }
  if (thresholds.autoApproveWithComment >= thresholds.requiresReview) {
    throw new Error('Invalid thresholds: autoApproveWithComment must be less than requiresReview');
  }
  if (thresholds.requiresReview >= thresholds.requiresSeniorReview) {
    throw new Error('Invalid thresholds: requiresReview must be less than requiresSeniorReview');
  }

  // Ensure thresholds are in valid range
  const allThresholds = Object.values(thresholds);
  if (allThresholds.some(t => t < 0 || t > 100)) {
    throw new Error('Invalid thresholds: all values must be between 0 and 100');
  }

  return {
    ...config,
    github: config.github!,
    team: {
      thresholds,
      criticalPaths: config.team?.criticalPaths || {},
      safePaths: config.team?.safePaths || {},
      blockedPaths: config.team?.blockedPaths || [],
      teamId: config.team?.teamId || 'default'
    },
    security: {
      enabled: true,
      scanSecrets: true,
      scanDependencies: true,
      scanInjections: true,
      dependencySeverityThreshold: 'medium',
      ...config.security
    },
    policies: {
      enabled: true,
      frameworks: [],
      requireJiraTicket: false,
      requireChangelog: false,
      ...config.policies
    },
    decision: {
      minConfidence: 0.7,
      fallbackToReview: true,
      ...config.decision
    },
    audit: {
      logPath: './audit-logs',
      retentionDays: 90,
      ...config.audit
    }
  };
}
