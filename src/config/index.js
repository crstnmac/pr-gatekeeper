import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export async function loadConfig(configPath) {
  const defaultConfigPath = path.join(__dirname, '../../config.json');
  const configFilePath = configPath || defaultConfigPath;

  try {
    const configContent = await fs.readFile(configFilePath, 'utf-8');
    const config = JSON.parse(configContent);
    return validateConfig(config);
  } catch (error) {
    if (error.code === 'ENOENT') {
      throw new Error(
        `Config file not found at ${configFilePath}. Copy config.example.json to config.json and configure.`
      );
    }
    throw new Error(`Failed to load config: ${error.message}`);
  }
}

function validateConfig(config) {
  if (!config.github || !config.github.token) {
    throw new Error('Missing required config: github.token');
  }

  // Set defaults
  return {
    ...config,
    team: {
      thresholds: {
        autoApprove: 20,
        autoApproveWithComment: 40,
        requiresReview: 60,
        requiresSeniorReview: 80,
        ...config.team?.thresholds
      },
      criticalPaths: config.team?.criticalPaths || {},
      safePaths: config.team?.safePaths || {},
      blockedPaths: config.team?.blockedPaths || []
    },
    security: {
      enabled: true,
      scanSecrets: true,
      scanDependencies: true,
      scanInjections: true,
      dependencySeverityThreshold: 'moderate',
      ...config.security
    },
    policies: {
      enabled: true,
      frameworks: [],
      ...config.policies
    },
    decision: {
      minConfidence: 0.7,
      fallbackToReview: true,
      ...config.decision
    },
    audit: {
      logPath: './audit',
      retentionDays: 90,
      ...config.audit
    }
  };
}
