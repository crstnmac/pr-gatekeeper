/**
 * Core type definitions for PR Gatekeeper
 */

/**
 * Pull Request information
 */
export interface PullRequest {
  number: number;
  title: string;
  author: string;
  sourceBranch: string;
  targetBranch: string;
  changedFiles: number;
  additions: number;
  deletions: number;
  url: string;
  files: PRFile[];
}

/**
 * Individual file changed in a PR
 */
export interface PRFile {
  filename: string;
  status: 'added' | 'modified' | 'removed' | 'renamed';
  additions: number;
  deletions: number;
  changes: number;
  patch?: string;
}

/**
 * Blast radius calculation result
 */
export interface BlastRadiusResult {
  score: number;
  codeImpact: BlastImpactLevel;
  testImpact: BlastImpactLevel;
  dependencyImpact: BlastImpactLevel;
  riskSignals: RiskSignal[];
  details: {
    codeImpact: CodeImpactDetails;
    testImpact: TestImpactDetails;
    dependencyImpact: DependencyImpactDetails;
  };
}

export type BlastImpactLevel = 'low' | 'medium' | 'high' | 'critical';

/**
 * Code impact details
 */
export interface CodeImpactDetails {
  score: number;
  level: BlastImpactLevel;
  fileCount: number;
  lineCount: number;
  criticalPathImpact: number;
  safePathReduction: number;
}

/**
 * Test impact details
 */
export interface TestImpactDetails {
  score: number;
  level: BlastImpactLevel;
  testFiles: number;
  testAdditions: number;
}

/**
 * Dependency impact details
 */
export interface DependencyImpactDetails {
  score: number;
  level: BlastImpactLevel;
  depFiles: number;
}

/**
 * Risk signal detected in PR
 */
export interface RiskSignal {
  type: RiskSignalType;
  pattern?: string;
  multiplier: number;
  file?: string;
}

export type RiskSignalType =
  | 'blocked_path'
  | 'config_change'
  | 'auth_change'
  | 'critical_path';

/**
 * Security finding
 */
export interface SecurityFinding {
  type: SecurityType;
  pattern?: string;
  severity: Severity;
  confidence: Confidence;
  location: string;
  snippet: string;
  description: string;
}

export type SecurityType = 'secret' | 'injection' | 'dependency';
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Confidence = 'high' | 'medium' | 'low';
export type PolicyActionType = 'block' | 'warn' | null;

/**
 * Policy evaluation result
 */
export interface PolicyResult {
  ruleId: string;
  name: string;
  status: PolicyStatus;
  action?: PolicyAction;
  validations: PolicyValidation[];
  message: string;
  reason?: string;
}

export type PolicyStatus = 'passed' | 'warning' | 'failed' | 'skipped';
export type PolicyAction = 'block' | 'warn' | null;

/**
 * Policy validation result
 */
export interface PolicyValidation {
  type: string;
  status: PolicyStatus;
  severity?: Severity;
  message?: string;
  reason?: string;
}

/**
 * Decision engine result
 */
export interface Decision {
  decisionId: string;
  action: DecisionAction;
  confidence: number;
  reasoning: {
    summary: string;
    factors: DecisionFactor[];
  };
  recommendations: string[];
  nextSteps: string[];
}

export type DecisionAction =
  | 'auto_approve'
  | 'auto_approve_comment'
  | 'require_review'
  | 'require_senior_review'
  | 'block';

/**
 * Decision factor
 */
export interface DecisionFactor {
  factor: string;
  impact: string;
  score: number;
  details: string;
}

/**
 * Gatekeeper analysis result
 */
export interface AnalysisResult {
  pr: PullRequest;
  blastRadius: BlastRadiusResult;
  securityFindings: SecurityFinding[];
  policyResults: PolicyResult[];
  decision: Decision;
}

/**
 * Configuration types
 */
export interface Config {
  github: GitHubConfig;
  team: TeamConfig;
  security: SecurityConfig;
  policies: PoliciesConfig;
  decision: DecisionConfig;
  audit: AuditConfig;
}

export interface GitHubConfig {
  token: string;
  baseUrl?: string;
}

export interface TeamConfig {
  teamId: string;
  thresholds: TeamThresholds;
  criticalPaths: Record<string, PathConfig>;
  safePaths: Record<string, PathConfig>;
  blockedPaths: string[];
}

export interface TeamThresholds {
  autoApprove: number;
  autoApproveWithComment: number;
  requiresReview: number;
  requiresSeniorReview: number;
}

export interface PathConfig {
  baseScore?: number;
  multiplier: number;
}

export interface SecurityConfig {
  enabled: boolean;
  scanSecrets: boolean;
  scanDependencies: boolean;
  scanInjections: boolean;
  dependencySeverityThreshold: Severity;
}

export interface PoliciesConfig {
  enabled: boolean;
  frameworks: string[];
  requireJiraTicket: boolean;
  requireChangelog: boolean;
}

export interface DecisionConfig {
  minConfidence: number;
  fallbackToReview: boolean;
}

export interface AuditConfig {
  logPath: string;
  retentionDays: number;
}

/**
 * CLI arguments
 */
export interface CLIArgs {
  owner: string;
  repo: string;
  pr: string;
  config?: string;
  verbose: boolean;
}
