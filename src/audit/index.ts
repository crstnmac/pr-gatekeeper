import fs from 'fs/promises';
import path from 'path';
import type { AuditConfig, AnalysisResult } from '../types.js';

export class AuditLogger {
  private config: AuditConfig;
  private logDir: string;

  constructor(config: AuditConfig) {
    this.config = config;
    this.logDir = config.logPath;
  }

  async log(result: AnalysisResult): Promise<void> {
    try {
      // Ensure log directory exists
      await fs.mkdir(this.logDir, { recursive: true });

      // Create daily log file
      const date = new Date().toISOString().split('T')[0];
      const logFile = path.join(this.logDir, `${date}.jsonl`);

      // Create audit entry
      const entry = {
        timestamp: new Date().toISOString(),
        decisionId: result.decision.decisionId,
        pr: {
          number: result.pr.number,
          title: result.pr.title,
          author: result.pr.author,
          repo: `${result.pr.sourceBranch} → ${result.pr.targetBranch}`
        },
        blastRadius: {
          score: result.blastRadius.score,
          codeImpact: result.blastRadius.codeImpact,
          testImpact: result.blastRadius.testImpact,
          dependencyImpact: result.blastRadius.dependencyImpact
        },
        security: {
          findingsCount: result.securityFindings.length,
          criticalCount: result.securityFindings.filter(f => f.severity === 'critical').length,
          highCount: result.securityFindings.filter(f => f.severity === 'high').length
        },
        policies: {
          total: result.policyResults.length,
          passed: result.policyResults.filter(r => r.status === 'passed').length,
          failed: result.policyResults.filter(r => r.status === 'failed').length,
          warnings: result.policyResults.filter(r => r.status === 'warning').length
        },
        decision: {
          action: result.decision.action,
          confidence: result.decision.confidence,
          summary: result.decision.reasoning.summary
        }
      };

      // Append to log file
      await fs.appendFile(logFile, JSON.stringify(entry) + '\n', 'utf-8');

      // Clean up old logs
      await this.pruneOldLogs();
    } catch (error) {
      // Don't fail analysis if logging fails
      console.error(`⚠️  Failed to log audit entry: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async pruneOldLogs(): Promise<void> {
    try {
      const files = await fs.readdir(this.logDir);
      const now = new Date();
      const retentionMs = this.config.retentionDays * 24 * 60 * 60 * 1000;

      for (const file of files) {
        if (!file.endsWith('.jsonl')) continue;

        const filePath = path.join(this.logDir, file);
        const stats = await fs.stat(filePath);
        const age = now.getTime() - stats.mtime.getTime();

        if (age > retentionMs) {
          await fs.unlink(filePath);
        }
      }
    } catch (error) {
      // Non-critical, don't fail
      console.error(`⚠️  Failed to prune old logs: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}
