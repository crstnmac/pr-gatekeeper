import { Octokit } from 'octokit';
import { RateLimiter } from '../utils/index.js';
import type { GitHubConfig, PullRequest } from '../types.js';

export class GitHubClient {
  private octokit: Octokit;
  private rateLimiter: RateLimiter;

  constructor(config: GitHubConfig) {
    this.octokit = new Octokit({
      auth: config.token,
      baseUrl: config.baseUrl || 'https://api.github.com',
      // Add retry handling at octokit level
      retry: {
        enabled: true,
        retries: 3
      },
      // Add throttle
      throttle: {
        enabled: true,
        onRateLimit: (retryAfter: number) => {
          console.warn(`⚠️  GitHub API rate limited. Resets at ${new Date(retryAfter * 1000).toISOString()}`);
        }
      }
    });

    // Create rate limiter (GitHub: 5000 requests/hour)
    this.rateLimiter = new RateLimiter({
      maxRequests: 5000,
      windowMs: 3600000 // 1 hour
    });
  }

  async getPR(owner: string, repo: string, prNumber: number): Promise<PullRequest> {
    return this.rateLimiter.execute(async () => {
      try {
        const { data: pr } = await this.octokit.rest.pulls.get({
          owner,
          repo,
          pull_number: prNumber
        });

        const { data: files } = await this.octokit.rest.pulls.listFiles({
          owner,
          repo,
          pull_number: prNumber
        });

        return {
          number: pr.number,
          title: pr.title,
          body: pr.body || undefined,
          author: pr.user.login,
          sourceBranch: pr.head.ref,
          targetBranch: pr.base.ref,
          changedFiles: pr.changed_files,
          additions: pr.additions,
          deletions: pr.deletions,
          url: pr.html_url,
          files: files.map((file: any) => ({
            filename: file.filename,
            status: file.status as 'added' | 'modified' | 'removed' | 'renamed',
            additions: file.additions,
            deletions: file.deletions,
            changes: file.changes,
            patch: file.patch
          }))
        };
      } catch (error) {
        if (error && typeof error === 'object' && 'status' in error && error.status === 404) {
          throw new Error(`PR #${prNumber} not found in ${owner}/${repo}`);
        }
        throw new Error(`Failed to fetch PR: ${error instanceof Error ? error.message : String(error)}`);
      }
    });
  }

  async getApprovals(owner: string, repo: string, prNumber: number): Promise<
    Array<{
      user: string;
      submittedAt: string;
      id: number;
    }>
  > {
    try {
      const { data: reviews } = await this.rateLimiter.execute(() =>
        this.octokit.rest.pulls.listReviews({
          owner,
          repo,
          pull_number: prNumber
        })
      );

      return reviews
        .filter((review: any) => review.state === 'APPROVED')
        .map((review: any) => ({
          user: review.user!.login,
          submittedAt: review.submitted_at || '',
          id: review.id
        }));
    } catch (error) {
      console.error('Failed to fetch approvals:', error instanceof Error ? error.message : String(error));
      return [];
    }
  }

  async getStatusChecks(owner: string, repo: string, prNumber: number): Promise<{
    state: string;
    totalCount: number;
    statuses: Array<{
      context: string;
      state: string;
      description: string | null;
    }>;
  }> {
    try {
      const { data: pr } = await this.rateLimiter.execute(() =>
        this.octokit.rest.pulls.get({
          owner,
          repo,
          pull_number: prNumber
        })
      );

      const { data: status } = await this.rateLimiter.execute(() =>
        this.octokit.rest.repos.getCombinedStatusForRef({
          owner,
          repo,
          ref: pr.head.sha
        })
      );

      return {
        state: status.state,
        totalCount: status.total_count,
        statuses: status.statuses.map((s: any) => ({
          context: s.context,
          state: s.state,
          description: s.description
        }))
      };
    } catch (error) {
      console.error(
        'Failed to fetch status checks:',
        error instanceof Error ? error.message : String(error)
      );
      return { state: 'unknown', totalCount: 0, statuses: [] };
    }
  }
}
