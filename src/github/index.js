import { Octokit } from 'octokit';

export class GitHubClient {
  constructor(config) {
    this.octokit = new Octokit({
      auth: config.token,
      baseUrl: config.baseUrl || 'https://api.github.com'
    });
  }

  async getPR(owner, repo, prNumber) {
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
        author: pr.user.login,
        sourceBranch: pr.head.ref,
        targetBranch: pr.base.ref,
        changedFiles: pr.changed_files,
        additions: pr.additions,
        deletions: pr.deletions,
        url: pr.html_url,
        files: files.map(file => ({
          filename: file.filename,
          status: file.status,
          additions: file.additions,
          deletions: file.deletions,
          changes: file.changes,
          patch: file.patch
        }))
      };
    } catch (error) {
      if (error.status === 404) {
        throw new Error(`PR #${prNumber} not found in ${owner}/${repo}`);
      }
      throw new Error(`Failed to fetch PR: ${error.message}`);
    }
  }

  async getApprovals(owner, repo, prNumber) {
    try {
      const { data: reviews } = await this.octokit.rest.pulls.listReviews({
        owner,
        repo,
        pull_number: prNumber
      });

      return reviews
        .filter(review => review.state === 'APPROVED')
        .map(review => ({
          user: review.user.login,
          submittedAt: review.submitted_at,
          id: review.id
        }));
    } catch (error) {
      console.error('Failed to fetch approvals:', error.message);
      return [];
    }
  }

  async getStatusChecks(owner, repo, prNumber) {
    try {
      const { data: pr } = await this.octokit.rest.pulls.get({
        owner,
        repo,
        pull_number: prNumber
      });

      const { data: status } = await this.octokit.rest.repos.getCombinedStatusForRef({
        owner,
        repo,
        ref: pr.head.sha
      });

      return {
        state: status.state,
        totalCount: status.total_count,
        statuses: status.statuses.map(s => ({
          context: s.context,
          state: s.state,
          description: s.description
        }))
      };
    } catch (error) {
      console.error('Failed to fetch status checks:', error.message);
      return { state: 'unknown', totalCount: 0, statuses: [] };
    }
  }
}
