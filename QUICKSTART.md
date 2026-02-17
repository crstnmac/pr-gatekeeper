# Quick Start Guide - PR Gatekeeper Prototype

## Setup

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure GitHub Token

Get a GitHub Personal Access Token:
1. Go to https://github.com/settings/tokens
2. Generate a new token (classic)
3. Select scopes: `repo` (or `public_repo` for public repos only)
4. Copy the token

Edit `config.json`:
```json
{
  "github": {
    "token": "ghp_YOUR_TOKEN_HERE",
    "baseUrl": "https://api.github.com"
  }
}
```

### 3. Run Analysis

```bash
# Basic usage
npm start -- --owner octocat --repo hello-world --pr 123

# With verbose output
npm start -- --owner octocat --repo hello-world --pr 123 --verbose

# Custom config file
npm start -- --owner octocat --repo hello-world --pr 123 --config /path/to/config.json
```

## Example Usage

### Analyze a Safe PR (Documentation Change)

```bash
npm start -- --owner octocat --repo hello-world --pr 1
```

Expected result:
- Blast radius: Low (0-20)
- Security findings: None
- Decision: AUTO-APPROVE

### Analyze a Medium-Risk PR (Feature Change)

```bash
npm start -- --owner octocat --repo hello-world --pr 42
```

Expected result:
- Blast radius: Medium (21-60)
- Security findings: Possibly none
- Decision: REQUIRE REVIEW

### Analyze a High-Risk PR (Contains Secrets)

```bash
npm start -- --owner octocat --repo hello-world --pr 100
```

Expected result:
- Blast radius: May vary
- Security findings: Critical (secrets detected)
- Decision: BLOCKED

## Understanding the Output

```
┌─────────────────────────────────────────────────────────────┐
│  PULL REQUEST                                               │
├─────────────────────────────────────────────────────────────┤
│  Title:     Add new feature XYZ                            │
│  Author:    octocat                                         │
│  Branch:    feature/xyz → main                            │
│  Files:     5 (+123/-45)                                   │
└─────────────────────────────────────────────────────────────┘
```

### Blast Radius
- **Score 0-20**: Minimal impact, auto-approve likely
- **Score 21-40**: Low-medium impact, may auto-approve
- **Score 41-60**: Medium impact, requires review
- **Score 61-80**: High impact, requires senior review
- **Score 81-100**: Critical impact, blocked

### Security Findings
- 🔴 **CRITICAL**: Immediately block the PR
- 🟠 **HIGH**: Warn or block depending on configuration
- 🟡 **MEDIUM**: Warning
- 🔵 **LOW**: Informational

### Final Decision
- ✅ **AUTO-APPROVED**: Safe to merge immediately
- ✅💬 **AUTO-APPROVED (with comment)**: Safe, but add a note
- 👀 **REQUIRES REVIEW**: Need at least one reviewer
- 👀👤 **REQUIRES SENIOR REVIEW**: Need senior engineer review
- 🚫 **BLOCKED**: Cannot merge - fix issues first

## Configuration Options

### Blast Radius Thresholds

```json
{
  "team": {
    "thresholds": {
      "autoApprove": 20,           // 0-20: Auto-approve
      "autoApproveWithComment": 40, // 21-40: Auto-approve with comment
      "requiresReview": 60,        // 41-60: Requires review
      "requiresSeniorReview": 80    // 61-80: Requires senior review
    }
  }
}
```

### Critical Paths

```json
{
  "criticalPaths": {
    "auth/**/*": { "baseScore": 60, "multiplier": 2.0 },
    "infra/**/*": { "baseScore": 50, "multiplier": 2.0 }
  }
}
```

### Security Settings

```json
{
  "security": {
    "enabled": true,
    "scanSecrets": true,
    "scanDependencies": true,
    "scanInjections": true
  }
}
```

### Policy Frameworks

```json
{
  "policies": {
    "enabled": true,
    "frameworks": ["SOC2", "HIPAA", "ISO27001"]
  }
}
```

## Troubleshooting

### Error: "Config file not found"
```bash
cp config.example.json config.json
# Edit config.json with your settings
```

### Error: "PR #X not found"
- Check the owner/repo/PR number are correct
- Verify your GitHub token has access to the repository

### Error: "Failed to fetch PR"
- Check your internet connection
- Verify the GitHub token is valid
- Check GitHub API status: https://www.githubstatus.com/

## Audit Logs

All decisions are logged to `./audit/YYYY-MM-DD.jsonl`:

```json
{
  "auditId": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-02-16T17:52:00.000Z",
  "pr": {
    "number": 123,
    "title": "Add new feature",
    "author": "octocat",
    "url": "https://github.com/octocat/hello-world/pull/123"
  },
  "blastRadius": { "score": 35, ... },
  "security": { "critical": 0, "high": 1, ... },
  "policies": { "passed": 5, "failed": 0, ... },
  "decision": { "action": "require_review", ... }
}
```

Query audit logs (in production, this would be a CLI command):
```javascript
import { AuditLogger } from './src/audit/index.js';

const audit = new AuditLogger({ logPath: './audit', retentionDays: 90 });
const results = await audit.query({
  action: 'blocked',
  startDate: '2024-02-01T00:00:00Z'
});
```

## Next Steps

1. **Test on real PRs**: Analyze actual PRs in your repositories
2. **Adjust thresholds**: Customize for your team's risk tolerance
3. **Add custom patterns**: Extend secret/injection patterns
4. **Enable frameworks**: Add SOC2, HIPAA, ISO27001 compliance rules
5. **Build CI integration**: Add to GitHub Actions workflow

## Production Considerations

- Rate limiting: GitHub API has rate limits (5000/hour authenticated)
- Security: Store tokens securely (environment variables, secret managers)
- Monitoring: Add logging and metrics
- Scaling: Consider caching, async processing for large repos
- LLM integration: Add decision engine with Claude/GPT for nuanced decisions

## Questions?

Open an issue on GitHub or contact the team.
