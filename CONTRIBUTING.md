# Contributing to PR Gatekeeper

## Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/pr-gatekeeper.git
   cd pr-gatekeeper
   ```
3. Install dependencies:
   ```bash
   npm install
   ```

## Running Tests

```bash
npm test
```

## Code Style

This project uses ESLint and Prettier:

```bash
# Lint
npm run lint

# Format
npm run format
```

## Project Structure

```
src/
├── blast-radius/     # Impact calculation algorithms
├── security/         # Security scanning patterns
├── policy/           # Policy evaluation rules
├── decision/         # Decision engine logic
├── github/           # GitHub API client
├── audit/            # Audit logging
├── cli/              # CLI argument parsing
├── config/           # Configuration loader
├── gatekeeper/       # Main orchestration
└── index.js          # Entry point
```

## Adding Features

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature
   ```

2. Make your changes

3. Write tests (if applicable)

4. Commit your changes:
   ```bash
   git commit -m "Add your feature"
   ```

5. Push to your fork:
   ```bash
   git push origin feature/your-feature
   ```

6. Open a pull request

## Adding Security Patterns

To add new secret detection patterns, edit `src/security/index.js`:

```javascript
initSecretPatterns() {
  return {
    // ... existing patterns
    yourPattern: {
      regex: /your-regex/,
      confidence: 'high',
      description: 'Your pattern description'
    }
  };
}
```

## Adding Policy Rules

To add custom policy rules, edit `src/policy/index.js`:

```javascript
initRules() {
  return [
    // ... existing rules
    {
      ruleId: 'your-custom-rule',
      name: 'Your Custom Rule',
      category: 'security',
      conditions: { targetBranch: ['main'] },
      validations: [
        // your validations
      ]
    }
  ];
}
```

## Testing

When adding new features, ensure:
- Code follows existing patterns
- Functions are well-documented
- Error handling is proper
- Configuration options are documented

## Questions?

Open an issue or join our discussions.
