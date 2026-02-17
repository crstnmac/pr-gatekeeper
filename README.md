# PR Gatekeeper - Prototype

Intelligent PR triage for enterprise teams.

## What It Does

- Calculates blast radius of PRs (code + test + dependency impact)
- Scans for security issues (secrets, vulnerabilities)
- Evaluates policies and compliance
- Makes auto-approve / review / block decisions

## Quick Start

```bash
# Install dependencies
npm install

# Configure
cp config.example.json config.json
# Edit config.json with your settings

# Run
npm start -- --owner <owner> --repo <repo> --pr <pr-number>
```

## Architecture

```
src/
├── blast-radius/     # Impact calculation
├── security/         # Security scanning
├── policy/           # Policy engine
├── decision/         # Decision engine
├── github/           # GitHub API client
└── index.js          # Main entry point
```

## Development

```bash
# Run tests
npm test

# Lint
npm run lint

# Format
npm run format
```
