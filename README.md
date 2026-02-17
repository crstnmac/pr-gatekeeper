# PR Gatekeeper - Prototype

Intelligent PR triage for enterprise teams. Built with TypeScript.

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

# Run (development mode with tsx)
npm run dev -- --owner <owner> --repo <repo> --pr <pr-number>

# Build
npm run build

# Run (production mode)
npm run start:build -- --owner <owner> --repo <repo> --pr <pr-number>
```

## Architecture

```
src/
├── blast-radius/     # Impact calculation
├── security/         # Security scanning
├── policy/           # Policy engine
├── decision/         # Decision engine
├── github/           # GitHub API client
├── audit/            # Audit logging
├── types.ts          # Type definitions
├── gatekeeper/       # Main orchestration
└── index.ts          # Main entry point
```

## Development

```bash
# Run in development mode (tsx)
npm run dev -- [args]

# Type checking
npm run type-check

# Build TypeScript
npm run build

# Run tests
npm test

# Lint
npm run lint

# Format
npm run format
```

## TypeScript

This project uses TypeScript with strict mode enabled:
- Full type safety
- Interface definitions for all data structures
- Better IDE support
- Catch errors at compile time
