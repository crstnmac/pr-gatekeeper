export function parseArgs() {
  const args = process.argv.slice(2);

  const parsed = {
    owner: null,
    repo: null,
    pr: null,
    config: null,
    verbose: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '--owner':
      case '-o':
        parsed.owner = args[++i];
        break;
      case '--repo':
      case '-r':
        parsed.repo = args[++i];
        break;
      case '--pr':
      case '-p':
        parsed.pr = args[++i];
        break;
      case '--config':
      case '-c':
        parsed.config = args[++i];
        break;
      case '--verbose':
      case '-v':
        parsed.verbose = true;
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
      default:
        throw new Error(`Unknown argument: ${arg}`);
    }
  }

  // Validate required arguments
  if (!parsed.owner || !parsed.repo || !parsed.pr) {
    console.error('Error: Missing required arguments\n');
    printHelp();
    process.exit(1);
  }

  return parsed;
}

function printHelp() {
  console.log(`
PR Gatekeeper - Intelligent PR Triage

USAGE:
  npm start -- --owner <owner> --repo <repo> --pr <pr-number> [options]

REQUIRED:
  --owner, -o    Repository owner (user or org)
  --repo, -r     Repository name
  --pr, -p       Pull request number

OPTIONS:
  --config, -c   Path to config file (default: ./config.json)
  --verbose, -v  Enable verbose output
  --help, -h     Show this help message

EXAMPLES:
  npm start -- --owner octocat --repo hello-world --pr 42
  npm start -- -o myorg -r myrepo -p 123 --verbose
  npm start -- --owner octocat --repo hello-world --pr 42 --config /path/to/config.json
`);
}
