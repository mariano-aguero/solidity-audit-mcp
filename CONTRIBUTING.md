# Contributing to Solidity Audit MCP

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/mariano-aguero/solidity-audit-mcp.git
cd solidity-audit-mcp

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test
```

## Development Workflow

1. **Fork** the repository
2. **Create a branch** for your feature or fix: `git checkout -b feature/my-feature`
3. **Make your changes** following the code style guidelines
4. **Run checks** before committing:
   ```bash
   npm run check  # Runs typecheck, lint, and tests
   ```
5. **Commit** with a descriptive message
6. **Push** to your fork and open a Pull Request

## Code Style

- We use **TypeScript** with strict mode
- Code is formatted with **Prettier**
- Linting is done with **ESLint**
- Run `npm run format` to format code
- Run `npm run lint:fix` to fix linting issues

## Adding New Detectors

### SWC Pattern Detectors

Edit `src/tools/checkVulnerabilities.ts`:

```typescript
{
  id: "SWC-XXX",
  title: "Your Detector Title",
  description: "What this vulnerability is about",
  severity: Severity.HIGH,
  patterns: [/your-regex-pattern/g],
  remediation: "How to fix this issue",
  references: ["https://swcregistry.io/docs/SWC-XXX"],
}
```

### Slither Detector Mappings

Edit `src/analyzers/slither.ts`:

```typescript
"detector-name": {
  title: "Human-readable title",
  description: "What this detector finds",
}
```

### AST-based Detectors (Slang)

Edit `src/analyzers/slangAnalyzer.ts`:

```typescript
// In SECURITY_DETECTORS array
{
  id: "SLANG-XXX",
  title: "Your Detector Title",
  description: "What this vulnerability is about",
  severity: Severity.HIGH,
  recommendation: "How to fix this issue",
}
```

## Testing

- Tests are written with **Vitest**
- Test files are in `__tests__/` directory
- Fixtures (test contracts) are in `__tests__/fixtures/`

```bash
# Run all tests
npm test

# Run specific test file
npx vitest run __tests__/analyzers/slither.test.ts

# Run tests matching pattern
npx vitest run -t "deduplication"

# Run with coverage
npm run test:coverage
```

## Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Include tests for new functionality
- Update documentation if needed
- Ensure all checks pass (CI will verify)

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps for bugs
- Provide system information (Node.js version, OS, etc.)

## Questions?

Feel free to open an issue for any questions about contributing.
