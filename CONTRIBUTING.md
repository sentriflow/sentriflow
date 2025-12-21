# Contributing to SentriFlow

Thank you for your interest in contributing to SentriFlow! This document outlines the process for contributing and the agreements required.

## Contributor License Agreement (CLA)

**Before your contribution can be accepted, you must agree to our Contributor License Agreement.**

By submitting a pull request, you agree to the following terms:

1. **Grant of Rights**: You grant the SentriFlow project maintainers a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use, reproduce, modify, sublicense, and distribute your contributions under any license, including proprietary licenses.

2. **Original Work**: You certify that your contribution is your original work, or you have the right to submit it under the terms of this agreement.

3. **No Obligation**: You understand that the maintainers are under no obligation to accept your contribution.

4. **Future Licensing**: You acknowledge that the maintainers may change the project's license in the future, and your contributions may be redistributed under different terms.

To indicate your agreement, include the following line in your pull request description:

```
I have read and agree to the SentriFlow Contributor License Agreement.
```

### Why This CLA?

We use a CLA that allows dual-licensing because SentriFlow uses an **Open Core** business model:

1. **Your code stays open source.** All code in this repository remains Apache-2.0 licensed. Anyone can use, modify, and distribute it.

2. **Contributions fund development.** The CLA grants us rights to *also* use contributions in commercial offerings. Revenue from commercial licenses funds continued open-source development.

3. **Transparent intent.** We're upfront about this model. See [README.md](README.md#business-model-open-core) for the feature breakdown and [LICENSING.md](LICENSING.md) for detailed licensing info.

**If you prefer not to sign this CLA, you can still:**
- Report issues and suggest improvements
- Create external rule packs or tools that integrate with SentriFlow
- Fork under Apache-2.0 (without our commercial extensions)

## How to Contribute

### Reporting Issues

- Search existing issues before creating a new one
- Use a clear, descriptive title
- Include steps to reproduce the issue
- Specify the vendor/platform if relevant

### Submitting Changes

1. Fork the repository
2. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes
4. Run tests and type checking:
   ```bash
   bun test
   bun run type-check
   ```
5. Commit with a descriptive message
6. Push to your fork and open a pull request

### Pull Request Guidelines

- Reference any related issues
- Include the CLA agreement statement
- Ensure all tests pass
- Update documentation if needed
- Keep changes focused and atomic

## Development Setup

```bash
# Install dependencies
bun install

# Run tests
bun test

# Type check
bun run type-check

# Build CLI
bun run build:cli
```

## Code Style

- TypeScript strict mode is enabled
- Use descriptive variable and function names
- Follow existing patterns in the codebase

## Adding New Rules

When contributing validation rules:

1. Place rules in the appropriate vendor file under `packages/rules-default/src/`
2. Follow the rule ID format: `[A-Z][A-Z0-9_-]{2,49}` (e.g., `SEC-001`, `NET-TRUNK-001`)
3. Include metadata: `severity`, `remediation`
4. Add test fixtures in `packages/rules-default/test/fixtures/`

## Adding Vendor Support

When adding a new vendor:

1. Create vendor schema in `packages/core/src/parser/`
2. Add helper functions in `packages/rule-helpers/src/<vendor>/`
3. Add vendor identifier to the supported vendors list
4. Include test configurations

## Questions?

Open an issue with the `question` label if you need clarification on anything.
