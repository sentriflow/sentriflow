# Licensing

SentriFlow uses an **Open Core** model with clear separation between open source and commercial components.

## This Repository

All code in this repository is licensed under the **Apache License 2.0**.

```
Copyright 2025 SentriFlow Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

See [LICENSE](LICENSE) for the full text.

## Package Breakdown

| Package | License | Description |
|---------|---------|-------------|
| `@sentriflow/core` | Apache-2.0 | Core scanning engine, parser, rule engine |
| `@sentriflow/cli` | Apache-2.0 | Command-line interface |
| `@sentriflow/rules-default` | Apache-2.0 | Default validation rules |
| `sentriflow-vscode` | Apache-2.0 | VS Code extension |
| `@sentriflow/licensing` | Proprietary | Cloud licensing (not in this repo) |

## Rule Packs

| Type | License | Notes |
|------|---------|-------|
| Default rules (`packages/rules-default`) | Apache-2.0 | Included in this repo |
| Custom JSON/TypeScript rules | Your choice | You own your rules |
| Premium rule packs (`.grpx`) | Proprietary | Sold separately, encrypted |

## Commercial Extensions

The optional `@sentriflow/licensing` package is **proprietary software** distributed separately. It is not included in this repository.

Commercial features include:
- Premium vendor-specific rule packs
- Cloud-based pack updates and versioning
- Online license management
- Enterprise support

Visit [sentriflow.com.au](https://sentriflow.com.au) for commercial licensing.

## Contributor License Agreement

Contributors agree to a CLA that grants SentriFlow maintainers rights to use contributions under any license, including proprietary licenses.

**Your contributions remain Apache-2.0 in this repository.** The CLA allows us to *also* include contributions in commercial offerings, funding continued open-source development.

See [CONTRIBUTING.md](CONTRIBUTING.md) for full CLA terms and the reasoning behind them.

## Third-Party Dependencies

This project uses third-party open-source libraries. See `package.json` files in each package for dependency lists. All dependencies are compatible with Apache-2.0.

## Questions

For licensing questions, open an issue with the `licensing` label or contact us at the commercial site.
