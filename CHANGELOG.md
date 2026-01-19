# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

- **BREAKING**: Removed legacy pack loading arguments:
  - `--encrypted-pack <path...>` - Use `--pack <path...>` instead
  - `--grx2-pack <path...>` - Use `--pack <path...>` instead
  - `--rule-pack <path>` - Use `--pack <path>` instead
  - `--strict-grx2` - Use `--strict-packs` instead

### Added

- **Cloud Licensing Integration** (VS Code & CLI):
  - 24-hour offline mode with entitlement caching for uninterrupted scanning
  - Cloud connection status indicator in VS Code License panel (online/offline with cache time remaining)
  - Graceful degradation when cloud API is unreachable - uses cached entitlements automatically
  - "Get License" link in VS Code sidebar for easy access to licensing page
  - CLI fallback commands (`activate`, `update`, `offline`, `license`) with helpful installation message when `@sentriflow/licensing` not installed

- Unified `--pack <path...>` argument that auto-detects pack format from magic bytes
  - Supports GRX2 (.grx2) and unencrypted (.js/.ts) packs
  - Format is detected from file content, not extension
  - Multiple packs can be specified with multiple `--pack` flags
- Format-based priority assignment:
  - Unencrypted packs: priority 100 + order index
  - GRX2 packs: priority 300 + order index
- `--strict-packs` now applies uniformly to all pack types

### Changed

- `--strict-packs` now applies to GRX2 and unencrypted packs

### Deprecated

- **GRPX format** (`.grpx`) - GRPX files are now treated as unencrypted format. Use GRX2 (`.grx2`) for encrypted packs.
- Pack loading summary now shows "Packs: X of Y loaded (Z rules)" instead of format-specific messages

### Migration Guide

Update your CLI commands:

```bash
# Before (0.2.x)
sentriflow --grx2-pack rules.grx2 --license-key $KEY config.cfg
sentriflow --rule-pack rules.js config.cfg

# After (0.3.0+)
sentriflow --pack rules.grx2 --license-key $KEY config.cfg
sentriflow --pack rules.js config.cfg

# Multiple packs
sentriflow --pack a.grx2 --pack b.grx2 --pack c.js --license-key $KEY config.cfg

# Strict mode (applies to all packs)
sentriflow --pack rules.grx2 --strict-packs --license-key $KEY config.cfg
```
