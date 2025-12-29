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

- Unified `--pack <path...>` argument that auto-detects pack format from magic bytes
  - Supports GRX2 (.grx2), GRPX (.grpx), and unencrypted (.js/.ts) packs
  - Format is detected from file content, not extension
  - Multiple packs can be specified with multiple `--pack` flags
- Format-based priority assignment:
  - Unencrypted packs: priority 100 + order index
  - GRPX packs: priority 200 + order index
  - GRX2 packs: priority 300 + order index
- `--strict-packs` now applies uniformly to all pack types

### Changed

- `--strict-packs` now applies to GRX2, GRPX, and unencrypted packs (previously only GRPX)
- Pack loading summary now shows "Packs: X of Y loaded (Z rules)" instead of format-specific messages

### Migration Guide

Update your CLI commands:

```bash
# Before (0.2.x)
sentriflow --grx2-pack rules.grx2 --license-key $KEY config.cfg
sentriflow --encrypted-pack rules.grpx --license-key $KEY config.cfg
sentriflow --rule-pack rules.js config.cfg

# After (0.3.0+)
sentriflow --pack rules.grx2 --license-key $KEY config.cfg
sentriflow --pack rules.grpx --license-key $KEY config.cfg
sentriflow --pack rules.js config.cfg

# Multiple packs (mixed formats)
sentriflow --pack a.grx2 --pack b.grpx --pack c.js --license-key $KEY config.cfg

# Strict mode (applies to all packs)
sentriflow --pack rules.grx2 --strict-packs --license-key $KEY config.cfg
```
