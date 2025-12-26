# Changelog

All notable changes to @sentriflow/cli will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-26

### Added
- **JSON Output Enrichment** - JSON output now includes rule category and tags for each result
- **SARIF Category Support** - SARIF output now includes rule category in the `properties` block
- **List Categories Command** - New `--list-categories` option to list all available rule categories with rule counts
- **Category Filter** - New `--category <name>` option to filter `--list-rules` output by category
- **List Format Option** - New `--list-format <format>` option for `--list-rules` (table, json, csv)
- **IP/Subnet Extraction** - New `--extract-ips` and `--copy-ips` options to extract IP addresses from configurations

### Changed
- `--list-rules` output now includes category column
- JSON output includes `category` and `tags` fields on each result object
- IP extraction now includes subnet network addresses in the addresses lists (e.g., `10.0.0.0` from `10.0.0.0/24` appears in `ipv4Addresses`)

## [0.1.7] - 2025-12-24

### Added
- **File Filtering** - New options for filtering files during directory scan:
  - `--glob <pattern>` - Glob pattern for file matching
  - `--extensions <exts>` - File extensions to include
  - `--exclude <patterns>` - Exclude patterns
- **Stdin Support** - Read configuration from stdin with `-` argument

### Changed
- Version bump for all workspace packages

## [0.1.6] - 2025-12-23

### Added
- ESLint 9.x configuration with TypeScript support
- Refactored file loaders for DRY compliance

### Changed
- Documentation clarification: SentriFlow is a compliance checker, not a syntax linter

## [0.1.5] - 2025-12-22

### Fixed
- `__VERSION__` injection in CLI binary builds

## [0.1.4] - 2025-12-21

### Added
- CI workflows for npm publishing with OIDC trusted publishing

### Fixed
- JSON rules included in vendor-specific lookups
- Separate versioning for npm packages and VS Code extension

## [0.1.3] - 2025-12-21

### Added
- GitHub Actions for CI and releases

## [0.1.1] - 2025-12-19

### Fixed
- Normalized package.json fields per npm standards
- Updated README to match actual CLI implementation

## [0.1.0] - 2025-12-19

### Added
- Initial release
- Multi-vendor configuration parsing (Cisco, Juniper, Arista, etc.)
- JSON and SARIF output formats
- Directory scanning with recursive support
- Rule pack loading (JSON and encrypted)
- Configuration file support (`.sentriflowrc`)
