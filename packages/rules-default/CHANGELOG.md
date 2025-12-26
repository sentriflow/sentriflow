# Changelog

All notable changes to @sentriflow/rules-default will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-26

### Added
- **Category Metadata** - All rules now have category metadata for grouping (e.g., `authentication`, `encryption`, `network-security`)
- **Typed Tags** - Rules use typed Tag objects with `type`, `label`, `text`, and `score` fields

### Changed
- Rules organized by categories for easier filtering and management
- Tag format changed from string arrays to structured Tag objects

## [0.1.7] - 2025-12-25

### Added
- Category metadata added to all rules
- Support for typed tags in rule definitions

## [0.1.6] - 2025-12-24

### Changed
- Version bump for all workspace packages

## [0.1.5] - 2025-12-22

### Fixed
- Removed JSON-COMMON-002 and JSON-COMMON-003 rules (duplicates)

## [0.1.4] - 2025-12-21

### Fixed
- JSON rules included in vendor-specific lookups
- NET-SEC-001 made Cisco-specific, added VYOS-SEC-001

## [0.1.3] - 2025-12-21

### Added
- GitHub Actions for CI and releases

## [0.1.1] - 2025-12-19

### Fixed
- Normalized package.json fields per npm standards

## [0.1.0] - 2025-12-19

### Added
- Initial release
- 100+ built-in compliance rules
- Support for 12+ network vendors
- Security, operational, and best-practice rules
- CVSS scoring on security rules
