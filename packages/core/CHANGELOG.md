# Changelog

All notable changes to @sentriflow/core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-26

### Added
- **IRule.category Field** - Rules can now specify a category (single string or array) for grouping and filtering
- **Typed Tags** - Tag interface now includes `type` field with values: `security`, `operational`, `compliance`, `general`
- **IP/Subnet Extraction** - New `extractIPs()` function to extract IP addresses and subnets from configuration text
- **Tag Score Support** - Tags can now include optional `score` (0-10) and `text` description fields
- **includeSubnetNetworks Option** - New `ExtractOptions.includeSubnetNetworks` to include subnet network addresses (e.g., `10.0.0.0` from `10.0.0.0/24`) in the addresses lists

### Changed
- Tag interface expanded from simple string to structured object with `type`, `label`, `text`, `score`

## [0.1.7] - 2025-12-25

### Added
- **Generalized Tags** - Tags converted from string arrays to typed Tag objects
- **IP Extraction Module** - New module for extracting IP addresses from configurations

## [0.1.6] - 2025-12-24

### Changed
- Version bump for all workspace packages

## [0.1.5] - 2025-12-22

### Added
- PackProvider interface for cloud licensing extension
- Open Core transparency documentation

## [0.1.4] - 2025-12-21

### Fixed
- JSON rules included in vendor-specific lookups

## [0.1.3] - 2025-12-21

### Added
- GitHub Actions for CI and releases

## [0.1.1] - 2025-12-19

### Fixed
- Normalized package.json fields per npm standards

## [0.1.0] - 2025-12-19

### Added
- Initial release
- Multi-vendor configuration parsing
- AST-based rule engine
- Support for 12+ network vendors
- Rule result types and interfaces
- Vendor detection from configuration content
