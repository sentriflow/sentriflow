# Changelog

All notable changes to SentriFlow Compliance Validator will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Added
- **Activity Bar with Rules TreeView** - Dedicated SentriFlow icon in the Activity Bar with a hierarchical view of all rules organized by Pack > Vendor > Rule
- **1-Click Rule Toggle** - Enable/disable rules, vendors, or entire packs directly from the TreeView with inline toggle icons
- **Settings Webview Panel** - Visual configuration interface for all settings without editing JSON
- **Direct Commands for Rule Management**:
  - `SentriFlow: Disable Rule...` - Fuzzy search to find and disable any rule
  - `SentriFlow: Enable Disabled Rule...` - Re-enable previously disabled rules
  - `SentriFlow: Enable/Disable Pack...` - Toggle entire rule packs
  - `SentriFlow: Enable/Disable Vendor...` - Toggle vendors within packs
  - `SentriFlow: Show All Disabled Items` - View summary of all disabled packs, vendors, and rules
  - `SentriFlow: Show Rules Panel` - Focus the Rules TreeView
- **Enhanced Status Bar Tooltips** - Rich markdown tooltips with:
  - Clickable links to common actions
  - Disabled rules count
  - Current vendor and scan status
- **Context Menu Actions** - Right-click on TreeView items for:
  - Toggle Enable/Disable
  - Copy Rule ID (for rules)
  - View Details

### Changed
- Rule management is now accessible in 1-2 clicks instead of 5+ clicks through nested menus
- Settings can be configured visually without editing `settings.json`
- TreeView automatically refreshes when settings change

## [0.1.7] - 2024-12-24

### Fixed
- Support comma-separated rule IDs in `disabledRules` setting

### Changed
- Version bump for all workspace packages

## [0.1.6] - 2024-11-XX

### Changed
- Documentation clarification: SentriFlow is a compliance validator, not a syntax linter

## [0.1.5] - 2024-10-XX

### Changed
- Minor changes and version bump

## [0.1.4] - 2024-10-XX

### Added
- Initial public release
- Real-time compliance validation for network configurations
- Support for 12+ network vendors (Cisco IOS/NX-OS, Juniper, Arista, Aruba, Fortinet, Palo Alto, and more)
- 100+ built-in compliance rules
- Auto-detection of vendor from configuration content
- Rule pack registration API for third-party extensions
- SARIF export support
- Status bar indicators for scan results, vendor, and active rules
- QuickPick menus for vendor selection and pack management

## [0.1.0] - 2024-XX-XX

### Added
- Initial development release
