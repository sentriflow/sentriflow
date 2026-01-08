# Changelog

All notable changes to SentriFlow Compliance Validator will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.6] - 2025-01-08

### Added
- **Persistent Debug Setting** - New `sentriflow.debug` setting that persists across window reloads:
  - Enable via Settings UI or "Toggle Debug Logging" command
  - Setting and command stay synchronized
  - Output channel auto-opens when debug is enabled

### Fixed
- **Entitled Feeds Display** - License panel now shows entitled feeds section with load status and source indicators

## [0.3.5] - 2025-01-06

### Added
- **Bulk Scanning from Explorer** - Right-click context menu support for scanning folders and multiple files:
  - Scan entire folders recursively for network configuration files
  - Multi-select support for scanning multiple files at once
  - Progress notification with cancel button
  - Results displayed in Problems panel with summary toast
  - Supports 15 config file extensions (.cfg, .conf, .ios, .junos, .nx-os, etc.)

### Changed
- **External Packs Settings UI** - Improved settings interface:
  - Renamed "Encrypted Packs" to "External Packs" throughout settings
  - Added directory picker (Browse button) for packs directory
  - Added blocked packs input field to External Packs section
  - Blocked packs now reload immediately on setting change

## [0.3.2] - 2025-12-29

### Added
- **IP Address Range Filtering** - Filter out special IP ranges from extraction results:
  - New `sentriflow.ipAddresses.filterSpecialRanges` setting
  - Toggle in Settings webview panel
  - When enabled, filters out loopback, multicast, reserved, broadcast, and documentation ranges
  - Keeps only public, private, and CGNAT addresses

## [0.3.0] - 2025-12-29

### Added
- **Unified Pack Loading** - Support for multiple pack formats (GRX2 + GRPX):
  - Automatic format detection based on file content
  - Format indicator [GRX2]/[GRPX] shown in License panel
  - Shared validation across CLI and VS Code extension

### Fixed
- **Tags View Pack Filtering** - Tags section now only shows rules from enabled packs, properly respecting `enableDefaultRules` and `blockedPacks` settings

### Changed
- **BREAKING**: VS Code settings renamed from `sentriflow.encryptedPacks.*` to `sentriflow.packs.*`

## [0.2.3] - 2025-12-27

### Added
- **Platform-Aware Pack Paths** - Encrypted pack directory now uses platform-aware paths:
  - Unix/macOS: `~/.sentriflow/packs`
  - Windows: `%USERPROFILE%\.sentriflow\packs`
  - Leave setting empty to use platform default
- **Enhanced Debug Logging** - Debug mode now shows API URL and machine ID for troubleshooting
- **Machine ID Verification** - License bound to a specific machine now verified at load time

### Fixed
- **Portable License Loading** - Fixed TMK unwrap failure for portable licenses by using `portable-pack` convention for machine ID
- **TreeView Unique IDs** - Fixed "Data tree node not found" error by adding unique IDs to LicenseTreeItem
- **License Info Visibility** - License information now visible even when encrypted packs are disabled
- **Logging Separation** - Split logging into `logInfo()` (always visible) and `log()` (debug only) for cleaner output

## [0.2.2] - 2025-12-26

### Added
- **IP Addresses TreeView** - New dedicated "IP Addresses" panel in the Activity Bar that automatically extracts and displays all IP addresses and subnets from the current file:
  - Organized by type: IPv4 Addresses, IPv6 Addresses, IPv4 Subnets, IPv6 Subnets
  - Network addresses from subnets are included in the Addresses lists (e.g., `10.0.0.0` from `10.0.0.0/24` appears in IPv4 Addresses)
  - Click any IP to copy it to clipboard
  - "Copy All" button in the view title to copy all IPs at once
  - "Copy All" button on each category to copy only that category (e.g., just IPv4 Subnets)
  - Automatically updates when switching between files
- **Hover Provider** - Hovering over diagnostics now shows rich tooltips with:
  - Rule ID and category with severity icons
  - All typed tags with their types and scores
  - Full description and remediation guidance
  - OBU and owner information
- **Multi-Diagnostic Hover** - When multiple diagnostics are stacked on the same line, hovering now shows details for ALL violations, not just the first one
- **Category Filter Command** - New `SENTRIFLOW: Filter Diagnostics by Category` command to filter diagnostics by rule category
- **Enhanced Diagnostic Messages** - Diagnostic messages now include rule ID and category: `[RULE-ID] (category) message`

### Changed
- Diagnostic format updated to include category information for better filtering
- IP address commands moved from context menu to dedicated Activity Bar panel for better UX

### Removed
- `Copy IP Addresses` and `Show IP Addresses` context menu items (replaced by IP Addresses TreeView)

## [0.2.1] - 2025-12-25

### Added
- **Typed Tags** - Tags now have a `type` field for multi-dimensional categorization:
  - `security` - Security vulnerabilities and hardening (e.g., vlan-hopping, access-control)
  - `operational` - Operations and monitoring (e.g., logging, metrics)
  - `compliance` - Compliance frameworks (e.g., nist-ac-3, pci-dss)
  - `general` - General categorization (e.g., best-practice, deprecated)
- **Tag Type Filter** - New `sentriflow.tagTypeFilter` setting to filter tags by type in the tree view
- **Filter Tags Command** - New `SENTRIFLOW: Filter Tags by Type...` command for quick filtering via Command Palette
- **Tag Tooltips** - Hovering over a tag in the tree view now shows its type and score (if set)
- **Settings Panel Update** - Tag Type Filter dropdown added to the Settings webview panel

### Changed
- "By Security Tag" section renamed to "By Tag" to reflect support for all tag types
- Tags are now displayed with their type in tooltips (e.g., `[security]`, `[operational]`)

## [0.2.0] - 2025-12-25

### Added
- **Activity Bar with Rules TreeView** - Dedicated SentriFlow icon in the Activity Bar with a hierarchical view of all rules organized by Pack > Vendor > Rule
- **Security Tags Section** - New collapsible "By Tag" section in the TreeView that groups rules by their typed tags (e.g., `vlan-hopping`, `access-control`, `network-security`). Rules with multiple tags appear under each tag they belong to.
- **Flexible Tree Grouping** - Configure how rules are organized in the tree view:
  - `Vendor > Rules` (default)
  - `Category > Rules`
  - `Category > Vendor > Rules`
  - `Vendor > Category > Rules`
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
- **New Settings**:
  - `sentriflow.treeGrouping` - Choose how to organize rules in the tree view
  - `sentriflow.showTagsSection` - Toggle the "By Tag" section visibility

### Changed
- Rule management is now accessible in 1-2 clicks instead of 5+ clicks through nested menus
- Settings can be configured visually without editing `settings.json`
- TreeView automatically refreshes when settings change
- Categories and security tags are now treated as separate concepts (tags no longer used as fallback for missing categories)

## [0.1.7] - 2025-12-24

### Fixed
- Support comma-separated rule IDs in `disabledRules` setting

### Changed
- Version bump for all workspace packages

## [0.1.6] - 2025-12-22

### Changed
- Documentation clarification: SentriFlow is a compliance validator, not a syntax linter

## [0.1.5] - 2025-12-21

### Added
- CI workflows for VS Code Marketplace publishing

### Fixed
- Skip scanning virtual documents from git extensions

## [0.1.4] - 2025-12-20

### Added
- Setting to disable individual rules
- Comma-separated values support in `disabledRules` setting

### Changed
- Updated README with actual settings and features

## [0.1.3] - 2025-12-20

### Changed
- Build system switched to Bun
- Fixed CLI usage examples in documentation

## [0.1.1] - 2025-12-19

### Fixed
- Normalized package.json fields per npm standards

## [0.1.0] - 2025-12-19

### Added
- Initial release
- Real-time compliance validation for network configurations
- Support for 12+ network vendors (Cisco IOS/NX-OS, Juniper, Arista, Aruba, Fortinet, Palo Alto, and more)
- 100+ built-in compliance rules
- Auto-detection of vendor from configuration content
- Rule pack registration API for third-party extensions
- SARIF export support
- Status bar indicators for scan results, vendor, and active rules
- QuickPick menus for vendor selection and pack management
