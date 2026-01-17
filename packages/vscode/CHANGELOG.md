# Changelog

All notable changes to SentriFlow Compliance Validator will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.6] - 2026-01-17

### Fixed
- **Bulk Scan Respects Suppressions** - File Explorer "Scan with SentriFlow" now honors existing suppressions
- **Race Condition Prevention** - Suppress commands now validate file path matches active editor

### Changed
- **Activity Bar Reordering** - Suppressions panel moved between IP Addresses and License sections

### Technical
- Proper Disposable pattern for EventEmitters and subscriptions
- Type-safe `diagnostic.code` handling (replaced unsafe casts with type guards)
- Bounds checking for `document.lineAt()` calls

## [0.5.5] - 2026-01-17

### Added
- **Diagnostic Suppression System** - Suppress diagnostics without modifying config files:
  - **Line-level suppression** - Suppress specific occurrences on individual lines
  - **File-level suppression** - Suppress all occurrences of a rule within a file
  - **Hover tooltip actions** - Click "Suppress this occurrence" or "Suppress in file" links
  - **Quick fix menu** - Use Cmd+. / Ctrl+. to access suppression actions
  - **Suppressions TreeView** - View and manage all active suppressions in dedicated panel
  - **Bulk operations** - Clear all suppressions for a file or entire workspace
  - **Persistence** - Suppressions survive VS Code restarts (stored in workspace state)
  - **Content-based tracking** - Line suppressions track content hash, not line numbers
- **Status bar suppression indicator** - Shows active suppression count in tooltip
- **Context key** - `sentriflow.hasSuppressions` available for keyboard shortcut when clauses

### Technical
- New `SuppressionManager` service with CRUD operations and change events
- `SuppressionsTreeProvider` for TreeView display
- `SentriFlowCodeActionProvider` for quick fix menu integration
- Extracted pure helper functions to `suppressionHelpers.ts` for testability

## [0.5.4] - 2026-01-16

### Added
- **Per-Document Vendor Override** - Manual vendor selection now persists per file:
  - Select vendor via status bar or command palette → applies only to current file
  - Switching to another file uses auto-detection (unless that file also has an override)
  - Returning to a file with override restores your vendor choice
  - Status bar shows "(override)" indicator when per-document override is active
  - Overrides persist across VS Code sessions (stored in workspace state)

### Changed
- **Immediate Status Bar Updates** - Vendor selection now updates status bar instantly without requiring editor switch

## [0.5.3] - 2026-01-16

### Fixed
- **Manual Vendor Selection Ignored** - Fixed bug where manually selecting a vendor was overridden by auto-detection. The scanner was passing vendor ID as a raw string instead of converting it to a VendorSchema object, causing the parser to fall back to default behavior.

## [0.5.2] - 2026-01-13

### Added
- **Multi-Tier Pack Support** - Professional and Enterprise licenses can now decrypt packs from all entitled tiers:
  - Professional: access to both Basic and Professional rule packs
  - Enterprise: access to Basic, Professional, and Enterprise rule packs
  - Automatic TMK selection based on pack tier header

### Changed
- **Tier Naming** - Renamed 'Community' tier to 'Basic' for clarity

## [0.5.0] - 2026-01-11

### Changed
- **Major Internal Refactoring** - Modularized extension.ts (5,200+ lines) into organized modules:
  - `commands/` - License, scanning, rules, packs, and custom rules commands (6 modules)
  - `services/` - Scanner, rule manager, and pack manager
  - `handlers/` - Event handlers (editor, config, file watcher)
  - `state/` - Centralized singleton state management
  - `ui/` - Status bar management
  - `utils/` - Helper functions
- **Improved Code Organization** - All 29+ command handlers extracted to specialized modules
- **Better Maintainability** - No circular dependencies, cleaner separation of concerns
- **Custom Rules System Directory** - Custom rules now stored in system directory instead of workspace:
  - Unix/macOS: `~/.sentriflow/rules/`
  - Windows: `%USERPROFILE%\.sentriflow\rules\`
  - Rules are shared across all workspaces

### Fixed
- **Pack Toggle Icon Not Updating** - Fixed DEFAULT_PACK_NAME mismatch that caused enable/disable toggle to not update tree view icon
- **Custom Rules Pack Toggle** - Custom Rules pack now properly responds to enable/disable toggle with correct icon state
- **Custom Rules Pack Visibility** - Pack now shows as disabled instead of disappearing when custom rules are disabled

### Technical
- Extension.ts reduced from 5,200+ to ~1,200 lines
- Bundle size unchanged (within 1.5% of previous version)
- All 1,205 tests passing
- TypeScript strict mode compliance verified
- Added DRY constants for system paths (SENTRIFLOW_HOME, DEFAULT_RULES_DIRECTORY, CACHE_DIRECTORY) in core package

## [0.4.0] - 2026-01-11

### Added
- **Custom JSON Rules** - Create organization-specific validation rules without TypeScript:
  - Load custom rules from `.sentriflow/rules/*.json` files in your workspace
  - Full JSON schema validation with IntelliSense support
  - Auto-completion for vendors, properties, check types, and helper functions
  - File watching with live reload on changes
  - Custom rules override built-in rules with the same ID
  - Duplicate rule ID warnings with detailed output panel
  - Debounced file watcher for rapid saves
- **Custom Rules Management Commands**:
  - "Create Custom Rules File" - Create new rule file from command palette or tree view title bar
  - "Copy Rule to Custom" - Copy any rule to custom rules file (context menu)
  - "Edit Custom Rule" - Open source JSON file and navigate to rule definition (context menu)
  - "Delete Custom Rule" - Remove rule from source file with confirmation (context menu)
- **Enable/Disable Custom Rules** - Toggle custom rules on/off with inline icons, same as built-in rules
- **Smart Rule Copying** - When copying a custom rule, preserves the full JSON including check logic; built-in rules get a template placeholder

### Fixed
- **Custom Rules Not Applied Immediately** - When editing a custom rules JSON file, config files are now rescanned immediately instead of waiting until you switch editors
- **Blocked Packs Still Scanning** - Packs in `blockedPacks` setting were not being excluded from scans
- **Custom Rules Pack Disappearing** - Pack no longer disappears from tree when all custom rules are disabled
- **Disabled Custom Rules Not Tracked** - Custom rules now properly show disabled state in tree view

### Security
- **SEC-001: XSS Prevention** - Removed `isTrusted` and `supportHtml` from HoverProvider markdown to prevent XSS
- **SEC-002: Secure Nonce** - Replaced `Math.random()` with `crypto.randomBytes()` for CSP nonce generation

### Changed
- **DRY-001: Rule Sorting** - Extracted `compareRulesByLevel` utility to eliminate duplicate sorting logic
- **DRY-002: Comma Parsing** - Extracted `parseCommaSeparated` utility for disabled rules parsing
- **PERF-001: Tags Caching** - Added caching for `getAllTags()` to improve tree view performance

### New Settings
- `sentriflow.customRules.enabled` - Enable/disable custom rules loading (default: true)
- `sentriflow.customRules.disabledRules` - List of custom rule IDs to disable

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
