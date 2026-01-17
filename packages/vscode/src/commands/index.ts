/**
 * Commands Index
 *
 * Re-exports all command functions from specialized modules for easy import.
 */

// ============================================================================
// License Commands
// ============================================================================

export {
  cmdEnterLicenseKey,
  cmdClearLicenseKey,
  cmdShowLicenseStatus,
  cmdCheckForUpdates,
  cmdDownloadUpdates,
  cmdReloadPacks,
  cmdShowEncryptedPackStatus,
} from './license';

// ============================================================================
// Scanning Commands
// ============================================================================

export {
  cmdScanFile,
  cmdScanSelection,
  cmdScanBulk,
  cmdSetLanguage,
  cmdToggleDebug,
} from './scanning';

// ============================================================================
// Pack Commands
// ============================================================================

export { cmdShowRulePacks } from './packs';

// ============================================================================
// Rules Commands
// ============================================================================

export {
  cmdDisableTreeItem,
  cmdEnableTreeItem,
  cmdCopyRuleId,
  cmdViewRuleDetails,
  cmdTogglePack,
  cmdToggleVendor,
  cmdDisableRuleById,
  cmdEnableRuleById,
  cmdShowDisabled,
  cmdFilterTagType,
  cmdFilterByCategory,
  cmdSelectVendor,
} from './rules';

// ============================================================================
// Custom Rules Commands
// ============================================================================

export {
  cmdCreateCustomRulesFile,
  cmdCopyRuleToCustom,
  cmdDeleteCustomRule,
  cmdEditCustomRule,
} from './customRules';

// ============================================================================
// Suppression Commands
// ============================================================================

export {
  cmdSuppressOccurrence,
  cmdSuppressRuleInFile,
  cmdRemoveSuppression,
  cmdClearFileSuppressions,
  cmdClearAllSuppressions,
  cmdFocusSuppressionsView,
} from './suppressions';
