'use client';

import { SeverityBadge } from './SeverityBadge';
import { VendorBadge } from './VendorBadge';

export interface RuleData {
  id: string;
  selector?: string;
  vendor?: string | string[];
  category?: string | string[];
  metadata: {
    level: 'error' | 'warning' | 'info';
    obu: string;
    owner: string;
    description?: string;
    remediation?: string;
    security?: {
      cwe?: string[];
      cvssScore?: number;
      cvssVector?: string;
    };
  };
}

interface RuleCardProps {
  rule: RuleData;
  compact?: boolean;
}

/**
 * Map severity levels to our SeverityBadge types.
 */
function mapSeverity(level: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  switch (level) {
    case 'error':
      return 'high';
    case 'warning':
      return 'medium';
    case 'info':
      return 'low';
    default:
      return 'info';
  }
}

/**
 * Get vendor ID from rule vendor field.
 */
function getVendorId(vendor: string | string[] | undefined): string {
  if (!vendor) return 'common';
  if (Array.isArray(vendor)) return vendor[0] || 'common';
  return vendor;
}

/**
 * Get category display text.
 */
function getCategoryDisplay(category: string | string[] | undefined): string {
  if (!category) return 'Uncategorized';
  if (Array.isArray(category)) return category[0] || 'Uncategorized';
  return category;
}

export function RuleCard({ rule, compact = false }: RuleCardProps) {
  const vendorId = getVendorId(rule.vendor);
  const severity = mapSeverity(rule.metadata.level);
  const category = getCategoryDisplay(rule.category);
  const hasSecurityMetadata = rule.metadata.security?.cwe?.length || rule.metadata.security?.cvssScore;

  if (compact) {
    // Use description if available, otherwise fall back to remediation
    const displayText = rule.metadata.description || rule.metadata.remediation;

    return (
      <div className="block p-4 rounded-lg border border-zinc-800 bg-zinc-900/50">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <code className="text-sm font-mono text-cyan-400">{rule.id}</code>
              <SeverityBadge severity={severity} size="sm" />
            </div>
            {displayText && (
              <p className="text-sm text-zinc-400 line-clamp-2">{displayText}</p>
            )}
          </div>
          <VendorBadge vendor={vendorId} size="sm" />
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/50">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-4">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <code className="text-lg font-mono font-semibold text-cyan-400">{rule.id}</code>
            <SeverityBadge severity={severity} />
          </div>
          <div className="flex items-center gap-2 text-sm text-zinc-500">
            <span>{category}</span>
            {rule.selector && (
              <>
                <span className="text-zinc-600">|</span>
                <code className="text-xs bg-zinc-800 px-1.5 py-0.5 rounded">{rule.selector}</code>
              </>
            )}
          </div>
        </div>
        <VendorBadge vendor={vendorId} />
      </div>

      {/* Description */}
      {rule.metadata.description && (
        <p className="text-zinc-300 mb-4">{rule.metadata.description}</p>
      )}

      {/* Remediation */}
      {rule.metadata.remediation && (
        <div className="mb-4">
          <h4 className="text-sm font-semibold text-zinc-400 mb-1">Remediation</h4>
          <p className="text-sm text-zinc-400">{rule.metadata.remediation}</p>
        </div>
      )}

      {/* Security Metadata */}
      {hasSecurityMetadata && (
        <div className="pt-4 border-t border-zinc-800">
          <h4 className="text-sm font-semibold text-zinc-400 mb-2">Security Information</h4>
          <div className="flex flex-wrap gap-3">
            {rule.metadata.security?.cvssScore !== undefined && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-zinc-500">CVSS:</span>
                <span
                  className={`text-sm font-mono ${
                    rule.metadata.security.cvssScore >= 9.0
                      ? 'text-red-400'
                      : rule.metadata.security.cvssScore >= 7.0
                        ? 'text-orange-400'
                        : rule.metadata.security.cvssScore >= 4.0
                          ? 'text-yellow-400'
                          : 'text-green-400'
                  }`}
                >
                  {rule.metadata.security.cvssScore.toFixed(1)}
                </span>
              </div>
            )}
            {rule.metadata.security?.cwe && rule.metadata.security.cwe.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-zinc-500">CWE:</span>
                <div className="flex gap-1">
                  {rule.metadata.security.cwe.map((cwe) => (
                    <a
                      key={cwe}
                      href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs bg-zinc-800 hover:bg-zinc-700 px-1.5 py-0.5 rounded text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      {cwe}
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Metadata Footer */}
      <div className="mt-4 pt-4 border-t border-zinc-800 flex items-center gap-4 text-xs text-zinc-500">
        <span>OBU: {rule.metadata.obu}</span>
        <span>Owner: {rule.metadata.owner}</span>
      </div>
    </div>
  );
}
