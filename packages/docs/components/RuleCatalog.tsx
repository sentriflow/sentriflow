'use client';

import { useState, useMemo, useCallback } from 'react';
import { RuleCard, type RuleData } from './RuleCard';

interface RuleCatalogProps {
  rules: RuleData[];
}

type SeverityFilter = 'all' | 'error' | 'warning' | 'info';
type SortBy = 'id' | 'severity' | 'vendor' | 'category';

/**
 * Get unique values from a field that can be string or string[].
 */
function getUniqueValues(rules: RuleData[], getField: (rule: RuleData) => string | string[] | undefined): string[] {
  const values = new Set<string>();
  for (const rule of rules) {
    const value = getField(rule);
    if (value === undefined) {
      values.add('common');
    } else if (Array.isArray(value)) {
      for (const v of value) {
        values.add(v);
      }
    } else {
      values.add(value);
    }
  }
  return Array.from(values).sort();
}

/**
 * Check if a rule matches a field filter.
 */
function matchesField(fieldValue: string | string[] | undefined, filterValue: string): boolean {
  if (filterValue === 'all') return true;
  if (fieldValue === undefined) return filterValue === 'common';
  if (Array.isArray(fieldValue)) return fieldValue.includes(filterValue);
  return fieldValue === filterValue;
}

/**
 * Severity sort order.
 */
const severityOrder: Record<string, number> = {
  error: 0,
  warning: 1,
  info: 2,
};

export function RuleCatalog({ rules }: RuleCatalogProps) {
  // Filter state
  const [search, setSearch] = useState('');
  const [vendor, setVendor] = useState('all');
  const [severity, setSeverity] = useState<SeverityFilter>('all');
  const [category, setCategory] = useState('all');
  const [sortBy, setSortBy] = useState<SortBy>('id');

  // Get unique filter options
  const vendors = useMemo(() => ['all', ...getUniqueValues(rules, (r) => r.vendor)], [rules]);
  const categories = useMemo(() => ['all', ...getUniqueValues(rules, (r) => r.category)], [rules]);

  // Filter and sort rules
  const filteredRules = useMemo(() => {
    let result = rules;

    // Search filter
    if (search) {
      const searchLower = search.toLowerCase();
      result = result.filter(
        (r) =>
          r.id.toLowerCase().includes(searchLower) ||
          r.metadata.description?.toLowerCase().includes(searchLower) ||
          r.metadata.remediation?.toLowerCase().includes(searchLower)
      );
    }

    // Vendor filter
    if (vendor !== 'all') {
      result = result.filter((r) => matchesField(r.vendor, vendor));
    }

    // Severity filter
    if (severity !== 'all') {
      result = result.filter((r) => r.metadata.level === severity);
    }

    // Category filter
    if (category !== 'all') {
      result = result.filter((r) => matchesField(r.category, category));
    }

    // Sort
    result = [...result].sort((a, b) => {
      switch (sortBy) {
        case 'id':
          return a.id.localeCompare(b.id);
        case 'severity':
          return (severityOrder[a.metadata.level] ?? 3) - (severityOrder[b.metadata.level] ?? 3);
        case 'vendor': {
          const vendorA = (Array.isArray(a.vendor) ? a.vendor[0] : a.vendor) ?? 'common';
          const vendorB = (Array.isArray(b.vendor) ? b.vendor[0] : b.vendor) ?? 'common';
          return vendorA.localeCompare(vendorB);
        }
        case 'category': {
          const catA = (Array.isArray(a.category) ? a.category[0] : a.category) ?? 'Uncategorized';
          const catB = (Array.isArray(b.category) ? b.category[0] : b.category) ?? 'Uncategorized';
          return catA.localeCompare(catB);
        }
        default:
          return 0;
      }
    });

    return result;
  }, [rules, search, vendor, severity, category, sortBy]);

  // Reset filters
  const resetFilters = useCallback(() => {
    setSearch('');
    setVendor('all');
    setSeverity('all');
    setCategory('all');
    setSortBy('id');
  }, []);

  const hasActiveFilters = search || vendor !== 'all' || severity !== 'all' || category !== 'all';

  // Common select styles with dark dropdown background
  const selectStyle = {
    colorScheme: 'dark',
  } as const;

  return (
    <div>
      {/* Search and Filters */}
      <div className="mb-8 space-y-5">
        {/* Search Input */}
        <div className="relative">
          <input
            type="text"
            placeholder="Search rules by ID, description, or remediation..."
            value={search}
            onChange={(e) => setSearch((e.target as HTMLInputElement).value)}
            className="w-full px-5 py-4 pl-12 rounded-xl bg-zinc-800/80 border-2 border-zinc-700 focus:border-cyan-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 text-white text-base placeholder-zinc-400 shadow-lg"
          />
          <svg
            className="absolute left-4 top-1/2 -translate-y-1/2 text-zinc-400"
            width={20}
            height={20}
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap gap-4">
          {/* Vendor Filter */}
          <select
            value={vendor}
            onChange={(e) => setVendor((e.target as HTMLSelectElement).value)}
            className="px-4 py-2.5 rounded-lg bg-zinc-800 border-2 border-zinc-700 hover:border-zinc-600 focus:border-cyan-500 focus:outline-none text-zinc-200 text-sm font-medium cursor-pointer"
            style={selectStyle}
          >
            <option value="all">All Vendors</option>
            {vendors.slice(1).map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>

          {/* Severity Filter */}
          <select
            value={severity}
            onChange={(e) => setSeverity((e.target as HTMLSelectElement).value as SeverityFilter)}
            className="px-4 py-2.5 rounded-lg bg-zinc-800 border-2 border-zinc-700 hover:border-zinc-600 focus:border-cyan-500 focus:outline-none text-zinc-200 text-sm font-medium cursor-pointer"
            style={selectStyle}
          >
            <option value="all">All Severities</option>
            <option value="error">Error (High)</option>
            <option value="warning">Warning (Medium)</option>
            <option value="info">Info (Low)</option>
          </select>

          {/* Category Filter */}
          <select
            value={category}
            onChange={(e) => setCategory((e.target as HTMLSelectElement).value)}
            className="px-4 py-2.5 rounded-lg bg-zinc-800 border-2 border-zinc-700 hover:border-zinc-600 focus:border-cyan-500 focus:outline-none text-zinc-200 text-sm font-medium cursor-pointer"
            style={selectStyle}
          >
            <option value="all">All Categories</option>
            {categories.slice(1).map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>

          {/* Sort By */}
          <select
            value={sortBy}
            onChange={(e) => setSortBy((e.target as HTMLSelectElement).value as SortBy)}
            className="px-4 py-2.5 rounded-lg bg-zinc-800 border-2 border-zinc-700 hover:border-zinc-600 focus:border-cyan-500 focus:outline-none text-zinc-200 text-sm font-medium cursor-pointer"
            style={selectStyle}
          >
            <option value="id">Sort by ID</option>
            <option value="severity">Sort by Severity</option>
            <option value="vendor">Sort by Vendor</option>
            <option value="category">Sort by Category</option>
          </select>

          {/* Reset Button */}
          {hasActiveFilters && (
            <button
              onClick={resetFilters}
              className="px-4 py-2.5 rounded-lg bg-zinc-700 hover:bg-zinc-600 text-zinc-200 hover:text-white text-sm font-medium transition-colors"
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Results Summary */}
      <div className="mb-6 text-sm text-zinc-400 font-medium">
        Showing {filteredRules.length} of {rules.length} rules
        {hasActiveFilters && ' (filtered)'}
      </div>

      {/* Rules Grid */}
      {filteredRules.length > 0 ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {filteredRules.map((rule) => (
            <RuleCard key={rule.id} rule={rule} compact />
          ))}
        </div>
      ) : (
        <div className="text-center py-12 text-zinc-500">
          <p className="text-lg mb-2">No rules found</p>
          <p className="text-sm">Try adjusting your filters or search query</p>
        </div>
      )}
    </div>
  );
}
