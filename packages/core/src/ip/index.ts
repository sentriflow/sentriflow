// packages/core/src/ip/index.ts

export {
  extractIPSummary,
  isValidIPv4,
  isValidIPv6,
  isValidSubnet,
  normalizeIPv4,
  normalizeIPv6,
  compareIPv4,
  compareIPv6,
  sortIPv4Addresses,
  sortIPv6Addresses,
  sortSubnets,
} from './extractor';

export type {
  IPAddressType,
  IPAddress,
  Subnet,
  IPSummary,
  IPCounts,
  ExtractOptions,
  InputValidationErrorCode,
} from './types';

export { InputValidationError, DEFAULT_MAX_CONTENT_SIZE } from './types';

// IP Classification and Filtering
export {
  classifyIPv4,
  classifyIPv6,
  classifyIPv4Subnet,
  classifyIPv6Subnet,
  filterIPv4Addresses,
  filterIPv6Addresses,
  filterIPv4Subnets,
  filterIPv6Subnets,
  filterIPSummary,
  DEFAULT_FILTER_OPTIONS,
} from './classifier';

export type { IPClassification, IPFilterOptions } from './classifier';
