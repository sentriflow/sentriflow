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
} from './types';
