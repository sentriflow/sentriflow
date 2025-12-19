// packages/rules-default/test/paloalto-rules.test.ts

import { describe, test, expect } from 'bun:test';
import { SchemaAwareParser, PaloAltoPANOSSchema, RuleEngine } from '@sentriflow/core';
import {
  allPaloAltoRules,
  HostnameRequired,
  NtpRequired,
  DnsRequired,
  ManagementAccessRestricted,
  LoginBannerRequired,
  SecurityRuleLogging,
  SecurityProfileRequired,
  NoAnyApplication,
  NoOverlyPermissiveRules,
  SecurityRuleDescription,
  ZoneProtectionRequired,
  WildfireRequired,
  UrlFilteringRequired,
  AntiVirusRequired,
  AntiSpywareRequired,
  VulnerabilityProtectionRequired,
  NatRuleDescription,
  HARecommended,
} from '../src/paloalto/panos-rules';

const parsePanos = (config: string) => {
  const parser = new SchemaAwareParser({ vendor: PaloAltoPANOSSchema });
  return parser.parse(config);
};

const runRule = (rule: typeof HostnameRequired, config: string) => {
  const ast = parsePanos(config);
  const engine = new RuleEngine();
  return engine.run(ast, [rule]);
};

// ============================================================================
// System Rules Tests
// ============================================================================

describe('Palo Alto System Rules', () => {
  describe('PAN-SYS-001: Hostname Required', () => {
    test('should fail when hostname is missing', () => {
      const config = `deviceconfig {
    system {
        ip-address 192.168.1.1;
    }
}`;
      const results = runRule(HostnameRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('hostname');
    });

    test('should pass when hostname is configured', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
        ip-address 192.168.1.1;
    }
}`;
      const results = runRule(HostnameRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-SYS-002: NTP Required', () => {
    test('should fail when NTP is not configured', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
    }
}`;
      const results = runRule(NtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('NTP');
    });

    test('should pass when NTP servers are configured', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
        ntp-servers {
            primary-ntp-server {
                ntp-server-address 0.pool.ntp.org;
            }
        }
    }
}`;
      const results = runRule(NtpRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-SYS-003: DNS Required', () => {
    test('should fail when DNS is not configured', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
    }
}`;
      const results = runRule(DnsRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when DNS servers are configured', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
        dns-setting {
            servers {
                primary 8.8.8.8;
            }
        }
    }
}`;
      const results = runRule(DnsRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-SYS-004: Management Access Restricted', () => {
    test('should fail when permitted-ip is not configured', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
    }
}`;
      const results = runRule(ManagementAccessRestricted, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('permitted-ip');
    });

    test('should pass when permitted-ip is configured', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
        permitted-ip {
            192.168.1.0/24;
            10.0.0.0/8;
        }
    }
}`;
      const results = runRule(ManagementAccessRestricted, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-SYS-005: Login Banner Required', () => {
    test('should report when login-banner is missing', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
    }
}`;
      const results = runRule(LoginBannerRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when login-banner is configured', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
        login-banner "Authorized access only";
    }
}`;
      const results = runRule(LoginBannerRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Security Policy Rules Tests
// ============================================================================

describe('Palo Alto Security Policy Rules', () => {
  describe('PAN-SEC-001: Security Rule Logging', () => {
    test('should fail when log-end is not enabled', () => {
      const config = `rulebase {
    security {
        rules {
            allow-web {
                from trust;
                to untrust;
                action allow;
            }
        }
    }
}`;
      const results = runRule(SecurityRuleLogging, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('log-end');
    });

    test('should pass when log-end is enabled', () => {
      const config = `rulebase {
    security {
        rules {
            allow-web {
                from trust;
                to untrust;
                action allow;
                log-end yes;
            }
        }
    }
}`;
      const results = runRule(SecurityRuleLogging, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-SEC-002: Security Profile Required', () => {
    test('should fail when allow rule has no security profile', () => {
      const config = `rulebase {
    security {
        rules {
            allow-web {
                from trust;
                to untrust;
                action allow;
                log-end yes;
            }
        }
    }
}`;
      const results = runRule(SecurityProfileRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('security profiles');
    });

    test('should pass when security profile is attached', () => {
      const config = `rulebase {
    security {
        rules {
            allow-web {
                from trust;
                to untrust;
                action allow;
                log-end yes;
                profile-setting {
                    group best-practices;
                }
            }
        }
    }
}`;
      const results = runRule(SecurityProfileRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });

    test('should not apply to deny rules', () => {
      const config = `rulebase {
    security {
        rules {
            block-bad {
                from any;
                to any;
                action deny;
                log-end yes;
            }
        }
    }
}`;
      const results = runRule(SecurityProfileRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-SEC-003: No Any Application', () => {
    test('should warn when rule uses any application', () => {
      const config = `rulebase {
    security {
        rules {
            allow-all-apps {
                from trust;
                to untrust;
                application any;
                action allow;
                log-end yes;
            }
        }
    }
}`;
      const results = runRule(NoAnyApplication, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('any');
    });

    test('should pass when specific applications are used', () => {
      const config = `rulebase {
    security {
        rules {
            allow-web {
                from trust;
                to untrust;
                application web-browsing;
                application ssl;
                action allow;
                log-end yes;
            }
        }
    }
}`;
      const results = runRule(NoAnyApplication, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-SEC-004: No Overly Permissive Rules', () => {
    test('should error on any-any-any rule', () => {
      const config = `rulebase {
    security {
        rules {
            allow-everything {
                from any;
                to any;
                source any;
                destination any;
                application any;
                service any;
                action allow;
            }
        }
    }
}`;
      const results = runRule(NoOverlyPermissiveRules, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('overly permissive');
    });

    test('should pass when rule is specific', () => {
      const config = `rulebase {
    security {
        rules {
            allow-specific {
                from trust;
                to untrust;
                source 10.0.0.0/8;
                destination web-servers;
                application web-browsing;
                service application-default;
                action allow;
            }
        }
    }
}`;
      const results = runRule(NoOverlyPermissiveRules, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-SEC-005: Security Rule Description', () => {
    test('should warn when description is missing', () => {
      const config = `rulebase {
    security {
        rules {
            allow-web {
                from trust;
                to untrust;
                action allow;
                log-end yes;
            }
        }
    }
}`;
      const results = runRule(SecurityRuleDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when description exists', () => {
      const config = `rulebase {
    security {
        rules {
            allow-web {
                description "Allow web traffic from trust zone";
                from trust;
                to untrust;
                action allow;
                log-end yes;
            }
        }
    }
}`;
      const results = runRule(SecurityRuleDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Zone Rules Tests
// ============================================================================

describe('Palo Alto Zone Rules', () => {
  describe('PAN-ZONE-001: Zone Protection Required', () => {
    test('should fail when zone has no protection profile', () => {
      const config = `zone {
    trust {
        network {
            layer3 ethernet1/2;
        }
    }
    untrust {
        network {
            layer3 ethernet1/1;
        }
    }
}`;
      const results = runRule(ZoneProtectionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('Zone Protection Profile');
    });

    test('should pass when all zones have protection profiles', () => {
      const config = `zone {
    trust {
        network {
            layer3 ethernet1/2;
        }
        zone-protection-profile strict-protection;
    }
    untrust {
        network {
            layer3 ethernet1/1;
        }
        zone-protection-profile external-protection;
    }
}`;
      const results = runRule(ZoneProtectionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// Profile Rules Tests
// ============================================================================

describe('Palo Alto Profile Rules', () => {
  describe('PAN-PROF-001: WildFire Required', () => {
    test('should warn when WildFire is not configured', () => {
      const config = `profiles {
    virus {
        default {
        }
    }
}`;
      const results = runRule(WildfireRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('WildFire');
    });

    test('should pass when WildFire is configured', () => {
      const config = `profiles {
    wildfire-analysis {
        default {
            rules {
                forward-all {
                    application any;
                }
            }
        }
    }
}`;
      const results = runRule(WildfireRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-PROF-002: URL Filtering Required', () => {
    test('should warn when URL Filtering is not configured', () => {
      const config = `profiles {
    virus {
        default {
        }
    }
}`;
      const results = runRule(UrlFilteringRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when URL Filtering is configured', () => {
      const config = `profiles {
    url-filtering {
        strict {
            block {
                malware;
                phishing;
            }
        }
    }
}`;
      const results = runRule(UrlFilteringRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-PROF-003: Anti-Virus Required', () => {
    test('should warn when AV is not configured', () => {
      const config = `profiles {
    spyware {
        default {
        }
    }
}`;
      const results = runRule(AntiVirusRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when AV is configured', () => {
      const config = `profiles {
    virus {
        strict {
            decoder {
                ftp {
                    action reset-both;
                }
            }
        }
    }
}`;
      const results = runRule(AntiVirusRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-PROF-004: Anti-Spyware Required', () => {
    test('should pass when Anti-Spyware is configured', () => {
      const config = `profiles {
    spyware {
        strict {
            rules {
                block-critical {
                    severity critical;
                    action reset-both;
                }
            }
        }
    }
}`;
      const results = runRule(AntiSpywareRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });

  describe('PAN-PROF-005: Vulnerability Protection Required', () => {
    test('should pass when Vulnerability Protection is configured', () => {
      const config = `profiles {
    vulnerability {
        strict {
            rules {
                block-critical-high {
                    severity critical;
                    severity high;
                    action reset-both;
                }
            }
        }
    }
}`;
      const results = runRule(VulnerabilityProtectionRequired, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// NAT Rules Tests
// ============================================================================

describe('Palo Alto NAT Rules', () => {
  describe('PAN-NAT-001: NAT Rule Description', () => {
    test('should warn when NAT rule has no description', () => {
      const config = `rulebase {
    nat {
        rules {
            outbound-nat {
                from trust;
                to untrust;
            }
        }
    }
}`;
      const results = runRule(NatRuleDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
    });

    test('should pass when NAT rule has description', () => {
      const config = `rulebase {
    nat {
        rules {
            outbound-nat {
                description "Outbound NAT for internal networks";
                from trust;
                to untrust;
            }
        }
    }
}`;
      const results = runRule(NatRuleDescription, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// HA Rules Tests
// ============================================================================

describe('Palo Alto HA Rules', () => {
  describe('PAN-HA-001: HA Recommended', () => {
    test('should inform when HA is not configured', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
    }
}`;
      const results = runRule(HARecommended, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(1);
      expect(failures[0]?.message).toContain('High Availability');
    });

    test('should pass when HA is configured', () => {
      const config = `deviceconfig {
    system {
        hostname firewall-01;
    }
    high-availability {
        interface {
            ha1 {
                port ethernet1/15;
            }
        }
        enabled yes;
    }
}`;
      const results = runRule(HARecommended, config);
      const failures = results.filter((r) => !r.passed);
      expect(failures.length).toBe(0);
    });
  });
});

// ============================================================================
// All Rules Export Test
// ============================================================================

describe('Palo Alto Rules Export', () => {
  test('should export all Palo Alto rules', () => {
    expect(allPaloAltoRules.length).toBeGreaterThan(0);
    expect(allPaloAltoRules.every((r) => r.id.startsWith('PAN-'))).toBe(true);
  });

  test('should have unique rule IDs', () => {
    const ids = allPaloAltoRules.map((r) => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  test('all rules should have required metadata', () => {
    for (const rule of allPaloAltoRules) {
      expect(rule.id).toBeDefined();
      expect(rule.selector).toBeDefined();
      expect(rule.metadata).toBeDefined();
      expect(rule.metadata.level).toBeDefined();
      expect(rule.metadata.obu).toBeDefined();
      expect(rule.metadata.owner).toBeDefined();
      expect(rule.check).toBeDefined();
    }
  });
});
