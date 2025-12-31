import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState,
  setRuntimeHandler
} from '../../../__tests__/integration-test-utils';
import type { ReverseIpLookupData } from '../tool-types';

// Mock reverse IP response
const createMockDomains = (): string[] => [
  'example.com',
  'example.org',
  'test-site.com',
  'mywebsite.net',
  'another-domain.io'
];

// IP validation function
const isValidIpv4 = (ip: string): boolean => {
  const pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!pattern.test(ip)) return false;
  const parts = ip.split('.');
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
};

const isValidIpv6 = (ip: string): boolean => {
  const pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){0,6}::([0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$/;
  return pattern.test(ip);
};

const isValidIp = (ip: string): boolean => {
  return isValidIpv4(ip) || isValidIpv6(ip);
};

// Domain filtering
const filterDomains = (domains: string[], search: string): string[] => {
  if (!search.trim()) return domains;
  const lowerSearch = search.toLowerCase();
  return domains.filter(d => d.toLowerCase().includes(lowerSearch));
};

describe('ReverseIpLookupTool', () => {
  describe('IP validation', () => {
    it('should validate valid IPv4 addresses', () => {
      aiAssertTruthy({ name: 'ValidIp1' }, isValidIpv4('192.168.1.1'));
      aiAssertTruthy({ name: 'ValidIp2' }, isValidIpv4('8.8.8.8'));
      aiAssertTruthy({ name: 'ValidIp3' }, isValidIpv4('255.255.255.255'));
      aiAssertTruthy({ name: 'ValidIp4' }, isValidIpv4('0.0.0.0'));
    });

    it('should reject invalid IPv4 addresses', () => {
      aiAssertEqual({ name: 'InvalidIp1' }, isValidIpv4('256.1.1.1'), false);
      aiAssertEqual({ name: 'InvalidIp2' }, isValidIpv4('1.1.1'), false);
      aiAssertEqual({ name: 'InvalidIp3' }, isValidIpv4('1.1.1.1.1'), false);
      aiAssertEqual({ name: 'InvalidIp4' }, isValidIpv4('abc.def.ghi.jkl'), false);
      aiAssertEqual({ name: 'InvalidIp5' }, isValidIpv4(''), false);
    });

    it('should validate valid IPv6 addresses', () => {
      aiAssertTruthy({ name: 'ValidIpv61' }, isValidIpv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334'));
      aiAssertTruthy({ name: 'ValidIpv62' }, isValidIpv6('::1'));
    });

    it('should validate IP using combined function', () => {
      aiAssertTruthy({ name: 'CombinedIpv4' }, isValidIp('8.8.8.8'));
      aiAssertTruthy({ name: 'CombinedIpv6' }, isValidIp('::1'));
      aiAssertEqual({ name: 'CombinedInvalid' }, isValidIp('not-an-ip'), false);
    });
  });

  describe('Domain filtering', () => {
    it('should return all domains when search is empty', () => {
      const domains = createMockDomains();
      const filtered = filterDomains(domains, '');

      aiAssertEqual(
        { name: 'EmptySearchCount', input: domains.length },
        filtered.length,
        domains.length
      );
    });

    it('should filter domains by search term', () => {
      const domains = createMockDomains();
      const filtered = filterDomains(domains, 'example');

      aiAssertEqual(
        { name: 'FilteredCount', input: domains },
        filtered.length,
        2
      );
      aiAssertTruthy(
        { name: 'ContainsExampleCom' },
        filtered.includes('example.com')
      );
      aiAssertTruthy(
        { name: 'ContainsExampleOrg' },
        filtered.includes('example.org')
      );
    });

    it('should be case-insensitive', () => {
      const domains = createMockDomains();
      const filtered = filterDomains(domains, 'EXAMPLE');

      aiAssertEqual(
        { name: 'CaseInsensitiveCount', input: domains },
        filtered.length,
        2
      );
    });

    it('should handle partial matches', () => {
      const domains = createMockDomains();
      const filtered = filterDomains(domains, '.com');

      aiAssertTruthy(
        { name: 'PartialMatchFound', input: filtered },
        filtered.length > 0
      );
    });

    it('should return empty array when no matches', () => {
      const domains = createMockDomains();
      const filtered = filterDomains(domains, 'nonexistent');

      aiAssertEqual(
        { name: 'NoMatchCount', input: domains },
        filtered.length,
        0
      );
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): ReverseIpLookupData | undefined => undefined;
      const data = getData();

      const ip = data?.ip ?? '';
      const domains = data?.domains ?? [];
      const search = data?.search ?? '';
      const error = data?.error;
      const loading = data?.loading ?? false;

      aiAssertEqual({ name: 'DefaultIp' }, ip, '');
      aiAssertEqual({ name: 'DefaultDomainsLength' }, domains.length, 0);
      aiAssertEqual({ name: 'DefaultSearch' }, search, '');
      aiAssertEqual({ name: 'DefaultError' }, error, undefined);
      aiAssertEqual({ name: 'DefaultLoading' }, loading, false);
    });
  });

  describe('Error handling', () => {
    it('should handle error state', () => {
      const data: ReverseIpLookupData = {
        ip: '256.1.1.1',
        error: 'Invalid IP address'
      };

      aiAssertTruthy(
        { name: 'ErrorPresent', input: data },
        data.error !== undefined
      );
      aiAssertIncludes(
        { name: 'ErrorMessage', input: data },
        data.error ?? '',
        'Invalid'
      );
    });
  });

  describe('Domain count', () => {
    it('should calculate domain count correctly', () => {
      const domains = createMockDomains();

      aiAssertEqual(
        { name: 'DomainCount' },
        domains.length,
        5
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle empty domains array', () => {
      const domains: string[] = [];
      const filtered = filterDomains(domains, 'test');

      aiAssertEqual({ name: 'EmptyArrayFilter' }, filtered.length, 0);
    });

    it('should handle whitespace search', () => {
      const domains = createMockDomains();
      const filtered = filterDomains(domains, '   ');

      aiAssertEqual(
        { name: 'WhitespaceSearch' },
        filtered.length,
        domains.length
      );
    });

    it('should handle special characters in search', () => {
      const domains = ['test-site.com', 'test_site.com'];
      const filtered = filterDomains(domains, '-');

      aiAssertEqual(
        { name: 'SpecialCharSearch' },
        filtered.length,
        1
      );
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    it('renders Reverse IP Lookup tool with input and button', async () => {
      const root = await mountWithTool('reverseIpLookup', { ip: '' });
      if (!root) return;

      const input = root.querySelector('input[placeholder="Enter IP address (e.g., 93.184.216.34)"]') as HTMLInputElement;
      aiAssertTruthy({ name: 'ReverseIpInput' }, input);

      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      aiAssertTruthy({ name: 'ReverseIpLookupButton' }, lookupButton);
    });

    it('displays domains when data is present', async () => {
      const root = await mountWithTool('reverseIpLookup', {
        ip: '93.184.216.34',
        domains: ['example.com', 'example.org', 'test.com']
      });
      if (!root) return;

      await flushPromises();

      const domainElements = Array.from(root.querySelectorAll('div')).filter(
        el => el.textContent?.includes('example.com')
      );
      aiAssertTruthy({ name: 'ReverseIpDomainDisplay' }, domainElements.length > 0);
    });

    it('performs reverse IP lookup via background script', async () => {
      setRuntimeHandler('xcalibr-reverse-ip-lookup', () => ({
        domains: ['example.com', 'example.org', 'test.com']
      }));

      const root = await mountWithTool('reverseIpLookup', { ip: '93.184.216.34' });
      if (!root) return;

      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      aiAssertTruthy({ name: 'ReverseIpLookupButtonFound' }, lookupButton);
      lookupButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, ReverseIpLookupData> | undefined;
        return Boolean(toolData?.reverseIpLookup?.domains?.length);
      });
      const toolData = (stored?.toolData ?? {}) as Record<string, ReverseIpLookupData>;
      aiAssertTruthy(
        { name: 'ReverseIpDomainsPresent', state: toolData.reverseIpLookup },
        (toolData.reverseIpLookup?.domains?.length ?? 0) > 0
      );
    });

    it('handles lookup error correctly', async () => {
      setRuntimeHandler('xcalibr-reverse-ip-lookup', () => ({
        error: 'IP lookup failed'
      }));

      const root = await mountWithTool('reverseIpLookup', { ip: '256.1.1.1' });
      if (!root) return;

      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      lookupButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, ReverseIpLookupData> | undefined;
        return Boolean(toolData?.reverseIpLookup?.error);
      });
      const toolData = (stored?.toolData ?? {}) as Record<string, ReverseIpLookupData>;
      aiAssertTruthy(
        { name: 'ReverseIpErrorPresent', state: toolData.reverseIpLookup },
        toolData.reverseIpLookup?.error
      );
    });

    it('displays error message when error is present', async () => {
      const root = await mountWithTool('reverseIpLookup', {
        ip: '256.1.1.1',
        error: 'Invalid IP address'
      });
      if (!root) return;

      await flushPromises();

      const errorElements = Array.from(root.querySelectorAll('div')).filter(
        el => el.textContent?.includes('Invalid IP address')
      );
      aiAssertTruthy({ name: 'ReverseIpErrorDisplay' }, errorElements.length > 0);
    });

    it('shows loading state during lookup', async () => {
      const root = await mountWithTool('reverseIpLookup', {
        ip: '8.8.8.8',
        loading: true
      });
      if (!root) return;

      const loadingButton = await waitFor(() => findButtonByText(root, 'Loading...'));
      aiAssertTruthy({ name: 'ReverseIpLoadingButton' }, loadingButton);
    });

    it('disables lookup button when IP is empty', async () => {
      const root = await mountWithTool('reverseIpLookup', { ip: '' });
      if (!root) return;

      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      aiAssertTruthy({ name: 'ReverseIpLookupButtonEmpty' }, lookupButton);
      aiAssertTruthy(
        { name: 'ReverseIpButtonDisabled' },
        lookupButton?.hasAttribute('disabled')
      );
    });

    it('displays domain count', async () => {
      const root = await mountWithTool('reverseIpLookup', {
        ip: '93.184.216.34',
        domains: ['example.com', 'example.org', 'test.com']
      });
      if (!root) return;

      await flushPromises();

      const countElements = Array.from(root.querySelectorAll('div')).filter(
        el => el.textContent?.includes('3 domain')
      );
      aiAssertTruthy({ name: 'ReverseIpDomainCount' }, countElements.length > 0);
    });
  });
});
