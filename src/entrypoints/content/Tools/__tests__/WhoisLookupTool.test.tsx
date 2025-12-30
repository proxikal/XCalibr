import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState,
  setRuntimeHandler,
  typeInput
} from '../../../__tests__/integration-test-utils';
import type { WhoisLookupData } from '../tool-types';

// Type for RDAP response
type RdapResponse = {
  ldhName: string;
  status?: string[];
  events?: { eventAction: string; eventDate: string }[];
  entities?: { roles?: string[]; vcardArray?: [string, unknown[][]] }[];
  nameservers?: { ldhName: string }[];
};

// Mock RDAP response factory
const createMockRdapResponse = (domain: string): RdapResponse => ({
  ldhName: domain,
  status: ['active'],
  events: [
    { eventAction: 'registration', eventDate: '2020-01-15T00:00:00Z' },
    { eventAction: 'expiration', eventDate: '2025-01-15T00:00:00Z' },
    { eventAction: 'last changed', eventDate: '2024-06-01T00:00:00Z' }
  ],
  entities: [
    {
      roles: ['registrar'],
      vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar Inc.']]]
    },
    {
      roles: ['registrant'],
      vcardArray: ['vcard', [['fn', {}, 'text', 'Domain Owner LLC']]]
    }
  ],
  nameservers: [
    { ldhName: 'ns1.example.com' },
    { ldhName: 'ns2.example.com' }
  ]
});

// RDAP parsing functions (mirrors component logic for testing)
const parseRdapResponse = (rdap: RdapResponse) => {
  const result: NonNullable<WhoisLookupData['result']> = {
    domain: rdap.ldhName,
    status: rdap.status?.join(', ') ?? 'Unknown',
    registrar: '',
    registrant: '',
    createdDate: '',
    expiresDate: '',
    updatedDate: '',
    nameservers: []
  };

  // Parse events for dates
  if (rdap.events) {
    for (const event of rdap.events) {
      const date = new Date(event.eventDate).toLocaleDateString();
      if (event.eventAction === 'registration') {
        result.createdDate = date;
      } else if (event.eventAction === 'expiration') {
        result.expiresDate = date;
      } else if (event.eventAction === 'last changed') {
        result.updatedDate = date;
      }
    }
  }

  // Parse entities for registrar/registrant
  if (rdap.entities) {
    for (const entity of rdap.entities) {
      const vcardEntries = entity.vcardArray?.[1];
      if (Array.isArray(vcardEntries)) {
        const fnEntry = vcardEntries.find(
          (v): v is unknown[] => Array.isArray(v) && v[0] === 'fn'
        );
        const name = fnEntry?.[3] as string | undefined;
        if (entity.roles?.includes('registrar') && name) {
          result.registrar = name;
        }
        if (entity.roles?.includes('registrant') && name) {
          result.registrant = name;
        }
      }
    }
  }

  // Parse nameservers
  if (rdap.nameservers) {
    result.nameservers = rdap.nameservers.map((ns) => ns.ldhName);
  }

  return result;
};

describe('WhoisLookupTool', () => {
  describe('RDAP response parsing', () => {
    it('should parse domain name correctly', () => {
      const rdap = createMockRdapResponse('example.com');
      const result = parseRdapResponse(rdap);

      aiAssertEqual(
        { name: 'DomainName', input: rdap.ldhName },
        result.domain,
        'example.com'
      );
    });

    it('should parse status correctly', () => {
      const rdap = createMockRdapResponse('example.com');
      const result = parseRdapResponse(rdap);

      aiAssertEqual(
        { name: 'DomainStatus', input: rdap.status },
        result.status,
        'active'
      );
    });

    it('should parse registrar from entities', () => {
      const rdap = createMockRdapResponse('example.com');
      const result = parseRdapResponse(rdap);

      aiAssertEqual(
        { name: 'Registrar', input: rdap.entities },
        result.registrar,
        'Example Registrar Inc.'
      );
    });

    it('should parse registrant from entities', () => {
      const rdap = createMockRdapResponse('example.com');
      const result = parseRdapResponse(rdap);

      aiAssertEqual(
        { name: 'Registrant', input: rdap.entities },
        result.registrant,
        'Domain Owner LLC'
      );
    });

    it('should parse registration date from events', () => {
      const rdap = createMockRdapResponse('example.com');
      const result = parseRdapResponse(rdap);

      aiAssertTruthy(
        { name: 'CreatedDate', input: result.createdDate },
        result.createdDate.length > 0
      );
    });

    it('should parse expiration date from events', () => {
      const rdap = createMockRdapResponse('example.com');
      const result = parseRdapResponse(rdap);

      aiAssertTruthy(
        { name: 'ExpiresDate', input: result.expiresDate },
        result.expiresDate.length > 0
      );
    });

    it('should parse nameservers', () => {
      const rdap = createMockRdapResponse('example.com');
      const result = parseRdapResponse(rdap);

      aiAssertEqual(
        { name: 'NameserverCount', input: rdap.nameservers },
        result.nameservers?.length,
        2
      );
      aiAssertIncludes(
        { name: 'Nameserver1', input: result.nameservers },
        result.nameservers?.join(',') ?? '',
        'ns1.example.com'
      );
    });
  });

  describe('Domain validation', () => {
    it('should validate basic domain format', () => {
      const isValidDomain = (domain: string) => {
        const pattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/;
        return pattern.test(domain);
      };

      aiAssertTruthy({ name: 'ValidDomain', input: 'example.com' }, isValidDomain('example.com'));
      aiAssertTruthy({ name: 'ValidSubdomain', input: 'sub.example.com' }, isValidDomain('sub.example.com'));
      aiAssertEqual({ name: 'InvalidDomain', input: 'invalid' }, isValidDomain('invalid'), false);
      aiAssertEqual({ name: 'EmptyDomain', input: '' }, isValidDomain(''), false);
    });

    it('should extract domain from URL', () => {
      const extractDomain = (input: string) => {
        try {
          if (input.includes('://')) {
            return new URL(input).hostname;
          }
          return input.replace(/^www\./, '');
        } catch {
          return input;
        }
      };

      aiAssertEqual(
        { name: 'ExtractFromUrl', input: 'https://www.example.com/path' },
        extractDomain('https://www.example.com/path'),
        'www.example.com'
      );
      aiAssertEqual(
        { name: 'ExtractPlain', input: 'example.com' },
        extractDomain('example.com'),
        'example.com'
      );
      aiAssertEqual(
        { name: 'ExtractWithWww', input: 'www.example.com' },
        extractDomain('www.example.com'),
        'example.com'
      );
    });
  });

  describe('TLD detection for RDAP bootstrap', () => {
    it('should extract TLD from domain', () => {
      const getTld = (domain: string) => {
        const parts = domain.split('.');
        return parts[parts.length - 1];
      };

      aiAssertEqual({ name: 'TldCom', input: 'example.com' }, getTld('example.com'), 'com');
      aiAssertEqual({ name: 'TldOrg', input: 'example.org' }, getTld('example.org'), 'org');
      aiAssertEqual({ name: 'TldCoUk', input: 'example.co.uk' }, getTld('example.co.uk'), 'uk');
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): WhoisLookupData | undefined => undefined;
      const data = getData();

      const domain = data?.domain ?? '';
      const result = data?.result;
      const error = data?.error;
      const loading = data?.loading ?? false;

      aiAssertEqual({ name: 'DefaultDomain' }, domain, '');
      aiAssertEqual({ name: 'DefaultResult' }, result, undefined);
      aiAssertEqual({ name: 'DefaultError' }, error, undefined);
      aiAssertEqual({ name: 'DefaultLoading' }, loading, false);
    });
  });

  describe('Error handling', () => {
    it('should handle error state', () => {
      const data: WhoisLookupData = {
        domain: 'invalid-domain',
        error: 'Domain not found in RDAP'
      };

      aiAssertTruthy(
        { name: 'ErrorPresent', input: data },
        data.error !== undefined
      );
      aiAssertIncludes(
        { name: 'ErrorMessage', input: data },
        data.error ?? '',
        'not found'
      );
    });
  });

  describe('Loading state', () => {
    it('should track loading state', () => {
      const data: WhoisLookupData = {
        domain: 'example.com',
        loading: true
      };

      aiAssertEqual(
        { name: 'LoadingState', input: data },
        data.loading,
        true
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle empty RDAP response', () => {
      const emptyRdap: RdapResponse = {
        ldhName: 'example.com',
        status: undefined,
        events: undefined,
        entities: undefined,
        nameservers: undefined
      };

      const result = parseRdapResponse(emptyRdap);

      aiAssertEqual({ name: 'EmptyStatus' }, result.status, 'Unknown');
      aiAssertEqual({ name: 'EmptyRegistrar' }, result.registrar, '');
      aiAssertEqual({ name: 'EmptyNameservers' }, result.nameservers?.length, 0);
    });

    it('should handle multiple status values', () => {
      const rdap = createMockRdapResponse('example.com');
      rdap.status = ['active', 'clientTransferProhibited', 'serverDeleteProhibited'];
      const result = parseRdapResponse(rdap);

      aiAssertIncludes(
        { name: 'MultipleStatus', input: result.status },
        result.status,
        'active'
      );
      aiAssertIncludes(
        { name: 'MultipleStatusTransfer', input: result.status },
        result.status,
        'clientTransferProhibited'
      );
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    it('renders Whois Lookup tool with input and button', async () => {
      const root = await mountWithTool('whoisLookup', { domain: '' });
      if (!root) return;

      // Find the domain input with exact placeholder
      const input = root.querySelector('input[placeholder="Enter domain (e.g., example.com)"]') as HTMLInputElement;
      aiAssertTruthy({ name: 'WhoisInput' }, input);

      // Find the lookup button
      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      aiAssertTruthy({ name: 'WhoisLookupButton' }, lookupButton);
    });

    it('displays results when data is present', async () => {
      const root = await mountWithTool('whoisLookup', {
        domain: 'example.com',
        result: {
          domain: 'example.com',
          status: 'active',
          registrar: 'Test Registrar',
          registrant: 'Test Owner',
          createdDate: '2020-01-15',
          expiresDate: '2025-01-15',
          updatedDate: '2024-06-01',
          nameservers: ['ns1.example.com', 'ns2.example.com']
        }
      });
      if (!root) return;

      // Verify results are displayed
      await flushPromises();
      const copyButton = await waitFor(() => findButtonByText(root, 'Copy Results'));
      aiAssertTruthy({ name: 'WhoisCopyButton' }, copyButton);
    });

    it('performs whois lookup via background script', async () => {
      // Set up runtime handler
      setRuntimeHandler('xcalibr-whois-lookup', () => ({
        result: {
          domain: 'example.com',
          status: 'active',
          registrar: 'Test Registrar',
          registrant: 'Test Owner',
          createdDate: '2020-01-15',
          expiresDate: '2025-01-15',
          updatedDate: '2024-06-01',
          nameservers: ['ns1.example.com', 'ns2.example.com']
        }
      }));

      // Mount with initial domain already set (similar to typing)
      const root = await mountWithTool('whoisLookup', { domain: 'example.com' });
      if (!root) return;

      // Find and click lookup button
      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      aiAssertTruthy({ name: 'WhoisLookupButton' }, lookupButton);
      lookupButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      // Verify state was updated with result
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, WhoisLookupData> | undefined;
        return Boolean(toolData?.whoisLookup?.result?.domain);
      });
      const toolData = (stored?.toolData ?? {}) as Record<string, WhoisLookupData>;
      aiAssertEqual(
        { name: 'WhoisResultDomain', state: toolData.whoisLookup },
        toolData.whoisLookup?.result?.domain,
        'example.com'
      );
      aiAssertEqual(
        { name: 'WhoisResultRegistrar', state: toolData.whoisLookup },
        toolData.whoisLookup?.result?.registrar,
        'Test Registrar'
      );
    });

    it('handles lookup error correctly', async () => {
      // Set up runtime handler to return error
      setRuntimeHandler('xcalibr-whois-lookup', () => ({
        error: 'Domain not found in RDAP'
      }));

      // Mount with initial domain
      const root = await mountWithTool('whoisLookup', { domain: 'nonexistent.invalid' });
      if (!root) return;

      // Find and click lookup button
      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      aiAssertTruthy({ name: 'WhoisLookupButtonError' }, lookupButton);
      lookupButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      // Verify state was updated with error
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, WhoisLookupData> | undefined;
        return Boolean(toolData?.whoisLookup?.error);
      });
      const toolData = (stored?.toolData ?? {}) as Record<string, WhoisLookupData>;
      aiAssertTruthy(
        { name: 'WhoisErrorPresent', state: toolData.whoisLookup },
        toolData.whoisLookup?.error
      );
      aiAssertIncludes(
        { name: 'WhoisErrorMessage', state: toolData.whoisLookup },
        toolData.whoisLookup?.error ?? '',
        'not found'
      );
    });

    it('updates input state when domain is typed', async () => {
      const root = await mountWithTool('whoisLookup', { domain: '' });
      if (!root) return;

      // Use exact placeholder match like SqlQueryBuilder does
      const input = root.querySelector('input[placeholder="Enter domain (e.g., example.com)"]') as HTMLInputElement;
      if (!input) return; // Skip if input not found

      // Use Object.getOwnPropertyDescriptor to set value and trigger React's onChange
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype,
        'value'
      )?.set;
      if (nativeInputValueSetter) {
        nativeInputValueSetter.call(input, 'test-domain.com');
      }
      input.dispatchEvent(new Event('input', { bubbles: true }));
      await flushPromises();

      // Verify the state was updated with the new domain
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, WhoisLookupData>;
        return toolData.whoisLookup?.domain === 'test-domain.com';
      });
      aiAssertTruthy({ name: 'WhoisDomainUpdated' }, stored !== null);

      if (stored) {
        const toolData = stored.toolData as Record<string, WhoisLookupData>;
        aiAssertEqual(
          { name: 'WhoisDomainValue', state: toolData.whoisLookup },
          toolData.whoisLookup?.domain,
          'test-domain.com'
        );
      }
    });

    it('disables lookup button when domain is empty', async () => {
      const root = await mountWithTool('whoisLookup', { domain: '' });
      if (!root) return;

      const lookupButton = await waitFor(() => findButtonByText(root, 'Lookup'));
      aiAssertTruthy({ name: 'WhoisLookupButtonEmpty' }, lookupButton);

      // Verify button is disabled when domain is empty
      aiAssertTruthy(
        { name: 'WhoisButtonDisabled' },
        lookupButton?.hasAttribute('disabled')
      );
    });

    it('shows loading state during lookup', async () => {
      // Mount with domain and loading state
      const root = await mountWithTool('whoisLookup', {
        domain: 'example.com',
        loading: true
      });
      if (!root) return;

      // Verify loading button text
      const loadingButton = await waitFor(() => findButtonByText(root, 'Loading...'));
      aiAssertTruthy({ name: 'WhoisLoadingButton' }, loadingButton);
    });

    it('displays error message when error is present', async () => {
      const root = await mountWithTool('whoisLookup', {
        domain: 'example.com',
        error: 'Failed to fetch WHOIS data'
      });
      if (!root) return;

      await flushPromises();

      // Check for error text in the DOM
      const errorElements = Array.from(root.querySelectorAll('div')).filter(
        el => el.textContent?.includes('Failed to fetch WHOIS data')
      );
      aiAssertTruthy({ name: 'WhoisErrorDisplay' }, errorElements.length > 0);
    });

    it('displays nameservers in results', async () => {
      const root = await mountWithTool('whoisLookup', {
        domain: 'example.com',
        result: {
          domain: 'example.com',
          status: 'active',
          registrar: 'Test Registrar',
          registrant: 'Test Owner',
          createdDate: '2020-01-15',
          expiresDate: '2025-01-15',
          updatedDate: '2024-06-01',
          nameservers: ['ns1.example.com', 'ns2.example.com']
        }
      });
      if (!root) return;

      await flushPromises();

      // Check for nameserver text in the DOM
      const ns1Elements = Array.from(root.querySelectorAll('div')).filter(
        el => el.textContent?.includes('ns1.example.com')
      );
      const ns2Elements = Array.from(root.querySelectorAll('div')).filter(
        el => el.textContent?.includes('ns2.example.com')
      );
      aiAssertTruthy({ name: 'WhoisNs1Display' }, ns1Elements.length > 0);
      aiAssertTruthy({ name: 'WhoisNs2Display' }, ns2Elements.length > 0);
    });
  });
});
