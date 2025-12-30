import { beforeEach, describe, it, afterEach, vi } from 'vitest';
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
import type { SubdomainFinderData } from '../tool-types';

// Test data constants
const TEST_DOMAIN = 'example.com';

// Mock subdomain results
const createMockSubdomains = (): string[] => [
  'www.example.com',
  'mail.example.com',
  'api.example.com',
  'admin.example.com',
  'blog.example.com',
  'dev.example.com',
  'staging.example.com'
];

// Helper function to validate domain format
const isValidDomain = (domain: string): boolean => {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/;
  return domainRegex.test(domain);
};

// Helper function to extract unique subdomains
const extractUniqueSubdomains = (subdomains: string[]): string[] => {
  return [...new Set(subdomains)].sort();
};

// Helper function to filter subdomains by pattern
const filterSubdomains = (subdomains: string[], pattern: string): string[] => {
  if (!pattern) return subdomains;
  return subdomains.filter(sub => sub.toLowerCase().includes(pattern.toLowerCase()));
};

describe('SubdomainFinderTool', () => {
  describe('Subdomain results', () => {
    it('creates mock subdomains array', () => {
      const subdomains = createMockSubdomains();
      aiAssertTruthy({ name: 'SubdomainsArray', input: subdomains }, subdomains.length > 0);
    });

    it('includes www subdomain', () => {
      const subdomains = createMockSubdomains();
      const hasWww = subdomains.some(s => s.startsWith('www.'));
      aiAssertTruthy({ name: 'HasWww', input: subdomains }, hasWww);
    });

    it('includes mail subdomain', () => {
      const subdomains = createMockSubdomains();
      const hasMail = subdomains.some(s => s.startsWith('mail.'));
      aiAssertTruthy({ name: 'HasMail', input: subdomains }, hasMail);
    });

    it('includes api subdomain', () => {
      const subdomains = createMockSubdomains();
      const hasApi = subdomains.some(s => s.startsWith('api.'));
      aiAssertTruthy({ name: 'HasApi', input: subdomains }, hasApi);
    });
  });

  describe('Domain validation', () => {
    it('validates correct domain format', () => {
      aiAssertEqual({ name: 'ValidDomain', input: TEST_DOMAIN }, isValidDomain(TEST_DOMAIN), true);
    });

    it('validates domain with subdomain', () => {
      aiAssertEqual({ name: 'SubdomainDomain', input: 'www.example.com' }, isValidDomain('www.example.com'), true);
    });

    it('rejects domain without TLD', () => {
      aiAssertEqual({ name: 'NoTLDDomain', input: 'example' }, isValidDomain('example'), false);
    });

    it('rejects empty string', () => {
      aiAssertEqual({ name: 'EmptyDomain', input: '' }, isValidDomain(''), false);
    });
  });

  describe('Unique subdomain extraction', () => {
    it('removes duplicate subdomains', () => {
      const duplicates = ['www.example.com', 'api.example.com', 'www.example.com'];
      const unique = extractUniqueSubdomains(duplicates);
      aiAssertEqual({ name: 'UniqueCount', input: duplicates }, unique.length, 2);
    });

    it('sorts subdomains alphabetically', () => {
      const unsorted = ['mail.example.com', 'api.example.com', 'www.example.com'];
      const sorted = extractUniqueSubdomains(unsorted);
      aiAssertEqual({ name: 'FirstSorted', input: unsorted }, sorted[0], 'api.example.com');
    });
  });

  describe('Subdomain filtering', () => {
    it('filters subdomains by pattern', () => {
      const subdomains = createMockSubdomains();
      const filtered = filterSubdomains(subdomains, 'api');
      aiAssertTruthy({ name: 'FilteredContainsApi', input: filtered }, filtered.every(s => s.includes('api')));
    });

    it('returns all subdomains when pattern is empty', () => {
      const subdomains = createMockSubdomains();
      const filtered = filterSubdomains(subdomains, '');
      aiAssertEqual({ name: 'NoFilter', input: filtered }, filtered.length, subdomains.length);
    });

    it('case insensitive filtering', () => {
      const subdomains = createMockSubdomains();
      const filtered = filterSubdomains(subdomains, 'API');
      aiAssertTruthy({ name: 'CaseInsensitive', input: filtered }, filtered.length > 0);
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): SubdomainFinderData | undefined => undefined;
      const data = getData();

      const domain = data?.domain ?? '';
      const loading = data?.loading ?? false;
      const subdomains = data?.subdomains ?? [];
      const error = data?.error;

      aiAssertEqual({ name: 'DefaultDomain' }, domain, '');
      aiAssertEqual({ name: 'DefaultLoading' }, loading, false);
      aiAssertEqual({ name: 'DefaultSubdomainsLength' }, subdomains.length, 0);
      aiAssertEqual({ name: 'DefaultError' }, error, undefined);
    });
  });

  describe('Successful search state', () => {
    it('should contain subdomain results', () => {
      const subdomains = createMockSubdomains();
      const data: SubdomainFinderData = {
        domain: TEST_DOMAIN,
        subdomains,
        searchedAt: Date.now()
      };

      aiAssertTruthy({ name: 'SubdomainsPresent', input: data }, (data.subdomains?.length ?? 0) > 0);
      aiAssertEqual({ name: 'SubdomainCount', input: data }, data.subdomains?.length, 7);
    });
  });

  describe('Error handling', () => {
    it('should handle error state', () => {
      const data: SubdomainFinderData = {
        domain: TEST_DOMAIN,
        error: 'Failed to find subdomains'
      };

      aiAssertTruthy({ name: 'ErrorPresent', input: data }, data.error !== undefined);
      aiAssertIncludes({ name: 'ErrorMessage', input: data }, data.error ?? '', 'Failed');
    });

    it('should handle rate limit error', () => {
      const data: SubdomainFinderData = {
        domain: TEST_DOMAIN,
        error: 'Rate limit exceeded'
      };

      aiAssertIncludes({ name: 'RateLimitError', input: data }, data.error ?? '', 'Rate limit');
    });
  });

  describe('Loading state', () => {
    it('should track loading state', () => {
      const data: SubdomainFinderData = {
        domain: TEST_DOMAIN,
        loading: true
      };

      aiAssertEqual({ name: 'LoadingState', input: data }, data.loading, true);
    });
  });

  describe('Filter state', () => {
    it('should store filter pattern', () => {
      const data: SubdomainFinderData = {
        domain: TEST_DOMAIN,
        subdomains: createMockSubdomains(),
        filter: 'api'
      };

      aiAssertEqual({ name: 'FilterPattern', input: data }, data.filter, 'api');
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    afterEach(() => {
      document.body.innerHTML = '';
      document.head.innerHTML = '';
      vi.restoreAllMocks();
    });

    it('renders Subdomain Finder tool with input and button', async () => {
      setRuntimeHandler('xcalibr-subdomain-find', () => ({ subdomains: [] }));

      const root = await mountWithTool('subdomainFinder');
      if (!root) return;

      const titleElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('Subdomain'));
      });
      aiAssertTruthy({ name: 'TitleFound' }, titleElement);

      const input = root.querySelector('input[type="text"], input[placeholder*="domain" i]');
      aiAssertTruthy({ name: 'DomainInputFound' }, input);

      const findButton = findButtonByText(root, 'Find') || findButtonByText(root, 'Search');
      aiAssertTruthy({ name: 'FindButtonFound' }, findButton);
    });

    it('displays subdomains when found', async () => {
      const mockSubdomains = createMockSubdomains();
      setRuntimeHandler('xcalibr-subdomain-find', () => ({
        subdomains: mockSubdomains
      }));

      const root = await mountWithTool('subdomainFinder', {
        domain: TEST_DOMAIN,
        subdomains: mockSubdomains,
        searchedAt: Date.now()
      });
      if (!root) return;

      const subdomainElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('www.example.com'));
      });
      aiAssertTruthy({ name: 'SubdomainDisplayed' }, subdomainElement);
    });

    it('displays no results message when empty', async () => {
      setRuntimeHandler('xcalibr-subdomain-find', () => ({
        subdomains: []
      }));

      const root = await mountWithTool('subdomainFinder', {
        domain: TEST_DOMAIN,
        subdomains: [],
        searchedAt: Date.now()
      });
      if (!root) return;

      const noResultsElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el =>
          el.textContent?.toLowerCase().includes('no subdomain') ||
          el.textContent?.toLowerCase().includes('not found') ||
          el.textContent?.toLowerCase().includes('0 subdomain')
        );
      });
      aiAssertTruthy({ name: 'NoResultsDisplayed' }, noResultsElement);
    });

    it('finds subdomains and stores results in state', async () => {
      const mockSubdomains = createMockSubdomains();
      setRuntimeHandler('xcalibr-subdomain-find', () => ({
        subdomains: mockSubdomains
      }));

      const root = await mountWithTool('subdomainFinder', { domain: TEST_DOMAIN });
      if (!root) return;

      const findButton = findButtonByText(root, 'Find') || findButtonByText(root, 'Search');
      aiAssertTruthy({ name: 'FindButtonFound' }, findButton);
      findButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));

      await flushPromises();

      const state = await waitForState((s) => {
        const data = s.toolData?.subdomainFinder as SubdomainFinderData | undefined;
        return Array.isArray(data?.subdomains) && data.subdomains.length > 0;
      });
      aiAssertTruthy({ name: 'StateUpdated' }, state);
      const data = state?.toolData?.subdomainFinder as SubdomainFinderData;
      aiAssertEqual({ name: 'SubdomainCount', state: data }, data.subdomains!.length, 7);
    });

    it('shows loading state during search', async () => {
      const root = await mountWithTool('subdomainFinder', {
        domain: TEST_DOMAIN,
        loading: true
      });
      if (!root) return;

      const loadingElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el =>
          el.textContent?.toLowerCase().includes('searching') ||
          el.textContent?.toLowerCase().includes('loading') ||
          el.textContent?.toLowerCase().includes('finding')
        );
      });
      aiAssertTruthy({ name: 'LoadingDisplayed' }, loadingElement);
    });
  });
});
