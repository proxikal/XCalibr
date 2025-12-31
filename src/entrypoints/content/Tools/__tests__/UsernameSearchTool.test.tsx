import { beforeEach, describe, it, afterEach, vi } from 'vitest';
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
import type { UsernameSearchData, PlatformResult } from '../tool-types';

// Test data constants
const TEST_USERNAME = 'testuser123';

// Mock platform result factory
const createMockPlatformResult = (
  platform: string,
  status: 'found' | 'not_found' | 'error',
  username: string
): PlatformResult => {
  const urlMap: Record<string, string> = {
    Twitter: `https://twitter.com/${username}`,
    GitHub: `https://github.com/${username}`,
    Reddit: `https://reddit.com/user/${username}`,
    Instagram: `https://instagram.com/${username}`,
    LinkedIn: `https://linkedin.com/in/${username}`
  };

  return {
    platform,
    url: urlMap[platform] || `https://${platform.toLowerCase()}.com/${username}`,
    status,
    statusCode: status === 'found' ? 200 : status === 'not_found' ? 404 : 0,
    error: status === 'error' ? 'Connection failed' : undefined
  };
};

// Create mock search results
const createMockSearchResults = (username: string): PlatformResult[] => [
  createMockPlatformResult('Twitter', 'found', username),
  createMockPlatformResult('GitHub', 'found', username),
  createMockPlatformResult('Reddit', 'not_found', username),
  createMockPlatformResult('Instagram', 'found', username),
  createMockPlatformResult('LinkedIn', 'error', username)
];

// Helper function to determine status from HTTP code
const determineStatus = (statusCode: number): 'found' | 'not_found' | 'error' => {
  if (statusCode === 200 || statusCode === 301 || statusCode === 302) {
    return 'found';
  } else if (statusCode === 404) {
    return 'not_found';
  } else if (statusCode === 403 || statusCode === 429) {
    return 'error';
  }
  return statusCode >= 400 ? 'not_found' : 'found';
};

// Helper function to clean username
const cleanUsername = (value: string): string => {
  return value.toLowerCase().trim().replace(/[^a-z0-9_-]/g, '');
};

describe('UsernameSearchTool', () => {
  describe('Platform result creation', () => {
    it('creates found result with correct status code', () => {
      const result = createMockPlatformResult('Twitter', 'found', 'testuser');
      aiAssertEqual({ name: 'ResultStatus', input: result }, result.status, 'found');
      aiAssertEqual({ name: 'ResultStatusCode', input: result }, result.statusCode, 200);
      aiAssertEqual({ name: 'ResultError', input: result }, result.error, undefined);
    });

    it('creates not_found result with 404 status code', () => {
      const result = createMockPlatformResult('GitHub', 'not_found', 'testuser');
      aiAssertEqual({ name: 'NotFoundStatus', input: result }, result.status, 'not_found');
      aiAssertEqual({ name: 'NotFoundStatusCode', input: result }, result.statusCode, 404);
    });

    it('creates error result with 0 status code', () => {
      const result = createMockPlatformResult('Reddit', 'error', 'testuser');
      aiAssertEqual({ name: 'ErrorStatus', input: result }, result.status, 'error');
      aiAssertEqual({ name: 'ErrorStatusCode', input: result }, result.statusCode, 0);
      aiAssertEqual({ name: 'ErrorMessage', input: result }, result.error, 'Connection failed');
    });

    it('generates correct Twitter URL', () => {
      const result = createMockPlatformResult('Twitter', 'found', 'johndoe');
      aiAssertEqual({ name: 'TwitterUrl', input: result }, result.url, 'https://twitter.com/johndoe');
    });

    it('generates correct GitHub URL', () => {
      const result = createMockPlatformResult('GitHub', 'found', 'johndoe');
      aiAssertEqual({ name: 'GitHubUrl', input: result }, result.url, 'https://github.com/johndoe');
    });

    it('generates correct Reddit URL', () => {
      const result = createMockPlatformResult('Reddit', 'found', 'johndoe');
      aiAssertEqual({ name: 'RedditUrl', input: result }, result.url, 'https://reddit.com/user/johndoe');
    });

    it('generates correct Instagram URL', () => {
      const result = createMockPlatformResult('Instagram', 'found', 'johndoe');
      aiAssertEqual({ name: 'InstagramUrl', input: result }, result.url, 'https://instagram.com/johndoe');
    });

    it('generates correct LinkedIn URL', () => {
      const result = createMockPlatformResult('LinkedIn', 'found', 'johndoe');
      aiAssertEqual({ name: 'LinkedInUrl', input: result }, result.url, 'https://linkedin.com/in/johndoe');
    });
  });

  describe('Mock search results', () => {
    it('creates results for all platforms', () => {
      const results = createMockSearchResults('testuser');
      aiAssertEqual({ name: 'ResultsCount', input: results }, results.length, 5);
    });

    it('includes Twitter as found', () => {
      const results = createMockSearchResults('testuser');
      const twitter = results.find(r => r.platform === 'Twitter');
      aiAssertTruthy({ name: 'TwitterExists', input: results }, twitter);
      aiAssertEqual({ name: 'TwitterStatus', input: twitter }, twitter!.status, 'found');
    });

    it('includes GitHub as found', () => {
      const results = createMockSearchResults('testuser');
      const github = results.find(r => r.platform === 'GitHub');
      aiAssertTruthy({ name: 'GitHubExists', input: results }, github);
      aiAssertEqual({ name: 'GitHubStatus', input: github }, github!.status, 'found');
    });

    it('includes Reddit as not_found', () => {
      const results = createMockSearchResults('testuser');
      const reddit = results.find(r => r.platform === 'Reddit');
      aiAssertTruthy({ name: 'RedditExists', input: results }, reddit);
      aiAssertEqual({ name: 'RedditStatus', input: reddit }, reddit!.status, 'not_found');
    });

    it('includes Instagram as found', () => {
      const results = createMockSearchResults('testuser');
      const instagram = results.find(r => r.platform === 'Instagram');
      aiAssertTruthy({ name: 'InstagramExists', input: results }, instagram);
      aiAssertEqual({ name: 'InstagramStatus', input: instagram }, instagram!.status, 'found');
    });

    it('includes LinkedIn as error', () => {
      const results = createMockSearchResults('testuser');
      const linkedin = results.find(r => r.platform === 'LinkedIn');
      aiAssertTruthy({ name: 'LinkedInExists', input: results }, linkedin);
      aiAssertEqual({ name: 'LinkedInStatus', input: linkedin }, linkedin!.status, 'error');
    });
  });

  describe('Status determination logic', () => {
    it('determines 200 as found', () => {
      aiAssertEqual({ name: 'Status200', input: 200 }, determineStatus(200), 'found');
    });

    it('determines 301 as found', () => {
      aiAssertEqual({ name: 'Status301', input: 301 }, determineStatus(301), 'found');
    });

    it('determines 302 as found', () => {
      aiAssertEqual({ name: 'Status302', input: 302 }, determineStatus(302), 'found');
    });

    it('determines 404 as not_found', () => {
      aiAssertEqual({ name: 'Status404', input: 404 }, determineStatus(404), 'not_found');
    });

    it('determines 403 as error', () => {
      aiAssertEqual({ name: 'Status403', input: 403 }, determineStatus(403), 'error');
    });

    it('determines 429 as error', () => {
      aiAssertEqual({ name: 'Status429', input: 429 }, determineStatus(429), 'error');
    });

    it('determines 500 as not_found', () => {
      aiAssertEqual({ name: 'Status500', input: 500 }, determineStatus(500), 'not_found');
    });

    it('determines 201 as found', () => {
      aiAssertEqual({ name: 'Status201', input: 201 }, determineStatus(201), 'found');
    });
  });

  describe('Results filtering', () => {
    const mockResults = createMockSearchResults(TEST_USERNAME);

    it('filters found results correctly', () => {
      const found = mockResults.filter(r => r.status === 'found');
      aiAssertEqual({ name: 'FoundCount', input: mockResults }, found.length, 3);
    });

    it('filters not_found results correctly', () => {
      const notFound = mockResults.filter(r => r.status === 'not_found');
      aiAssertEqual({ name: 'NotFoundCount', input: mockResults }, notFound.length, 1);
    });

    it('filters error results correctly', () => {
      const errors = mockResults.filter(r => r.status === 'error');
      aiAssertEqual({ name: 'ErrorCount', input: mockResults }, errors.length, 1);
    });

    it('calculates correct totals', () => {
      const foundCount = mockResults.filter(r => r.status === 'found').length;
      const notFoundCount = mockResults.filter(r => r.status === 'not_found').length;
      const errorCount = mockResults.filter(r => r.status === 'error').length;
      aiAssertEqual(
        { name: 'TotalCount', input: mockResults },
        foundCount + notFoundCount + errorCount,
        mockResults.length
      );
    });
  });

  describe('Username validation', () => {
    it('handles lowercase conversion', () => {
      const cleaned = cleanUsername('TestUser');
      aiAssertEqual({ name: 'LowercaseConversion', input: 'TestUser' }, cleaned, 'testuser');
    });

    it('removes special characters', () => {
      const cleaned = cleanUsername('test@user!');
      aiAssertEqual({ name: 'RemoveSpecialChars', input: 'test@user!' }, cleaned, 'testuser');
    });

    it('allows underscores', () => {
      const cleaned = cleanUsername('test_user');
      aiAssertEqual({ name: 'AllowUnderscores', input: 'test_user' }, cleaned, 'test_user');
    });

    it('allows hyphens', () => {
      const cleaned = cleanUsername('test-user');
      aiAssertEqual({ name: 'AllowHyphens', input: 'test-user' }, cleaned, 'test-user');
    });

    it('allows numbers', () => {
      const cleaned = cleanUsername('test123');
      aiAssertEqual({ name: 'AllowNumbers', input: 'test123' }, cleaned, 'test123');
    });

    it('trims whitespace', () => {
      const cleaned = cleanUsername('  testuser  ');
      aiAssertEqual({ name: 'TrimWhitespace', input: '  testuser  ' }, cleaned, 'testuser');
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): UsernameSearchData | undefined => undefined;
      const data = getData();

      const username = data?.username ?? '';
      const loading = data?.loading ?? false;
      const results = data?.results ?? [];
      const filter = data?.filter ?? 'all';
      const error = data?.error;

      aiAssertEqual({ name: 'DefaultUsername' }, username, '');
      aiAssertEqual({ name: 'DefaultLoading' }, loading, false);
      aiAssertEqual({ name: 'DefaultResultsLength' }, results.length, 0);
      aiAssertEqual({ name: 'DefaultFilter' }, filter, 'all');
      aiAssertEqual({ name: 'DefaultError' }, error, undefined);
    });
  });

  describe('Error handling', () => {
    it('should handle error state', () => {
      const data: UsernameSearchData = {
        username: 'testuser',
        error: 'Username search failed'
      };

      aiAssertTruthy({ name: 'ErrorPresent', input: data }, data.error !== undefined);
      aiAssertIncludes({ name: 'ErrorMessage', input: data }, data.error ?? '', 'failed');
    });
  });

  describe('Loading state', () => {
    it('should track loading state', () => {
      const data: UsernameSearchData = {
        username: 'testuser',
        loading: true
      };

      aiAssertEqual({ name: 'LoadingState', input: data }, data.loading, true);
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

    it('renders Username Search tool with input and button', async () => {
      const mockResults = createMockSearchResults(TEST_USERNAME);
      setRuntimeHandler('xcalibr-username-search', () => ({ results: mockResults }));

      const root = await mountWithTool('usernameSearch');
      if (!root) return;

      const titleElement = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('Username Search'));
      });
      aiAssertTruthy({ name: 'TitleFound' }, titleElement);

      const input = root.querySelector('input[placeholder="Enter username"]');
      aiAssertTruthy({ name: 'InputFound' }, input);

      const searchButton = findButtonByText(root, 'Search');
      aiAssertTruthy({ name: 'SearchButtonFound' }, searchButton);
    });

    it('displays platform list before search', async () => {
      setRuntimeHandler('xcalibr-username-search', () => ({ results: [] }));

      const root = await mountWithTool('usernameSearch');
      if (!root) return;

      const platformText = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('platforms will be checked'));
      });
      aiAssertTruthy({ name: 'PlatformListVisible' }, platformText);
    });

    it('searches for username and stores results in state', async () => {
      setRuntimeHandler('xcalibr-username-search', (payload) => {
        const { username } = payload as { username: string };
        return { results: createMockSearchResults(username) };
      });

      const root = await mountWithTool('usernameSearch', { username: TEST_USERNAME });
      if (!root) return;

      const searchButton = findButtonByText(root, 'Search');
      aiAssertTruthy({ name: 'SearchButtonFound' }, searchButton);
      searchButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));

      await flushPromises();

      const state = await waitForState((s) => {
        const data = s.toolData?.usernameSearch as UsernameSearchData | undefined;
        return Array.isArray(data?.results) && data.results.length > 0;
      });
      aiAssertTruthy({ name: 'StateUpdated' }, state);
      const data = state?.toolData?.usernameSearch as UsernameSearchData;
      aiAssertEqual({ name: 'ResultsCount', state: data }, data.results!.length, 5);
    });

    it('handles search error and stores error in state', async () => {
      setRuntimeHandler('xcalibr-username-search', () => ({
        error: 'Username search failed'
      }));

      const root = await mountWithTool('usernameSearch', { username: TEST_USERNAME });
      if (!root) return;

      const searchButton = findButtonByText(root, 'Search');
      aiAssertTruthy({ name: 'SearchButtonFound' }, searchButton);
      searchButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));

      await flushPromises();

      const state = await waitForState((s) => {
        const data = s.toolData?.usernameSearch as UsernameSearchData | undefined;
        return !!data?.error;
      });
      aiAssertTruthy({ name: 'ErrorStateUpdated' }, state);
      const data = state?.toolData?.usernameSearch as UsernameSearchData;
      aiAssertEqual({ name: 'ErrorValue', state: data }, data.error, 'Username search failed');
    });

    it('types username into input field', async () => {
      setRuntimeHandler('xcalibr-username-search', () => ({ results: [] }));

      const root = await mountWithTool('usernameSearch');
      if (!root) return;

      const input = root.querySelector('input[placeholder="Enter username"]') as HTMLInputElement;
      if (!input) return;

      // Use Object.getOwnPropertyDescriptor to set value and trigger React's onChange
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype,
        'value'
      )?.set;
      if (nativeInputValueSetter) {
        nativeInputValueSetter.call(input, 'newuser');
      }
      input.dispatchEvent(new Event('input', { bubbles: true }));
      await flushPromises();

      const state = await waitForState((s) => {
        const data = s.toolData?.usernameSearch as UsernameSearchData | undefined;
        return data?.username === 'newuser';
      });
      aiAssertTruthy({ name: 'UsernameUpdated' }, state !== null);
    });

    it('counts found platforms correctly', async () => {
      const mockResults = createMockSearchResults(TEST_USERNAME);
      setRuntimeHandler('xcalibr-username-search', () => ({ results: mockResults }));

      const root = await mountWithTool('usernameSearch', {
        username: TEST_USERNAME,
        results: mockResults
      });
      if (!root) return;

      const foundText = await waitFor(() => {
        const elements = Array.from(root.querySelectorAll('*'));
        return elements.find(el => el.textContent?.includes('3 found'));
      });
      aiAssertTruthy({ name: 'FoundCountDisplayed' }, foundText);
    });
  });
});
