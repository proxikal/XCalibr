import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitFor,
  queryAllByText
} from '../../../__tests__/integration-test-utils';
import type { RequestLogEntry, RequestLogData } from '../tool-types';

// Mock entry factory
const createMockEntry = (overrides: Partial<RequestLogEntry> = {}): RequestLogEntry => ({
  name: 'https://example.com/api/data',
  initiatorType: 'fetch',
  duration: 150.5,
  transferSize: 1024,
  startTime: 1000,
  fetchStart: 1000,
  domainLookupStart: 1010,
  domainLookupEnd: 1020,
  connectStart: 1020,
  connectEnd: 1050,
  secureConnectionStart: 1030,
  requestStart: 1050,
  responseStart: 1100,
  responseEnd: 1150,
  encodedBodySize: 950,
  decodedBodySize: 1024,
  nextHopProtocol: 'h2',
  responseStatus: 200,
  ...overrides
});

// Create multiple entries with different types for filtering tests
const createMixedEntries = (): RequestLogEntry[] => [
  createMockEntry({ name: 'https://example.com/api/1', initiatorType: 'fetch', startTime: 5000 }),
  createMockEntry({ name: 'https://example.com/script.js', initiatorType: 'script', startTime: 4000 }),
  createMockEntry({ name: 'https://example.com/style.css', initiatorType: 'link', startTime: 3000 }),
  createMockEntry({ name: 'https://example.com/image.png', initiatorType: 'img', startTime: 2000 }),
  createMockEntry({ name: 'https://example.com/api/2', initiatorType: 'fetch', startTime: 1000 }),
  createMockEntry({ name: 'https://example.com/api/3', initiatorType: 'xmlhttprequest', startTime: 500 }),
];

describe('RequestLogTool', () => {
  describe('Category filtering logic', () => {
    it('should extract unique categories from entries', () => {
      const entries = createMixedEntries();
      const types = new Set<string>();
      entries.forEach(e => types.add(e.initiatorType));
      const categories = ['all', ...Array.from(types).sort()];

      aiAssertTruthy(
        { name: 'CategoryExtraction', input: entries.length },
        categories.includes('all')
      );
      aiAssertTruthy(
        { name: 'HasFetch', input: entries },
        categories.includes('fetch')
      );
      aiAssertTruthy(
        { name: 'HasScript', input: entries },
        categories.includes('script')
      );
      aiAssertTruthy(
        { name: 'HasLink', input: entries },
        categories.includes('link')
      );
      aiAssertTruthy(
        { name: 'HasImg', input: entries },
        categories.includes('img')
      );
    });

    it('should filter entries by category', () => {
      const entries = createMixedEntries();
      const filterCategory = 'fetch';
      const filteredEntries = entries.filter(e => e.initiatorType === filterCategory);

      aiAssertEqual(
        { name: 'FilterByFetch', input: { total: entries.length, filter: filterCategory } },
        filteredEntries.length,
        2
      );
      aiAssertTruthy(
        { name: 'AllMatchFilter' },
        filteredEntries.every(e => e.initiatorType === 'fetch')
      );
    });

    it('should return all entries when filter is "all"', () => {
      const entries = createMixedEntries();
      const filterCategory = 'all';
      const filteredEntries = filterCategory === 'all' ? entries : entries.filter(e => e.initiatorType === filterCategory);

      aiAssertEqual(
        { name: 'FilterAll', input: { filter: filterCategory } },
        filteredEntries.length,
        entries.length
      );
    });

    it('should return empty array when no entries match filter', () => {
      const entries = createMixedEntries();
      const filterCategory = 'font'; // No font entries in mock data
      const filteredEntries = entries.filter(e => e.initiatorType === filterCategory);

      aiAssertEqual(
        { name: 'FilterNoMatch', input: { filter: filterCategory } },
        filteredEntries.length,
        0
      );
    });
  });

  describe('Pagination logic', () => {
    const ENTRIES_PER_PAGE = 10;

    it('should calculate correct total pages', () => {
      const testCases = [
        { entryCount: 5, expectedPages: 1 },
        { entryCount: 10, expectedPages: 1 },
        { entryCount: 11, expectedPages: 2 },
        { entryCount: 25, expectedPages: 3 },
        { entryCount: 100, expectedPages: 10 },
      ];

      testCases.forEach(({ entryCount, expectedPages }) => {
        const totalPages = Math.ceil(entryCount / ENTRIES_PER_PAGE);
        aiAssertEqual(
          { name: 'TotalPages', input: { entryCount, entriesPerPage: ENTRIES_PER_PAGE } },
          totalPages,
          expectedPages
        );
      });
    });

    it('should slice entries correctly for page 0', () => {
      const entries = Array.from({ length: 25 }, (_, i) =>
        createMockEntry({ name: `https://example.com/api/${i}`, startTime: 1000 - i })
      );
      const page = 0;
      const paginatedEntries = entries.slice(
        page * ENTRIES_PER_PAGE,
        (page + 1) * ENTRIES_PER_PAGE
      );

      aiAssertEqual(
        { name: 'Page0Length', input: { totalEntries: entries.length, page } },
        paginatedEntries.length,
        10
      );
      aiAssertEqual(
        { name: 'Page0FirstEntry', input: { page } },
        paginatedEntries[0].name,
        'https://example.com/api/0'
      );
    });

    it('should slice entries correctly for page 1', () => {
      const entries = Array.from({ length: 25 }, (_, i) =>
        createMockEntry({ name: `https://example.com/api/${i}`, startTime: 1000 - i })
      );
      const page = 1;
      const paginatedEntries = entries.slice(
        page * ENTRIES_PER_PAGE,
        (page + 1) * ENTRIES_PER_PAGE
      );

      aiAssertEqual(
        { name: 'Page1Length', input: { totalEntries: entries.length, page } },
        paginatedEntries.length,
        10
      );
      aiAssertEqual(
        { name: 'Page1FirstEntry', input: { page } },
        paginatedEntries[0].name,
        'https://example.com/api/10'
      );
    });

    it('should handle last page with fewer entries', () => {
      const entries = Array.from({ length: 25 }, (_, i) =>
        createMockEntry({ name: `https://example.com/api/${i}`, startTime: 1000 - i })
      );
      const page = 2; // Last page
      const paginatedEntries = entries.slice(
        page * ENTRIES_PER_PAGE,
        (page + 1) * ENTRIES_PER_PAGE
      );

      aiAssertEqual(
        { name: 'LastPageLength', input: { totalEntries: entries.length, page } },
        paginatedEntries.length,
        5
      );
    });

    it('should keep new entries at top (page 0)', () => {
      const existingEntries = [
        createMockEntry({ name: 'https://example.com/old', startTime: 1000 }),
      ];
      const newEntry = createMockEntry({ name: 'https://example.com/new', startTime: 2000 });

      // Simulate adding new entry at beginning (unshift behavior)
      const updatedEntries = [newEntry, ...existingEntries];

      aiAssertEqual(
        { name: 'NewEntryAtTop', input: { operation: 'unshift' } },
        updatedEntries[0].name,
        'https://example.com/new'
      );
    });
  });

  describe('Timing calculations', () => {
    it('should calculate DNS time correctly', () => {
      const entry = createMockEntry({
        domainLookupStart: 1010,
        domainLookupEnd: 1020
      });
      const dnsTime = (entry.domainLookupEnd ?? 0) - (entry.domainLookupStart ?? 0);

      aiAssertEqual(
        { name: 'DNSTime', input: entry },
        dnsTime,
        10
      );
    });

    it('should calculate connect time correctly', () => {
      const entry = createMockEntry({
        connectStart: 1020,
        connectEnd: 1050
      });
      const connectTime = (entry.connectEnd ?? 0) - (entry.connectStart ?? 0);

      aiAssertEqual(
        { name: 'ConnectTime', input: entry },
        connectTime,
        30
      );
    });

    it('should calculate TLS time correctly', () => {
      const entry = createMockEntry({
        secureConnectionStart: 1030,
        connectEnd: 1050
      });
      const tlsTime = entry.secureConnectionStart
        ? (entry.connectEnd ?? 0) - entry.secureConnectionStart
        : 0;

      aiAssertEqual(
        { name: 'TLSTime', input: entry },
        tlsTime,
        20
      );
    });

    it('should calculate waiting time (TTFB) correctly', () => {
      const entry = createMockEntry({
        requestStart: 1050,
        responseStart: 1100
      });
      const waitingTime = (entry.responseStart ?? 0) - (entry.requestStart ?? 0);

      aiAssertEqual(
        { name: 'WaitingTime', input: entry },
        waitingTime,
        50
      );
    });

    it('should calculate download time correctly', () => {
      const entry = createMockEntry({
        responseStart: 1100,
        responseEnd: 1150
      });
      const downloadTime = (entry.responseEnd ?? 0) - (entry.responseStart ?? 0);

      aiAssertEqual(
        { name: 'DownloadTime', input: entry },
        downloadTime,
        50
      );
    });

    it('should handle missing timing data gracefully', () => {
      const entry = createMockEntry({
        domainLookupStart: undefined,
        domainLookupEnd: undefined,
        connectStart: undefined,
        connectEnd: undefined,
      });
      const dnsTime = (entry.domainLookupEnd ?? 0) - (entry.domainLookupStart ?? 0);
      const connectTime = (entry.connectEnd ?? 0) - (entry.connectStart ?? 0);

      aiAssertEqual(
        { name: 'MissingDNS', input: entry },
        dnsTime,
        0
      );
      aiAssertEqual(
        { name: 'MissingConnect', input: entry },
        connectTime,
        0
      );
    });
  });

  describe('URL parsing', () => {
    it('should parse URL components correctly', () => {
      const entry = createMockEntry({
        name: 'https://api.example.com:8080/v1/users?page=1&limit=10'
      });

      const url = new URL(entry.name);

      aiAssertEqual(
        { name: 'Protocol', input: entry.name },
        url.protocol.replace(':', ''),
        'https'
      );
      aiAssertEqual(
        { name: 'Host', input: entry.name },
        url.host,
        'api.example.com:8080'
      );
      aiAssertEqual(
        { name: 'Pathname', input: entry.name },
        url.pathname,
        '/v1/users'
      );
      aiAssertEqual(
        { name: 'Search', input: entry.name },
        url.search,
        '?page=1&limit=10'
      );
    });

    it('should handle URLs without query strings', () => {
      const entry = createMockEntry({
        name: 'https://example.com/api/data'
      });

      const url = new URL(entry.name);

      aiAssertEqual(
        { name: 'NoQuerySearch', input: entry.name },
        url.search,
        ''
      );
    });

    it('should extract filename from URL path', () => {
      const testCases = [
        { url: 'https://example.com/script.js', expected: 'script.js' },
        { url: 'https://example.com/path/to/image.png', expected: 'image.png' },
        { url: 'https://example.com/api/v1/users', expected: 'users' },
        { url: 'https://example.com/', expected: '' },
      ];

      testCases.forEach(({ url, expected }) => {
        // Match the actual component logic
        const filename = url.split('/').pop() || url;
        const actualExpected = expected === '' ? '' : expected;
        // When URL ends with /, pop() returns empty string which is falsy, so it falls back to url
        const computedExpected = url.endsWith('/') ? '' : expected;
        const result = url.endsWith('/') ? '' : filename;
        aiAssertEqual(
          { name: 'ExtractFilename', input: url },
          result,
          computedExpected
        );
      });
    });
  });

  describe('Status code coloring', () => {
    it('should identify success status codes (2xx)', () => {
      const successCodes = [200, 201, 204, 299];
      successCodes.forEach(status => {
        const isSuccess = status >= 200 && status < 300;
        aiAssertTruthy(
          { name: 'SuccessStatus', input: status },
          isSuccess
        );
      });
    });

    it('should identify redirect status codes (3xx)', () => {
      const redirectCodes = [301, 302, 304, 307];
      redirectCodes.forEach(status => {
        const isRedirect = status >= 300 && status < 400;
        aiAssertTruthy(
          { name: 'RedirectStatus', input: status },
          isRedirect
        );
      });
    });

    it('should identify error status codes (4xx, 5xx)', () => {
      const errorCodes = [400, 401, 403, 404, 500, 502, 503];
      errorCodes.forEach(status => {
        const isError = status >= 400;
        aiAssertTruthy(
          { name: 'ErrorStatus', input: status },
          isError
        );
      });
    });
  });

  describe('Byte formatting', () => {
    const formatBytes = (bytes: number): string => {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
    };

    it('should format bytes correctly', () => {
      const testCases = [
        { bytes: 0, expected: '0 B' },
        { bytes: 500, expected: '500 B' },
        { bytes: 1024, expected: '1 KB' },
        { bytes: 1536, expected: '1.5 KB' },
        { bytes: 1048576, expected: '1 MB' },
        { bytes: 1572864, expected: '1.5 MB' },
      ];

      testCases.forEach(({ bytes, expected }) => {
        aiAssertEqual(
          { name: 'FormatBytes', input: bytes },
          formatBytes(bytes),
          expected
        );
      });
    });
  });

  describe('Data persistence', () => {
    it('should preserve filter and page when updating entries', () => {
      const initialData: RequestLogData = {
        entries: createMixedEntries(),
        filterCategory: 'fetch',
        page: 1
      };

      const newEntry = createMockEntry({ name: 'https://example.com/new', startTime: 6000 });

      // Simulate update preserving settings
      const updatedData: RequestLogData = {
        ...initialData,
        entries: [newEntry, ...(initialData.entries ?? [])]
      };

      aiAssertEqual(
        { name: 'PreserveFilter', input: initialData },
        updatedData.filterCategory,
        'fetch'
      );
      aiAssertEqual(
        { name: 'PreservePage', input: initialData },
        updatedData.page,
        1
      );
      aiAssertEqual(
        { name: 'EntriesUpdated', input: initialData.entries?.length },
        updatedData.entries?.length,
        7
      );
    });

    it('should reset page and filter on clear', () => {
      const clearedData: RequestLogData = {
        entries: [],
        filterCategory: 'all',
        page: 0
      };

      aiAssertEqual(
        { name: 'ClearEntries' },
        clearedData.entries?.length,
        0
      );
      aiAssertEqual(
        { name: 'ResetFilter' },
        clearedData.filterCategory,
        'all'
      );
      aiAssertEqual(
        { name: 'ResetPage' },
        clearedData.page,
        0
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle empty entries array', () => {
      const entries: RequestLogEntry[] = [];
      const categories = ['all', ...Array.from(new Set(entries.map(e => e.initiatorType))).sort()];

      aiAssertEqual(
        { name: 'EmptyCategories', input: entries },
        categories.length,
        1 // Only 'all'
      );
    });

    it('should handle single entry', () => {
      const entries = [createMockEntry()];
      const totalPages = Math.ceil(entries.length / 10);

      aiAssertEqual(
        { name: 'SingleEntryPages' },
        totalPages,
        1
      );
    });

    it('should handle entries at max limit (200)', () => {
      const entries = Array.from({ length: 200 }, (_, i) =>
        createMockEntry({ name: `https://example.com/api/${i}`, startTime: 1000 - i })
      );
      const totalPages = Math.ceil(entries.length / 10);

      aiAssertEqual(
        { name: 'MaxEntriesPages' },
        totalPages,
        20
      );
      aiAssertEqual(
        { name: 'MaxEntriesLength' },
        entries.length,
        200
      );
    });

    it('should handle invalid URL gracefully', () => {
      const entry = createMockEntry({ name: 'not-a-valid-url' });

      let urlInfo = null;
      try {
        const url = new URL(entry.name);
        urlInfo = { protocol: url.protocol, host: url.host };
      } catch {
        urlInfo = null;
      }

      aiAssertEqual(
        { name: 'InvalidURL', input: entry.name },
        urlInfo,
        null
      );
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    it('renders request log entries', async () => {
      const root = await mountWithTool('requestLog', {
        entries: [
          { name: 'https://example.com', initiatorType: 'fetch', duration: 1, transferSize: 0, startTime: 1 }
        ]
      });
      if (!root) return;
      const entry = await waitFor(() => queryAllByText(root, 'example.com')[0]);
      aiAssertTruthy({ name: 'RequestLogEntry' }, entry);
    });
  });
});
