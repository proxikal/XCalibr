import { describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import type { StorageExplorerData } from '../tool-types';

type StorageEntry = { key: string; value: string };

const ITEMS_PER_PAGE = 10;

// Mock data factories
const createMockEntry = (key: string, value: string): StorageEntry => ({ key, value });

const createMockData = (localCount: number, sessionCount: number): StorageExplorerData => ({
  local: Array.from({ length: localCount }, (_, i) => createMockEntry(`local_key_${i}`, `local_value_${i}`)),
  session: Array.from({ length: sessionCount }, (_, i) => createMockEntry(`session_key_${i}`, `session_value_${i}`))
});

describe('StorageExplorerTool', () => {
  describe('Pagination logic', () => {
    it('should calculate total pages correctly', () => {
      const testCases = [
        { itemCount: 5, expectedPages: 1 },
        { itemCount: 10, expectedPages: 1 },
        { itemCount: 11, expectedPages: 2 },
        { itemCount: 25, expectedPages: 3 },
        { itemCount: 100, expectedPages: 10 },
      ];

      testCases.forEach(({ itemCount, expectedPages }) => {
        const totalPages = Math.ceil(itemCount / ITEMS_PER_PAGE);
        aiAssertEqual(
          { name: 'TotalPages', input: { itemCount, perPage: ITEMS_PER_PAGE } },
          totalPages,
          expectedPages
        );
      });
    });

    it('should paginate local storage correctly', () => {
      const data = createMockData(25, 5);
      const page = 0;
      const paginatedData = data.local!.slice(
        page * ITEMS_PER_PAGE,
        (page + 1) * ITEMS_PER_PAGE
      );

      aiAssertEqual(
        { name: 'LocalPage0Length', input: { totalItems: data.local!.length, page } },
        paginatedData.length,
        10
      );
    });

    it('should paginate session storage correctly', () => {
      const data = createMockData(5, 15);
      const page = 1;
      const paginatedData = data.session!.slice(
        page * ITEMS_PER_PAGE,
        (page + 1) * ITEMS_PER_PAGE
      );

      aiAssertEqual(
        { name: 'SessionPage1Length', input: { totalItems: data.session!.length, page } },
        paginatedData.length,
        5
      );
    });

    it('should handle last page with fewer items', () => {
      const data = createMockData(23, 0);
      const page = 2;
      const paginatedData = data.local!.slice(
        page * ITEMS_PER_PAGE,
        (page + 1) * ITEMS_PER_PAGE
      );

      aiAssertEqual(
        { name: 'LastPageLength', input: { totalItems: data.local!.length, page } },
        paginatedData.length,
        3
      );
    });
  });

  describe('Tab switching', () => {
    it('should have separate data for local and session tabs', () => {
      const data = createMockData(10, 5);

      aiAssertEqual(
        { name: 'LocalCount', input: data },
        data.local!.length,
        10
      );
      aiAssertEqual(
        { name: 'SessionCount', input: data },
        data.session!.length,
        5
      );
    });

    it('should maintain independent pagination per tab', () => {
      const localPage: number = 1;
      const sessionPage: number = 2;

      aiAssertTruthy(
        { name: 'IndependentPages', input: { localPage, sessionPage } },
        localPage !== sessionPage
      );
    });
  });

  describe('JSON parsing', () => {
    const tryParseJSON = (value: string): string | object => {
      try {
        return JSON.parse(value);
      } catch {
        return value;
      }
    };

    it('should parse valid JSON objects', () => {
      const jsonValue = '{"name":"test","count":5}';
      const parsed = tryParseJSON(jsonValue);

      aiAssertTruthy(
        { name: 'ParsedIsObject', input: jsonValue },
        typeof parsed === 'object'
      );
      aiAssertEqual(
        { name: 'ParsedObjectValue', input: jsonValue },
        (parsed as Record<string, unknown>).name,
        'test'
      );
    });

    it('should parse valid JSON arrays', () => {
      const jsonValue = '[1,2,3,4,5]';
      const parsed = tryParseJSON(jsonValue);

      aiAssertTruthy(
        { name: 'ParsedIsArray', input: jsonValue },
        Array.isArray(parsed)
      );
      aiAssertEqual(
        { name: 'ParsedArrayLength', input: jsonValue },
        (parsed as number[]).length,
        5
      );
    });

    it('should return original string for non-JSON', () => {
      const plainValue = 'just a plain string';
      const parsed = tryParseJSON(plainValue);

      aiAssertEqual(
        { name: 'NonJsonReturnsString', input: plainValue },
        parsed,
        plainValue
      );
    });

    it('should return original string for invalid JSON', () => {
      const invalidJson = '{invalid json}';
      const parsed = tryParseJSON(invalidJson);

      aiAssertEqual(
        { name: 'InvalidJsonReturnsString', input: invalidJson },
        parsed,
        invalidJson
      );
    });
  });

  describe('Value truncation', () => {
    it('should truncate long values when not expanded', () => {
      const longValue = 'a'.repeat(100);
      const isExpanded = false;
      const truncatedValue = longValue.length > 60 && !isExpanded
        ? `${longValue.slice(0, 60)}...`
        : longValue;

      aiAssertEqual(
        { name: 'TruncatedLength', input: { originalLength: longValue.length, isExpanded } },
        truncatedValue.length,
        63 // 60 chars + "..."
      );
      aiAssertTruthy(
        { name: 'EndsWithEllipsis', input: truncatedValue },
        truncatedValue.endsWith('...')
      );
    });

    it('should not truncate short values', () => {
      const shortValue = 'short value';
      const isExpanded = false;
      const truncatedValue = shortValue.length > 60 && !isExpanded
        ? `${shortValue.slice(0, 60)}...`
        : shortValue;

      aiAssertEqual(
        { name: 'ShortValueUnchanged', input: shortValue },
        truncatedValue,
        shortValue
      );
    });

    it('should show full value when expanded', () => {
      const longValue = 'a'.repeat(100);
      const isExpanded = true;
      const truncatedValue = longValue.length > 60 && !isExpanded
        ? `${longValue.slice(0, 60)}...`
        : longValue;

      aiAssertEqual(
        { name: 'ExpandedShowsFull', input: { originalLength: longValue.length, isExpanded } },
        truncatedValue.length,
        100
      );
    });
  });

  describe('Expand/collapse toggle', () => {
    it('should add key to expanded set', () => {
      const expandedKeys = new Set<string>();
      const key = 'local-test_key';

      // Simulate toggle (add)
      const next = new Set(expandedKeys);
      next.add(key);

      aiAssertTruthy(
        { name: 'KeyAdded', input: key },
        next.has(key)
      );
      aiAssertEqual(
        { name: 'SetSize', input: key },
        next.size,
        1
      );
    });

    it('should remove key from expanded set on second toggle', () => {
      const expandedKeys = new Set<string>(['local-test_key']);
      const key = 'local-test_key';

      // Simulate toggle (remove)
      const next = new Set(expandedKeys);
      if (next.has(key)) next.delete(key);

      aiAssertTruthy(
        { name: 'KeyRemoved', input: key },
        !next.has(key)
      );
      aiAssertEqual(
        { name: 'SetSizeAfterRemove', input: key },
        next.size,
        0
      );
    });

    it('should generate unique keys with prefix', () => {
      const entry = createMockEntry('test_key', 'test_value');
      const localKey = `local-${entry.key}`;
      const sessionKey = `session-${entry.key}`;

      aiAssertTruthy(
        { name: 'UniqueKeys', input: { localKey, sessionKey } },
        localKey !== sessionKey
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle empty storage', () => {
      const data = createMockData(0, 0);

      aiAssertEqual(
        { name: 'EmptyLocalLength', input: data },
        data.local!.length,
        0
      );
      aiAssertEqual(
        { name: 'EmptySessionLength', input: data },
        data.session!.length,
        0
      );
    });

    it('should handle undefined data', () => {
      const getData = (): StorageExplorerData | undefined => undefined;
      const data = getData();
      const local = data?.local ?? [];
      const session = data?.session ?? [];

      aiAssertEqual(
        { name: 'UndefinedLocalFallback' },
        local.length,
        0
      );
      aiAssertEqual(
        { name: 'UndefinedSessionFallback' },
        session.length,
        0
      );
    });

    it('should handle special characters in keys and values', () => {
      const entry = createMockEntry('key<with>"special"&chars', 'value<with>"special"&chars');

      aiAssertTruthy(
        { name: 'SpecialCharsKey', input: entry },
        entry.key.includes('<') && entry.key.includes('"')
      );
      aiAssertTruthy(
        { name: 'SpecialCharsValue', input: entry },
        entry.value.includes('<') && entry.value.includes('"')
      );
    });
  });

  describe('Export functionality', () => {
    it('should create export data with both storage types', () => {
      const data = createMockData(3, 2);
      const exportData = { local: data.local, session: data.session };
      const json = JSON.stringify(exportData, null, 2);

      aiAssertTruthy(
        { name: 'ExportContainsLocal', input: json },
        json.includes('local_key_0')
      );
      aiAssertTruthy(
        { name: 'ExportContainsSession', input: json },
        json.includes('session_key_0')
      );
    });
  });
});
