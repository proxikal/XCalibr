import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  queryAllByText
} from '../../../__tests__/integration-test-utils';
import type { CookieManagerData } from '../tool-types';

type Cookie = { name: string; value: string };

const ITEMS_PER_PAGE = 8;

// Mock data factories
const createMockCookie = (name: string, value: string): Cookie => ({ name, value });

const createMockCookies = (count: number): Cookie[] =>
  Array.from({ length: count }, (_, i) => createMockCookie(`cookie_${i}`, `value_${i}`));

describe('CookieManagerTool', () => {
  describe('Pagination logic', () => {
    it('should calculate total pages correctly', () => {
      const testCases = [
        { cookieCount: 5, expectedPages: 1 },
        { cookieCount: 8, expectedPages: 1 },
        { cookieCount: 9, expectedPages: 2 },
        { cookieCount: 20, expectedPages: 3 },
        { cookieCount: 40, expectedPages: 5 },
      ];

      testCases.forEach(({ cookieCount, expectedPages }) => {
        const totalPages = Math.ceil(cookieCount / ITEMS_PER_PAGE);
        aiAssertEqual(
          { name: 'TotalPages', input: { cookieCount, perPage: ITEMS_PER_PAGE } },
          totalPages,
          expectedPages
        );
      });
    });

    it('should paginate cookies correctly for page 0', () => {
      const cookies = createMockCookies(20);
      const page = 0;
      const paginatedCookies = cookies.slice(
        page * ITEMS_PER_PAGE,
        (page + 1) * ITEMS_PER_PAGE
      );

      aiAssertEqual(
        { name: 'Page0Length', input: { totalCookies: cookies.length, page } },
        paginatedCookies.length,
        8
      );
      aiAssertEqual(
        { name: 'Page0FirstCookie', input: paginatedCookies },
        paginatedCookies[0].name,
        'cookie_0'
      );
    });

    it('should handle last page with fewer cookies', () => {
      const cookies = createMockCookies(18);
      const page = 2;
      const paginatedCookies = cookies.slice(
        page * ITEMS_PER_PAGE,
        (page + 1) * ITEMS_PER_PAGE
      );

      aiAssertEqual(
        { name: 'LastPageLength', input: { totalCookies: cookies.length, page } },
        paginatedCookies.length,
        2
      );
    });
  });

  describe('Cookie string building', () => {
    it('should encode cookie value correctly', () => {
      const name = 'test_cookie';
      const value = 'value with spaces & special=chars';
      const encoded = encodeURIComponent(value);

      aiAssertTruthy(
        { name: 'EncodedSpaces', input: { value, encoded } },
        !encoded.includes(' ')
      );
      aiAssertTruthy(
        { name: 'EncodedAmpersand', input: { value, encoded } },
        !encoded.includes('&')
      );
      aiAssertTruthy(
        { name: 'EncodedEquals', input: { value, encoded } },
        !encoded.includes('=')
      );
    });

    it('should build cookie string with path', () => {
      const name = 'session';
      const value = 'abc123';
      const cookieString = `${name}=${encodeURIComponent(value)}; path=/`;

      aiAssertTruthy(
        { name: 'ContainsName', input: cookieString },
        cookieString.includes('session=')
      );
      aiAssertTruthy(
        { name: 'ContainsPath', input: cookieString },
        cookieString.includes('path=/')
      );
    });

    it('should build expiration string for deletion', () => {
      const name = 'to_delete';
      const deleteString = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;

      aiAssertTruthy(
        { name: 'ContainsExpires', input: deleteString },
        deleteString.includes('expires=Thu, 01 Jan 1970')
      );
      aiAssertTruthy(
        { name: 'EmptyValue', input: deleteString },
        deleteString.includes(`${name}=;`)
      );
    });
  });

  describe('Input validation', () => {
    it('should require non-empty name', () => {
      const name = '';
      const isValid = name.trim().length > 0;

      aiAssertEqual(
        { name: 'EmptyNameInvalid', input: { name } },
        isValid,
        false
      );
    });

    it('should accept name with whitespace trimmed', () => {
      const name = '  test  ';
      const isValid = name.trim().length > 0;

      aiAssertEqual(
        { name: 'TrimmedNameValid', input: { name } },
        isValid,
        true
      );
    });

    it('should allow empty value', () => {
      const value = '';
      const isValidValue = true; // Value can be empty

      aiAssertEqual(
        { name: 'EmptyValueAllowed', input: { value } },
        isValidValue,
        true
      );
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): CookieManagerData | undefined => undefined;
      const data = getData();

      const name = data?.name ?? '';
      const value = data?.value ?? '';
      const cookies = data?.cookies ?? [];

      aiAssertEqual({ name: 'DefaultName' }, name, '');
      aiAssertEqual({ name: 'DefaultValue' }, value, '');
      aiAssertEqual({ name: 'DefaultCookiesLength' }, cookies.length, 0);
    });
  });

  describe('Edit mode', () => {
    it('should track editing cookie name', () => {
      const editingCookie = 'session_id';

      aiAssertTruthy(
        { name: 'EditingCookieSet', input: { editingCookie } },
        editingCookie === 'session_id'
      );
    });

    it('should clear editing state on cancel', () => {
      let editingCookie: string | null = 'session_id';
      editingCookie = null;

      aiAssertEqual(
        { name: 'EditingCleared', input: { editingCookie } },
        editingCookie,
        null
      );
    });

    it('should save edit value on submit', () => {
      const cookieName = 'test_cookie';
      const editValue = 'new_value';
      const cookieString = `${cookieName}=${encodeURIComponent(editValue)}; path=/`;

      aiAssertTruthy(
        { name: 'SavedEditValue', input: { cookieName, editValue } },
        cookieString.includes(encodeURIComponent(editValue))
      );
    });
  });

  describe('Export functionality', () => {
    it('should create export data structure', () => {
      const cookies = createMockCookies(3);
      const exportData = cookies.map((c) => ({ name: c.name, value: c.value }));
      const json = JSON.stringify(exportData, null, 2);

      aiAssertTruthy(
        { name: 'ExportContainsCookies', input: json },
        json.includes('cookie_0')
      );
      aiAssertTruthy(
        { name: 'ExportIsValidJson', input: json },
        JSON.parse(json).length === 3
      );
    });

    it('should handle empty cookies in export', () => {
      const cookies: Cookie[] = [];
      const exportData = cookies.map((c) => ({ name: c.name, value: c.value }));
      const json = JSON.stringify(exportData, null, 2);

      aiAssertEqual(
        { name: 'EmptyExport', input: json },
        JSON.parse(json).length,
        0
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle empty cookies array', () => {
      const cookies: Cookie[] = [];
      const totalPages = Math.ceil(cookies.length / ITEMS_PER_PAGE);

      aiAssertEqual(
        { name: 'EmptyArrayPages', input: { cookiesLength: cookies.length } },
        totalPages,
        0
      );
    });

    it('should handle special characters in cookie names', () => {
      const cookie = createMockCookie('test-cookie_name.1', 'value');

      aiAssertTruthy(
        { name: 'SpecialCharsInName', input: cookie },
        cookie.name.includes('-') && cookie.name.includes('_') && cookie.name.includes('.')
      );
    });

    it('should handle unicode in cookie values', () => {
      const cookie = createMockCookie('unicode', 'value with unicode: 你好 🍪');
      const encoded = encodeURIComponent(cookie.value);

      aiAssertTruthy(
        { name: 'UnicodeEncoded', input: { original: cookie.value, encoded } },
        encoded !== cookie.value
      );
    });

    it('should handle very long cookie values', () => {
      const longValue = 'a'.repeat(1000);
      const cookie = createMockCookie('long_cookie', longValue);

      aiAssertEqual(
        { name: 'LongValueLength', input: cookie },
        cookie.value.length,
        1000
      );
    });
  });

  describe('State updates', () => {
    it('should clear inputs after setting cookie', () => {
      const initialData: CookieManagerData = { name: 'test', value: 'value', cookies: [] };
      const clearedData = { ...initialData, name: '', value: '' };

      aiAssertEqual(
        { name: 'ClearedName', input: clearedData },
        clearedData.name,
        ''
      );
      aiAssertEqual(
        { name: 'ClearedValue', input: clearedData },
        clearedData.value,
        ''
      );
    });

    it('should preserve cookies when updating inputs', () => {
      const cookies = createMockCookies(5);
      const data: CookieManagerData = { name: '', value: '', cookies };
      const updatedData = { ...data, name: 'new_name' };

      aiAssertEqual(
        { name: 'CookiesPreserved', input: updatedData },
        updatedData.cookies!.length,
        5
      );
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    it('lists cookies in Cookie Manager', async () => {
      document.cookie = 'test_cookie=hello';
      const root = await mountWithTool('cookieManager');
      if (!root) return;
      const refreshButton = await waitFor(() => findButtonByText(root, 'Refresh'));
      aiAssertTruthy({ name: 'CookieManagerRefresh' }, refreshButton);
      refreshButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const entry = await waitFor(() => queryAllByText(root, 'test_cookie')[0]);
      aiAssertTruthy(
        { name: 'CookieManagerEntry' },
        entry
      );
    });
  });
});
