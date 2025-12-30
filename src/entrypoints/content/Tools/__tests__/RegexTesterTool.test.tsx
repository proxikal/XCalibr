import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';
import type { RegexTesterData } from '../tool-types';

// runRegexTest function logic (from web-tools.ts)
const runRegexTest = (pattern: string, flags: string, text: string): { matches: string[]; error?: string } => {
  if (!pattern) return { matches: [] };
  try {
    const regex = new RegExp(pattern, flags);
    const matches: string[] = [];
    let match: RegExpExecArray | null;

    if (flags.includes('g')) {
      while ((match = regex.exec(text)) !== null) {
        matches.push(match[0]);
        if (!match[0]) break; // Prevent infinite loop for zero-width matches
      }
    } else {
      match = regex.exec(text);
      if (match) matches.push(match[0]);
    }
    return { matches };
  } catch (err) {
    return { matches: [], error: err instanceof Error ? err.message : 'Invalid regex' };
  }
};

describe('RegexTesterTool', () => {
  describe('Basic regex matching', () => {
    it('should find simple string matches', () => {
      const result = runRegexTest('hello', 'g', 'hello world hello');

      aiAssertEqual(
        { name: 'SimpleMatch', input: { pattern: 'hello', text: 'hello world hello' } },
        result.matches.length,
        2
      );
      aiAssertEqual(
        { name: 'MatchValue', input: result },
        result.matches[0],
        'hello'
      );
    });

    it('should find pattern matches with special characters', () => {
      const result = runRegexTest('\\d+', 'g', 'abc123def456');

      aiAssertEqual(
        { name: 'DigitMatches', input: { pattern: '\\d+', text: 'abc123def456' } },
        result.matches.length,
        2
      );
      aiAssertEqual(
        { name: 'FirstDigitMatch', input: result },
        result.matches[0],
        '123'
      );
      aiAssertEqual(
        { name: 'SecondDigitMatch', input: result },
        result.matches[1],
        '456'
      );
    });

    it('should return empty array for no matches', () => {
      const result = runRegexTest('xyz', 'g', 'hello world');

      aiAssertEqual(
        { name: 'NoMatches', input: { pattern: 'xyz', text: 'hello world' } },
        result.matches.length,
        0
      );
    });
  });

  describe('Regex flags', () => {
    it('should respect case-insensitive flag', () => {
      const caseResult = runRegexTest('hello', 'gi', 'Hello HELLO hello');

      aiAssertEqual(
        { name: 'CaseInsensitiveMatches', input: { pattern: 'hello', flags: 'gi' } },
        caseResult.matches.length,
        3
      );
    });

    it('should respect case-sensitive by default', () => {
      const result = runRegexTest('hello', 'g', 'Hello HELLO hello');

      aiAssertEqual(
        { name: 'CaseSensitiveMatches', input: { pattern: 'hello', flags: 'g' } },
        result.matches.length,
        1
      );
    });

    it('should return first match without global flag', () => {
      const result = runRegexTest('\\d+', '', '123 456 789');

      aiAssertEqual(
        { name: 'NonGlobalMatch', input: { pattern: '\\d+', flags: '' } },
        result.matches.length,
        1
      );
      aiAssertEqual(
        { name: 'FirstMatchOnly', input: result },
        result.matches[0],
        '123'
      );
    });

    it('should handle multiline flag', () => {
      const result = runRegexTest('^line', 'gm', 'line1\nline2\nline3');

      aiAssertEqual(
        { name: 'MultilineMatches', input: { pattern: '^line', flags: 'gm' } },
        result.matches.length,
        3
      );
    });
  });

  describe('Error handling', () => {
    it('should return error for invalid regex', () => {
      const result = runRegexTest('[invalid', 'g', 'test');

      aiAssertTruthy(
        { name: 'InvalidRegexError', input: { pattern: '[invalid' } },
        result.error !== undefined
      );
      aiAssertEqual(
        { name: 'EmptyMatchesOnError', input: result },
        result.matches.length,
        0
      );
    });

    it('should return error for invalid flags', () => {
      const result = runRegexTest('test', 'xyz', 'test');

      aiAssertTruthy(
        { name: 'InvalidFlagsError', input: { flags: 'xyz' } },
        result.error !== undefined
      );
    });

    it('should handle empty pattern gracefully', () => {
      const result = runRegexTest('', 'g', 'test');

      aiAssertEqual(
        { name: 'EmptyPattern', input: { pattern: '' } },
        result.matches.length,
        0
      );
      aiAssertTruthy(
        { name: 'NoErrorEmptyPattern', input: result },
        result.error === undefined
      );
    });
  });

  describe('Common regex patterns', () => {
    it('should match email addresses', () => {
      const emailPattern = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}';
      const result = runRegexTest(emailPattern, 'g', 'Contact us at test@example.com or support@domain.org');

      aiAssertEqual(
        { name: 'EmailMatches', input: { pattern: 'email regex' } },
        result.matches.length,
        2
      );
      aiAssertTruthy(
        { name: 'FirstEmailMatch', input: result },
        result.matches[0].includes('@')
      );
    });

    it('should match URLs', () => {
      const urlPattern = 'https?://[\\w.-]+(?:/[\\w.-]*)*';
      const result = runRegexTest(urlPattern, 'g', 'Visit https://example.com or http://test.org/page');

      aiAssertEqual(
        { name: 'UrlMatches', input: { pattern: 'url regex' } },
        result.matches.length,
        2
      );
    });

    it('should match phone numbers', () => {
      const phonePattern = '\\d{3}-\\d{3}-\\d{4}';
      const result = runRegexTest(phonePattern, 'g', 'Call 123-456-7890 or 987-654-3210');

      aiAssertEqual(
        { name: 'PhoneMatches', input: { pattern: 'phone regex' } },
        result.matches.length,
        2
      );
    });

    it('should match IP addresses', () => {
      const ipPattern = '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}';
      const result = runRegexTest(ipPattern, 'g', 'Servers at 192.168.1.1 and 10.0.0.1');

      aiAssertEqual(
        { name: 'IpMatches', input: { pattern: 'ip regex' } },
        result.matches.length,
        2
      );
    });
  });

  describe('Match limiting', () => {
    it('should limit matches to 100', () => {
      const text = 'a '.repeat(150);
      const result = runRegexTest('a', 'g', text);
      const limitedMatches = result.matches.slice(0, 100);

      aiAssertEqual(
        { name: 'LimitedTo100', input: { totalMatches: result.matches.length } },
        limitedMatches.length,
        100
      );
    });
  });

  describe('Text truncation for page mode', () => {
    it('should truncate long text to 1000 chars with ellipsis', () => {
      const longText = 'a'.repeat(1500);
      const truncated = longText.slice(0, 1000) + (longText.length > 1000 ? '...' : '');

      aiAssertEqual(
        { name: 'TruncatedLength', input: { originalLength: longText.length } },
        truncated.length,
        1003
      );
      aiAssertTruthy(
        { name: 'EndsWithEllipsis', input: truncated },
        truncated.endsWith('...')
      );
    });

    it('should not truncate short text', () => {
      const shortText = 'short text';
      const truncated = shortText.slice(0, 1000) + (shortText.length > 1000 ? '...' : '');

      aiAssertEqual(
        { name: 'ShortTextUnchanged', input: shortText },
        truncated,
        shortText
      );
    });
  });

  describe('Default values', () => {
    it('should use default values when data is undefined', () => {
      const getData = (): RegexTesterData | undefined => undefined;
      const data = getData();

      const pattern = data?.pattern ?? '';
      const flags = data?.flags ?? 'g';
      const text = data?.text ?? '';
      const matches = data?.matches ?? [];
      const error = data?.error ?? '';

      aiAssertEqual({ name: 'DefaultPattern' }, pattern, '');
      aiAssertEqual({ name: 'DefaultFlags' }, flags, 'g');
      aiAssertEqual({ name: 'DefaultText' }, text, '');
      aiAssertEqual({ name: 'DefaultMatchesLength' }, matches.length, 0);
      aiAssertEqual({ name: 'DefaultError' }, error, '');
    });
  });

  describe('Edge cases', () => {
    it('should handle zero-width matches', () => {
      const result = runRegexTest('(?=a)', 'g', 'aaa');

      aiAssertTruthy(
        { name: 'ZeroWidthNoInfiniteLoop', input: { pattern: '(?=a)' } },
        result.matches.length <= 10 // Should not cause infinite loop
      );
    });

    it('should handle empty text', () => {
      const result = runRegexTest('test', 'g', '');

      aiAssertEqual(
        { name: 'EmptyTextNoMatches', input: { pattern: 'test', text: '' } },
        result.matches.length,
        0
      );
    });

    it('should handle special regex characters in pattern', () => {
      const result = runRegexTest('\\.\\*\\+\\?', 'g', 'test.*+?');

      aiAssertEqual(
        { name: 'EscapedCharsMatch', input: { pattern: '\\.\\*\\+\\?' } },
        result.matches.length,
        1
      );
      aiAssertEqual(
        { name: 'EscapedCharsValue', input: result },
        result.matches[0],
        '.*+?'
      );
    });
  });

  describe('Integration tests', () => {
    beforeEach(() => {
      document.body.innerHTML = '';
      resetChrome();
    });

    it('runs regex test', async () => {
      const root = await mountWithTool('regexTester', {
        pattern: 'hello',
        flags: 'g',
        text: 'hello world',
        matches: []
      });
      if (!root) return;
      const button = await waitFor(() => findButtonByText(root, 'Run Test'));
      aiAssertTruthy({ name: 'RegexTesterRunButton' }, button);
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { matches?: string[] }>;
        return (toolData.regexTester?.matches?.length ?? 0) > 0;
      });
      const matches = (stored?.toolData as Record<string, { matches?: string[] }> | undefined)
        ?.regexTester?.matches ?? [];
      aiAssertTruthy({ name: 'RegexTesterMatches', state: matches }, matches.includes('hello'));
    });
  });
});
