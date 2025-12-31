import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitFor
} from '../../../__tests__/integration-test-utils';

describe('ParamAnalyzerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('paramAnalyzer');
      aiAssertTruthy({ name: 'ParamAnalyzerMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ParamAnalyzerTitle' }, text, 'Param Analyzer');
    });

    it('renders Refresh button', async () => {
      const root = await mountWithTool('paramAnalyzer');
      const refreshBtn = findButtonByText(root!, 'Refresh');
      aiAssertTruthy({ name: 'ParamAnalyzerRefreshBtn' }, refreshBtn);
    });

    it('renders Add Param button', async () => {
      const root = await mountWithTool('paramAnalyzer');
      const addBtn = findButtonByText(root!, 'Add Param');
      aiAssertTruthy({ name: 'ParamAnalyzerAddBtn' }, addBtn);
    });

    it('renders Copy Updated URL button', async () => {
      const root = await mountWithTool('paramAnalyzer');
      const copyBtn = findButtonByText(root!, 'Copy Updated URL');
      aiAssertTruthy({ name: 'ParamAnalyzerCopyBtn' }, copyBtn);
    });

    it('renders Open Updated URL button', async () => {
      const root = await mountWithTool('paramAnalyzer');
      const openBtn = findButtonByText(root!, 'Open Updated URL');
      aiAssertTruthy({ name: 'ParamAnalyzerOpenBtn' }, openBtn);
    });
  });

  describe('No parameters state', () => {
    it('shows no parameters message when params are empty', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com',
        params: []
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ParamAnalyzerNoParams' }, text, 'No query parameters detected');
    });

    it('shows no parameters message when params is undefined', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ParamAnalyzerNoParamsUndefined' }, text, 'No query parameters detected');
    });
  });

  describe('URL display', () => {
    it('displays the current URL', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/page?foo=bar'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ParamAnalyzerUrlDisplay' }, text, 'https://example.com/page?foo=bar');
    });

    it('displays URL without query params', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://api.example.com/v1/users'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ParamAnalyzerUrlNoParams' }, text, 'https://api.example.com/v1/users');
    });
  });

  describe('Parameter display', () => {
    it('displays single parameter with key and value inputs', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?a=1',
        params: [{ key: 'a', value: '1' }]
      });
      const keyInputs = root?.querySelectorAll('input[placeholder="Key"]');
      const valueInputs = root?.querySelectorAll('input[placeholder="Value"]');
      aiAssertEqual({ name: 'ParamAnalyzerKeyInputCount' }, keyInputs?.length, 1);
      aiAssertEqual({ name: 'ParamAnalyzerValueInputCount' }, valueInputs?.length, 1);
    });

    it('displays multiple parameters', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?a=1&b=2&c=3',
        params: [
          { key: 'a', value: '1' },
          { key: 'b', value: '2' },
          { key: 'c', value: '3' }
        ]
      });
      const keyInputs = root?.querySelectorAll('input[placeholder="Key"]');
      aiAssertEqual({ name: 'ParamAnalyzerMultipleParams' }, keyInputs?.length, 3);
    });

    it('displays parameter key values correctly', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?name=john',
        params: [{ key: 'name', value: 'john' }]
      });
      const keyInput = root?.querySelector('input[placeholder="Key"]') as HTMLInputElement;
      aiAssertEqual({ name: 'ParamAnalyzerKeyValue' }, keyInput?.value, 'name');
    });

    it('displays parameter value correctly', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?name=john',
        params: [{ key: 'name', value: 'john' }]
      });
      const valueInput = root?.querySelector('input[placeholder="Value"]') as HTMLInputElement;
      aiAssertEqual({ name: 'ParamAnalyzerValueValue' }, valueInput?.value, 'john');
    });

    it('displays delete button for each parameter', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?a=1&b=2',
        params: [
          { key: 'a', value: '1' },
          { key: 'b', value: '2' }
        ]
      });
      const deleteButtons = Array.from(root?.querySelectorAll('button') || [])
        .filter(btn => btn.textContent === '×');
      // Should have at least 2 delete buttons (one for each param)
      aiAssertTruthy({ name: 'ParamAnalyzerDeleteBtns' }, deleteButtons.length >= 2);
    });
  });

  describe('Add parameter functionality', () => {
    it('Add Param button is clickable', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com',
        params: []
      });
      const addBtn = findButtonByText(root!, 'Add Param') as HTMLButtonElement;
      aiAssertTruthy({ name: 'ParamAnalyzerAddBtnClickable' }, addBtn && !addBtn.disabled);
    });

    it('clicking Add Param adds new empty parameter', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com',
        params: []
      });
      const addBtn = findButtonByText(root!, 'Add Param');
      addBtn?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();

      const keyInputs = await waitFor(() => {
        const inputs = root?.querySelectorAll('input[placeholder="Key"]');
        return inputs && inputs.length > 0 ? inputs : null;
      });
      aiAssertTruthy({ name: 'ParamAnalyzerAddedParam' }, keyInputs && keyInputs.length > 0);
    });
  });

  describe('URL action buttons', () => {
    it('Copy Updated URL button exists and is clickable', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?test=1',
        params: [{ key: 'test', value: '1' }]
      });
      const copyBtn = findButtonByText(root!, 'Copy Updated URL') as HTMLButtonElement;
      aiAssertTruthy({ name: 'ParamAnalyzerCopyBtnClickable' }, copyBtn && !copyBtn.disabled);
    });

    it('Open Updated URL button exists and is clickable', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?test=1',
        params: [{ key: 'test', value: '1' }]
      });
      const openBtn = findButtonByText(root!, 'Open Updated URL') as HTMLButtonElement;
      aiAssertTruthy({ name: 'ParamAnalyzerOpenBtnClickable' }, openBtn && !openBtn.disabled);
    });
  });

  describe('Edge cases', () => {
    it('handles empty key parameter', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?=value',
        params: [{ key: '', value: 'value' }]
      });
      const keyInput = root?.querySelector('input[placeholder="Key"]') as HTMLInputElement;
      aiAssertEqual({ name: 'ParamAnalyzerEmptyKey' }, keyInput?.value, '');
    });

    it('handles empty value parameter', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?key=',
        params: [{ key: 'key', value: '' }]
      });
      const valueInput = root?.querySelector('input[placeholder="Value"]') as HTMLInputElement;
      aiAssertEqual({ name: 'ParamAnalyzerEmptyValue' }, valueInput?.value, '');
    });

    it('handles special characters in parameter key', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?user[name]=john',
        params: [{ key: 'user[name]', value: 'john' }]
      });
      const keyInput = root?.querySelector('input[placeholder="Key"]') as HTMLInputElement;
      aiAssertEqual({ name: 'ParamAnalyzerSpecialKey' }, keyInput?.value, 'user[name]');
    });

    it('handles special characters in parameter value', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?query=hello%20world',
        params: [{ key: 'query', value: 'hello world' }]
      });
      const valueInput = root?.querySelector('input[placeholder="Value"]') as HTMLInputElement;
      aiAssertEqual({ name: 'ParamAnalyzerSpecialValue' }, valueInput?.value, 'hello world');
    });

    it('handles long parameter values', async () => {
      const longValue = 'a'.repeat(200);
      const root = await mountWithTool('paramAnalyzer', {
        url: `https://example.com/?data=${longValue}`,
        params: [{ key: 'data', value: longValue }]
      });
      const valueInput = root?.querySelector('input[placeholder="Value"]') as HTMLInputElement;
      aiAssertEqual({ name: 'ParamAnalyzerLongValue' }, valueInput?.value, longValue);
    });

    it('handles many parameters', async () => {
      const params = Array.from({ length: 10 }, (_, i) => ({
        key: `param${i}`,
        value: `value${i}`
      }));
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?many=params',
        params
      });
      const keyInputs = root?.querySelectorAll('input[placeholder="Key"]');
      aiAssertEqual({ name: 'ParamAnalyzerManyParams' }, keyInputs?.length, 10);
    });
  });

  describe('URL format variations', () => {
    it('handles URL with hash', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/page?tab=1#section',
        params: [{ key: 'tab', value: '1' }]
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ParamAnalyzerUrlWithHash' }, text, '#section');
    });

    it('handles URL with port', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://localhost:3000/api?debug=true',
        params: [{ key: 'debug', value: 'true' }]
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ParamAnalyzerUrlWithPort' }, text, 'localhost:3000');
    });

    it('handles URL with path', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://api.example.com/v1/users/123?fields=name,email',
        params: [{ key: 'fields', value: 'name,email' }]
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'ParamAnalyzerUrlWithPath' }, text, '/v1/users/123');
    });
  });

  describe('Input field attributes', () => {
    it('key input has correct placeholder', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?a=1',
        params: [{ key: 'a', value: '1' }]
      });
      const keyInput = root?.querySelector('input[placeholder="Key"]') as HTMLInputElement;
      aiAssertTruthy({ name: 'ParamAnalyzerKeyPlaceholder' }, keyInput);
    });

    it('value input has correct placeholder', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?a=1',
        params: [{ key: 'a', value: '1' }]
      });
      const valueInput = root?.querySelector('input[placeholder="Value"]') as HTMLInputElement;
      aiAssertTruthy({ name: 'ParamAnalyzerValuePlaceholder' }, valueInput);
    });

    it('inputs are editable', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?a=1',
        params: [{ key: 'a', value: '1' }]
      });
      const keyInput = root?.querySelector('input[placeholder="Key"]') as HTMLInputElement;
      const valueInput = root?.querySelector('input[placeholder="Value"]') as HTMLInputElement;
      aiAssertTruthy({ name: 'ParamAnalyzerKeyEditable' }, !keyInput?.disabled && !keyInput?.readOnly);
      aiAssertTruthy({ name: 'ParamAnalyzerValueEditable' }, !valueInput?.disabled && !valueInput?.readOnly);
    });
  });
});
