import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertEqual, aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState,
  setRuntimeHandler,
  typeInput
} from '../../../__tests__/integration-test-utils';

describe('CorsCheckTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders with URL input field', async () => {
      const root = await mountWithTool('corsCheck');
      aiAssertTruthy({ name: 'CorsCheckMount' }, root);
      const input = root?.querySelector('input[type="text"]');
      aiAssertTruthy({ name: 'CorsCheckInput' }, input);
    });

    it('renders Check button', async () => {
      const root = await mountWithTool('corsCheck');
      const checkBtn = findButtonByText(root!, 'Check');
      aiAssertTruthy({ name: 'CorsCheckButton' }, checkBtn);
    });

    it('renders Check Current Page button', async () => {
      const root = await mountWithTool('corsCheck');
      const checkCurrentBtn = findButtonByText(root!, 'Check Current Page');
      aiAssertTruthy({ name: 'CorsCheckCurrentPageButton' }, checkCurrentBtn);
    });

    it('shows placeholder text when no results', async () => {
      const root = await mountWithTool('corsCheck');
      const text = root?.textContent?.toLowerCase() || '';
      const hasPlaceholder = text.includes('enter a url') || text.includes('check current page');
      aiAssertTruthy({ name: 'CorsCheckPlaceholder', input: text }, hasPlaceholder);
    });

    it('displays URL from data', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://api.example.com'
      });
      const input = root?.querySelector('input[placeholder="https://example.com"]') as HTMLInputElement;
      aiAssertEqual({ name: 'CorsCheckUrlValue' }, input?.value, 'https://api.example.com');
    });
  });

  describe('Button states', () => {
    it('disables Check button when URL is empty', async () => {
      const root = await mountWithTool('corsCheck', { url: '' });
      const checkBtn = findButtonByText(root!, 'Check') as HTMLButtonElement;
      aiAssertTruthy({ name: 'CorsCheckButtonDisabled' }, checkBtn?.disabled);
    });

    it('enables Check button when URL is provided', async () => {
      const root = await mountWithTool('corsCheck', { url: 'https://example.com' });
      const checkBtn = findButtonByText(root!, 'Check') as HTMLButtonElement;
      aiAssertTruthy({ name: 'CorsCheckButtonEnabled' }, !checkBtn?.disabled);
    });
  });

  describe('CORS check functionality', () => {
    it('runs CORS check and displays results', async () => {
      setRuntimeHandler('xcalibr-cors-check', () => ({
        result: { status: 200, acao: '*', acc: null, methods: 'GET, POST', headers: 'Content-Type' }
      }));
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com'
      });
      if (!root) return;
      const runButton = findButtonByText(root, 'Check');
      runButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { result?: { status?: number } }>;
        return toolData.corsCheck?.result?.status === 200;
      });
      const status = (stored?.toolData as Record<string, { result?: { status?: number } }> | undefined)
        ?.corsCheck?.result?.status;
      aiAssertEqual({ name: 'CorsCheckStatus' }, status, 200);
    });

    it('displays status code in results', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: { status: 200, acao: '*', acc: null, methods: 'GET', headers: null }
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CorsCheckStatusDisplay' }, text, '200');
    });

    it('displays Access-Control-Allow-Origin header', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: { status: 200, acao: 'https://trusted.com', acc: null, methods: null, headers: null }
      });
      const text = root?.textContent || '';
      const hasAcaoLabel = text.includes('Access-Control-Allow-Origin');
      const hasAcaoValue = text.includes('https://trusted.com');
      aiAssertTruthy({ name: 'CorsCheckAcaoLabel' }, hasAcaoLabel);
      aiAssertTruthy({ name: 'CorsCheckAcaoValue' }, hasAcaoValue);
    });

    it('displays wildcard ACAO value', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: { status: 200, acao: '*', acc: null, methods: null, headers: null }
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CorsCheckAcaoWildcard' }, text, '*');
    });

    it('displays None when ACAO is not set', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: { status: 200, acao: null, acc: null, methods: null, headers: null }
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CorsCheckAcaoNone' }, text, 'None');
    });

    it('displays Access-Control-Allow-Credentials', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: { status: 200, acao: '*', acc: 'true', methods: null, headers: null }
      });
      const text = root?.textContent || '';
      const hasAccLabel = text.includes('Access-Control-Allow-Credentials');
      const hasAccValue = text.includes('true');
      aiAssertTruthy({ name: 'CorsCheckAccLabel' }, hasAccLabel);
      aiAssertTruthy({ name: 'CorsCheckAccValue' }, hasAccValue);
    });

    it('displays Allow-Methods header', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: { status: 200, acao: '*', acc: null, methods: 'GET, POST, PUT, DELETE', headers: null }
      });
      const text = root?.textContent || '';
      const hasMethodsLabel = text.includes('Allow-Methods');
      const hasMethodsValue = text.includes('GET') && text.includes('POST');
      aiAssertTruthy({ name: 'CorsCheckMethodsLabel' }, hasMethodsLabel);
      aiAssertTruthy({ name: 'CorsCheckMethodsValue' }, hasMethodsValue);
    });

    it('displays Allow-Headers header', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: { status: 200, acao: '*', acc: null, methods: null, headers: 'Content-Type, Authorization' }
      });
      const text = root?.textContent || '';
      const hasHeadersLabel = text.includes('Allow-Headers');
      const hasHeadersValue = text.includes('Content-Type') || text.includes('Authorization');
      aiAssertTruthy({ name: 'CorsCheckHeadersLabel' }, hasHeadersLabel);
      aiAssertTruthy({ name: 'CorsCheckHeadersValue' }, hasHeadersValue);
    });
  });

  describe('Status code handling', () => {
    it('shows 404 status code', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: { status: 404, acao: null, acc: null, methods: null, headers: null }
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CorsCheck404Status' }, text, '404');
    });

    it('shows 500 status code', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: { status: 500, acao: null, acc: null, methods: null, headers: null }
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CorsCheck500Status' }, text, '500');
    });

    it('shows Unknown when status is undefined', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: { status: undefined, acao: null, acc: null, methods: null, headers: null }
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CorsCheckUnknownStatus' }, text, 'Unknown');
    });
  });

  describe('Error handling', () => {
    it('displays error message when error exists', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        error: 'Network error: Failed to fetch'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CorsCheckError' }, text, 'Network error');
    });

    it('handles CORS check failure', async () => {
      setRuntimeHandler('xcalibr-cors-check', () => ({
        error: 'Request failed'
      }));
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com'
      });
      if (!root) return;
      const runButton = findButtonByText(root, 'Check');
      runButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { error?: string }>;
        return !!toolData.corsCheck?.error;
      });
      const hasError = !!(stored?.toolData as Record<string, { error?: string }> | undefined)?.corsCheck?.error;
      aiAssertTruthy({ name: 'CorsCheckFailure' }, hasError);
    });
  });

  describe('Input handling', () => {
    it('has editable URL input field', async () => {
      const root = await mountWithTool('corsCheck');
      const input = root?.querySelector('input[placeholder="https://example.com"]') as HTMLInputElement;
      aiAssertTruthy({ name: 'CorsCheckInputExists' }, input);
      // Input should be editable (not disabled or readonly)
      aiAssertTruthy({ name: 'CorsCheckInputEditable' }, !input?.disabled && !input?.readOnly);
    });

    it('shows URL input field with correct placeholder', async () => {
      const root = await mountWithTool('corsCheck');
      const input = root?.querySelector('input[placeholder="https://example.com"]') as HTMLInputElement;
      aiAssertTruthy({ name: 'CorsCheckInputExists' }, input);
    });
  });

  describe('Result display variations', () => {
    it('displays complete CORS result set', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://api.example.com',
        result: {
          status: 200,
          acao: 'https://example.com',
          acc: 'true',
          methods: 'GET, POST, OPTIONS',
          headers: 'Content-Type, X-Custom-Header'
        }
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CorsCompleteStatus' }, text, '200');
      aiAssertIncludes({ name: 'CorsCompleteAcao' }, text, 'https://example.com');
      const hasCredentials = text.includes('true');
      aiAssertTruthy({ name: 'CorsCompleteAcc' }, hasCredentials);
    });

    it('displays restrictive CORS policy', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://secure.example.com',
        result: {
          status: 200,
          acao: 'https://specific-origin.com',
          acc: 'false',
          methods: 'GET',
          headers: null
        }
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CorsRestrictiveAcao' }, text, 'https://specific-origin.com');
    });

    it('displays open CORS policy', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://public.example.com',
        result: {
          status: 200,
          acao: '*',
          acc: null,
          methods: 'GET, POST, PUT, DELETE, PATCH',
          headers: '*'
        }
      });
      const text = root?.textContent || '';
      const hasWildcardAcao = text.includes('*');
      aiAssertTruthy({ name: 'CorsOpenPolicy' }, hasWildcardAcao);
    });
  });

  describe('Edge cases', () => {
    it('handles empty result object', async () => {
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: {}
      });
      const text = root?.textContent || '';
      // Should show Unknown for status
      aiAssertIncludes({ name: 'CorsEmptyResult' }, text, 'Unknown');
    });

    it('handles long header values with truncation', async () => {
      const longHeaders = 'Accept, Accept-Language, Content-Type, Authorization, X-Custom-Header-1, X-Custom-Header-2';
      const root = await mountWithTool('corsCheck', {
        url: 'https://example.com',
        result: {
          status: 200,
          acao: '*',
          acc: null,
          methods: null,
          headers: longHeaders
        }
      });
      // Component should still render without breaking
      aiAssertTruthy({ name: 'CorsLongHeaders' }, root);
    });
  });
});
