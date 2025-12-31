import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('HttpStatusReferenceTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('httpStatusReference');
      aiAssertTruthy({ name: 'HttpMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HttpTitle' }, text, 'HTTP Status Code Reference');
    });

    it('renders status code categories', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HttpInfoCat' }, text, '1xx');
      aiAssertIncludes({ name: 'HttpSuccessCat' }, text, '2xx');
      aiAssertIncludes({ name: 'HttpClientCat' }, text, '4xx');
    });

    it('renders search input', async () => {
      const root = await mountWithTool('httpStatusReference');
      const inputs = root?.querySelectorAll('input[type="text"]');
      aiAssertTruthy({ name: 'HttpSearchInput' }, inputs && inputs.length > 0);
    });
  });

  describe('Status Codes - 2xx Success', () => {
    it('shows 200 OK', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http200' }, text, '200');
      aiAssertIncludes({ name: 'HttpOK' }, text, 'OK');
    });

    it('shows 201 Created', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http201' }, text, '201');
      aiAssertIncludes({ name: 'HttpCreated' }, text, 'Created');
    });

    it('shows 204 No Content', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http204' }, text, '204');
    });
  });

  describe('Status Codes - 3xx Redirect', () => {
    it('shows 301 Moved Permanently', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http301' }, text, '301');
    });

    it('shows 302 Found', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http302' }, text, '302');
    });

    it('shows 304 Not Modified', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http304' }, text, '304');
    });
  });

  describe('Status Codes - 4xx Client Error', () => {
    it('shows 400 Bad Request', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http400' }, text, '400');
      aiAssertIncludes({ name: 'HttpBadRequest' }, text, 'Bad Request');
    });

    it('shows 401 Unauthorized', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http401' }, text, '401');
      aiAssertIncludes({ name: 'HttpUnauthorized' }, text, 'Unauthorized');
    });

    it('shows 404 Not Found', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http404' }, text, '404');
      aiAssertIncludes({ name: 'HttpNotFound' }, text, 'Not Found');
    });
  });

  describe('Status Codes - 5xx Server Error', () => {
    it('shows 500 Internal Server Error', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http500' }, text, '500');
    });

    it('shows 502 Bad Gateway', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http502' }, text, '502');
    });

    it('shows 503 Service Unavailable', async () => {
      const root = await mountWithTool('httpStatusReference');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Http503' }, text, '503');
    });
  });

  describe('Search Functionality', () => {
    it('filters by status code', async () => {
      const root = await mountWithTool('httpStatusReference', {
        search: '404'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HttpSearch404' }, text, 'Not Found');
    });

    it('persists search value in state', async () => {
      const root = await mountWithTool('httpStatusReference', {
        search: '500'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { search?: string }>;
        return toolData.httpStatusReference?.search === '500';
      });
      aiAssertTruthy({ name: 'HttpSearchPersist' }, stored);
    });
  });
});
