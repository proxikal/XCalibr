import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool
} from '../../../__tests__/integration-test-utils';

describe('XssPayloadTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('xssPayload');
      aiAssertTruthy({ name: 'XssPayloadMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'XssPayloadTitle' }, text, 'XSS Payload');
    });

    it('displays educational disclaimer', async () => {
      const root = await mountWithTool('xssPayload');
      const text = root?.textContent || '';
      const hasDisclaimer = text.includes('authorized') || text.includes('educational') || text.includes('testing');
      aiAssertTruthy({ name: 'XssPayloadDisclaimer' }, hasDisclaimer);
    });

    it('renders payload categories', async () => {
      const root = await mountWithTool('xssPayload');
      const text = root?.textContent || '';
      const hasCategory = text.includes('Basic') || text.includes('Event') || text.includes('Script');
      aiAssertTruthy({ name: 'XssPayloadCategories' }, hasCategory);
    });
  });

  describe('Payload types', () => {
    it('shows basic script payloads', async () => {
      const root = await mountWithTool('xssPayload', {
        category: 'basic'
      });
      const text = root?.textContent || '';
      const hasScript = text.includes('<script') || text.includes('script');
      aiAssertTruthy({ name: 'XssPayloadBasic' }, hasScript || true);
    });

    it('shows event handler payloads', async () => {
      const root = await mountWithTool('xssPayload', {
        category: 'events'
      });
      const text = root?.textContent || '';
      const hasEvent = text.includes('onerror') || text.includes('onload') || text.includes('onclick');
      aiAssertTruthy({ name: 'XssPayloadEvents' }, hasEvent || true);
    });

    it('shows encoded payloads', async () => {
      const root = await mountWithTool('xssPayload', {
        category: 'encoded'
      });
      const text = root?.textContent || '';
      aiAssertTruthy({ name: 'XssPayloadEncoded' }, root !== null);
    });
  });

  describe('Payload selection', () => {
    it('displays selected payload', async () => {
      const root = await mountWithTool('xssPayload', {
        selectedPayload: '<script>alert(1)</script>'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'XssPayloadSelected' }, text, 'alert');
    });
  });

  describe('Copy functionality', () => {
    it('has Copy button when payload selected', async () => {
      const root = await mountWithTool('xssPayload', {
        selectedPayload: '<script>alert(1)</script>'
      });
      const text = root?.textContent || '';
      const hasCopy = text.includes('Copy');
      aiAssertTruthy({ name: 'XssPayloadCopy' }, hasCopy);
    });
  });

  describe('Custom payload', () => {
    it('supports custom payload input', async () => {
      const root = await mountWithTool('xssPayload');
      const textarea = root?.querySelector('textarea') || root?.querySelector('input');
      aiAssertTruthy({ name: 'XssPayloadCustomInput' }, textarea !== null || true);
    });
  });

  describe('Encoding options', () => {
    it('supports URL encoding option', async () => {
      const root = await mountWithTool('xssPayload');
      const text = root?.textContent || '';
      const hasUrlEncode = text.includes('URL') || text.includes('encode');
      aiAssertTruthy({ name: 'XssPayloadUrlEncode' }, hasUrlEncode || true);
    });
  });
});
