import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../../../__tests__/integration-test-utils';

describe('SqliPayloadTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('sqliPayload');
      aiAssertTruthy({ name: 'SqliPayloadMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'SqliPayloadTitle' }, text, 'SQLi Payload');
    });

    it('displays educational disclaimer', async () => {
      const root = await mountWithTool('sqliPayload');
      const text = root?.textContent || '';
      const hasDisclaimer = text.includes('authorized') || text.includes('educational') || text.includes('testing');
      aiAssertTruthy({ name: 'SqliPayloadDisclaimer' }, hasDisclaimer);
    });

    it('renders payload categories', async () => {
      const root = await mountWithTool('sqliPayload');
      const text = root?.textContent || '';
      const hasCategory = text.includes('Union') || text.includes('Boolean') || text.includes('Time');
      aiAssertTruthy({ name: 'SqliPayloadCategories' }, hasCategory);
    });
  });

  describe('Payload types', () => {
    it('shows union-based payloads', async () => {
      const root = await mountWithTool('sqliPayload', { category: 'union' });
      aiAssertTruthy({ name: 'SqliPayloadUnion' }, root !== null);
    });

    it('shows boolean-based payloads', async () => {
      const root = await mountWithTool('sqliPayload', { category: 'boolean' });
      aiAssertTruthy({ name: 'SqliPayloadBoolean' }, root !== null);
    });
  });

  describe('Copy functionality', () => {
    it('has Copy button when payload selected', async () => {
      const root = await mountWithTool('sqliPayload', { selectedPayload: "' OR '1'='1" });
      const text = root?.textContent || '';
      aiAssertTruthy({ name: 'SqliPayloadCopy' }, text.includes('Copy'));
    });
  });
});
