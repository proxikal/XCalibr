import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../../../__tests__/integration-test-utils';

describe('UserAgentTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('userAgent');
      aiAssertTruthy({ name: 'UserAgentMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'UserAgentTitle' }, text, 'User-Agent');
    });

    it('renders browser categories', async () => {
      const root = await mountWithTool('userAgent');
      const text = root?.textContent || '';
      const hasChrome = text.includes('Chrome');
      const hasFirefox = text.includes('Firefox');
      aiAssertTruthy({ name: 'UserAgentCategories' }, hasChrome || hasFirefox);
    });
  });

  describe('User-Agent display', () => {
    it('displays selected user-agent', async () => {
      const root = await mountWithTool('userAgent', {
        selectedAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'UserAgentSelected' }, text, 'Mozilla');
    });
  });

  describe('Copy functionality', () => {
    it('has Copy button when agent selected', async () => {
      const root = await mountWithTool('userAgent', { selectedAgent: 'Mozilla/5.0' });
      const text = root?.textContent || '';
      aiAssertTruthy({ name: 'UserAgentCopy' }, text.includes('Copy'));
    });
  });
});
