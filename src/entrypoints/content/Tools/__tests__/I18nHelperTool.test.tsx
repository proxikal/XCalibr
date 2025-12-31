import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('I18nHelperTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('i18nHelper');
      aiAssertTruthy({ name: 'I18nMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'I18nTitle' }, text, 'i18n');
    });

    it('renders message input', async () => {
      const root = await mountWithTool('i18nHelper');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'I18nMessage' }, text, 'Message');
    });

    it('renders add button', async () => {
      const root = await mountWithTool('i18nHelper');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'I18nAdd' }, text, 'Add');
    });
  });

  describe('Messages', () => {
    it('shows messages list', async () => {
      const root = await mountWithTool('i18nHelper', {
        messages: [{ key: 'hello', message: 'Hello World' }]
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'I18nList' }, text, 'hello');
    });
  });

  describe('Persistence', () => {
    it('persists messages', async () => {
      await mountWithTool('i18nHelper', {
        messages: [{ key: 'test', message: 'Test Message' }]
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { messages?: Array<{ key: string }> }>;
        return toolData.i18nHelper?.messages?.[0]?.key === 'test';
      });
      aiAssertTruthy({ name: 'I18nPersist' }, stored);
    });
  });
});
