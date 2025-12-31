import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('MarkdownToHtmlTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('markdownToHtml');
      aiAssertTruthy({ name: 'MarkdownMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MarkdownTitle' }, text, 'Markdown to HTML');
    });

    it('renders markdown input area', async () => {
      const root = await mountWithTool('markdownToHtml');
      const textareas = root?.querySelectorAll('textarea') || [];
      aiAssertTruthy({ name: 'MarkdownInput' }, textareas.length >= 1);
    });

    it('renders Convert button', async () => {
      const root = await mountWithTool('markdownToHtml');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MarkdownConvert' }, text, 'Convert');
    });

    it('renders Copy button', async () => {
      const root = await mountWithTool('markdownToHtml');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MarkdownCopy' }, text, 'Copy');
    });
  });

  describe('Conversion', () => {
    it('converts headers', async () => {
      const root = await mountWithTool('markdownToHtml', {
        input: '# Hello',
        output: '<h1>Hello</h1>'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MarkdownHeader' }, text, '<h1>');
    });

    it('converts bold text', async () => {
      const root = await mountWithTool('markdownToHtml', {
        input: '**bold**',
        output: '<strong>bold</strong>'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'MarkdownBold' }, text, '<strong>');
    });
  });

  describe('Persistence', () => {
    it('persists input value', async () => {
      await mountWithTool('markdownToHtml', {
        input: '# Test'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { input?: string }>;
        return toolData.markdownToHtml?.input === '# Test';
      });
      aiAssertTruthy({ name: 'MarkdownPersist' }, stored);
    });
  });
});
