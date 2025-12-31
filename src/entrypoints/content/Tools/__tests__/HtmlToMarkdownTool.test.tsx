import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('HtmlToMarkdownTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('htmlToMarkdown');
      aiAssertTruthy({ name: 'HtmlToMdMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtmlToMdTitle' }, text, 'HTML to Markdown');
    });

    it('renders HTML input area', async () => {
      const root = await mountWithTool('htmlToMarkdown');
      const textareas = root?.querySelectorAll('textarea') || [];
      aiAssertTruthy({ name: 'HtmlToMdInput' }, textareas.length >= 1);
    });

    it('renders Convert button', async () => {
      const root = await mountWithTool('htmlToMarkdown');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtmlToMdConvert' }, text, 'Convert');
    });
  });

  describe('Conversion', () => {
    it('converts headers', async () => {
      const root = await mountWithTool('htmlToMarkdown', {
        input: '<h1>Hello</h1>',
        output: '# Hello'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtmlToMdHeader' }, text, '# Hello');
    });

    it('converts bold text', async () => {
      const root = await mountWithTool('htmlToMarkdown', {
        input: '<strong>bold</strong>',
        output: '**bold**'
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'HtmlToMdBold' }, text, '**bold**');
    });
  });

  describe('Persistence', () => {
    it('persists input value', async () => {
      await mountWithTool('htmlToMarkdown', {
        input: '<h1>Test</h1>'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { input?: string }>;
        return toolData.htmlToMarkdown?.input === '<h1>Test</h1>';
      });
      aiAssertTruthy({ name: 'HtmlToMdPersist' }, stored);
    });
  });
});
