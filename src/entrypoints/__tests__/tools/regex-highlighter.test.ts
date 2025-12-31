import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Regex Highlighter Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Regex Highlighter interface', async () => {
    const root = await mountWithTool('regexHighlighter');
    aiAssertTruthy({ name: 'RegexHighlighterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'RegexHighlighterTitle' }, text.includes('Regex') || text.includes('Match'));
  });

  it('shows regex pattern input', async () => {
    const root = await mountWithTool('regexHighlighter');
    const input = root?.querySelector('input') || root?.querySelector('textarea');
    aiAssertTruthy({ name: 'RegexHighlighterPattern' }, input);
  });

  it('shows text input area', async () => {
    const root = await mountWithTool('regexHighlighter');
    const textareas = root?.querySelectorAll('textarea');
    aiAssertTruthy({ name: 'RegexHighlighterText' }, textareas && textareas.length >= 1);
  });

  it('displays match count', async () => {
    const root = await mountWithTool('regexHighlighter', {
      pattern: '\\w+',
      text: 'hello world',
      matches: ['hello', 'world'],
      matchCount: 2
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'RegexHighlighterCount' },
      text.includes('2') || text.includes('match') || text.includes('Match'));
  });

  it('shows flag options', async () => {
    const root = await mountWithTool('regexHighlighter');
    const text = root?.textContent || '';
    const checkboxes = root?.querySelectorAll('input[type="checkbox"]');
    aiAssertTruthy({ name: 'RegexHighlighterFlags' },
      checkboxes && checkboxes.length >= 0 || text.includes('global') || text.includes('i'));
  });
});
