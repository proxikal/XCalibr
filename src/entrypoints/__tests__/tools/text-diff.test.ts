import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('Text Diff Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Text Diff interface', async () => {
    const root = await mountWithTool('textDiff');
    aiAssertTruthy({ name: 'TextDiffRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TextDiffTitle' }, text.includes('Diff') || text.includes('Compare'));
  });

  it('shows two textareas for comparison', async () => {
    const root = await mountWithTool('textDiff');
    const textareas = root?.querySelectorAll('textarea');
    aiAssertTruthy({ name: 'TextDiffTextareas' }, textareas && textareas.length >= 2);
  });

  it('has compare button', async () => {
    const root = await mountWithTool('textDiff');
    const btn = findButtonByText(root!, 'Compare') || findButtonByText(root!, 'Diff');
    aiAssertTruthy({ name: 'TextDiffButton' }, btn);
  });

  it('displays diff results', async () => {
    const root = await mountWithTool('textDiff', {
      text1: 'hello world',
      text2: 'hello there',
      diffResult: [{ type: 'equal', value: 'hello ' }, { type: 'removed', value: 'world' }, { type: 'added', value: 'there' }]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TextDiffResults' },
      text.includes('hello') || text.includes('world') || text.includes('there'));
  });

  it('shows labels for text areas', async () => {
    const root = await mountWithTool('textDiff');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TextDiffLabels' },
      text.includes('Text') || text.includes('Original') || text.includes('Modified'));
  });
});
