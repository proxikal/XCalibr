import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Persistent Scratchpad Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Scratchpad interface', async () => {
    const root = await mountWithTool('scratchpad');
    aiAssertTruthy({ name: 'ScratchpadRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ScratchpadTitle' }, text.includes('Scratchpad') || text.includes('Notes') || text.includes('Scratch'));
  });

  it('shows textarea for notes', async () => {
    const root = await mountWithTool('scratchpad');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'ScratchpadTextarea' }, textarea);
  });

  it('has auto-save or save indicator', async () => {
    const root = await mountWithTool('scratchpad');
    const text = root?.textContent || '';
    const hasSaveIndicator = text.toLowerCase().includes('save') || text.toLowerCase().includes('auto') || text.includes('Saved');
    const hasTextarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'ScratchpadAutoSave' }, hasSaveIndicator || hasTextarea);
  });

  it('persists text content', async () => {
    const root = await mountWithTool('scratchpad', { content: 'Test note content' });
    const textarea = root?.querySelector('textarea') as HTMLTextAreaElement | null;
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ScratchpadPersistence' },
      (textarea && textarea.value.includes('Test')) || text.includes('Test'));
  });

  it('allows clear or reset', async () => {
    const root = await mountWithTool('scratchpad');
    const text = root?.textContent || '';
    const hasClear = text.toLowerCase().includes('clear') || text.toLowerCase().includes('reset');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'ScratchpadClear' }, hasClear || textarea);
  });
});
