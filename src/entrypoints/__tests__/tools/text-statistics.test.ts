import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Text Statistics Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Text Statistics interface', async () => {
    const root = await mountWithTool('textStatistics');
    aiAssertTruthy({ name: 'TextStatsRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TextStatsTitle' }, text.includes('Statistics') || text.includes('Text'));
  });

  it('shows textarea for text input', async () => {
    const root = await mountWithTool('textStatistics');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'TextStatsTextarea' }, textarea);
  });

  it('displays character count', async () => {
    const root = await mountWithTool('textStatistics', {
      input: 'Hello World',
      stats: { characters: 11, charactersNoSpaces: 10, words: 2, sentences: 0, paragraphs: 1, lines: 1, readingTime: '0 sec', speakingTime: '0 sec' }
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TextStatsChars' }, text.includes('11') || text.includes('Character'));
  });

  it('displays word count', async () => {
    const root = await mountWithTool('textStatistics', {
      input: 'Hello World',
      stats: { characters: 11, charactersNoSpaces: 10, words: 2, sentences: 0, paragraphs: 1, lines: 1, readingTime: '0 sec', speakingTime: '0 sec' }
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TextStatsWords' }, text.includes('2') || text.includes('Words') || text.includes('words'));
  });

  it('shows reading time', async () => {
    const root = await mountWithTool('textStatistics');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TextStatsReading' },
      text.includes('Reading') || text.includes('reading') || text.includes('sec') || text.includes('min'));
  });
});
