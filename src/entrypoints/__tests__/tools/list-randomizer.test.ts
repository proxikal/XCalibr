import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('List Randomizer Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the List Randomizer interface', async () => {
    const root = await mountWithTool('listRandomizer');
    aiAssertTruthy({ name: 'ListRandomizerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ListRandomizerTitle' }, text.includes('Random') || text.includes('Shuffle'));
  });

  it('shows textarea for items', async () => {
    const root = await mountWithTool('listRandomizer');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'ListRandomizerTextarea' }, textarea);
  });

  it('has shuffle button', async () => {
    const root = await mountWithTool('listRandomizer');
    const btn = findButtonByText(root!, 'Shuffle') || findButtonByText(root!, 'Shuffle All');
    aiAssertTruthy({ name: 'ListRandomizerShuffle' }, btn);
  });

  it('has pick winner button', async () => {
    const root = await mountWithTool('listRandomizer');
    const btn = findButtonByText(root!, 'Pick Winner') || findButtonByText(root!, 'Pick');
    aiAssertTruthy({ name: 'ListRandomizerPick' }, btn);
  });

  it('displays shuffled output', async () => {
    const root = await mountWithTool('listRandomizer', {
      input: 'Apple\nBanana\nCherry',
      output: 'Banana\nCherry\nApple'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ListRandomizerOutput' },
      text.includes('Banana') || text.includes('Shuffled'));
  });

  it('displays winner when picked', async () => {
    const root = await mountWithTool('listRandomizer', {
      input: 'Apple\nBanana\nCherry',
      winner: 'Banana',
      pickCount: 1
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ListRandomizerWinner' },
      text.includes('Winner') || text.includes('Banana'));
  });

  it('shows pick count option', async () => {
    const root = await mountWithTool('listRandomizer');
    const numInput = root?.querySelector('input[type="number"]');
    aiAssertTruthy({ name: 'ListRandomizerPickCount' }, numInput);
  });
});
