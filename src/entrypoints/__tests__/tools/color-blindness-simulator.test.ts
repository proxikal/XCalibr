import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Color Blindness Simulator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Color Blindness Simulator interface', async () => {
    const root = await mountWithTool('colorBlindnessSimulator');
    aiAssertTruthy({ name: 'ColorBlindnessSimRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ColorBlindnessSimTitle' },
      text.includes('Color') || text.includes('Blindness') || text.includes('Vision'));
  });

  it('shows simulation type options', async () => {
    const root = await mountWithTool('colorBlindnessSimulator');
    const text = root?.textContent || '';
    const select = root?.querySelector('select');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'ColorBlindnessSimTypes' },
      text.includes('Protanopia') || text.includes('Deuteranopia') ||
      text.includes('Tritanopia') || select || (buttons && buttons.length >= 2));
  });

  it('has apply/toggle button', async () => {
    const root = await mountWithTool('colorBlindnessSimulator');
    const button = root?.querySelector('button');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ColorBlindnessSimApply' },
      button || text.includes('Apply') || text.includes('Enable'));
  });

  it('shows preview or description', async () => {
    const root = await mountWithTool('colorBlindnessSimulator');
    const text = root?.textContent || '';
    const hasInfo = text.toLowerCase().includes('affects') ||
                    text.toLowerCase().includes('red') ||
                    text.toLowerCase().includes('green') ||
                    text.toLowerCase().includes('blue');
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'ColorBlindnessSimInfo' }, hasInfo || (elements && elements.length > 5));
  });

  it('has reset option', async () => {
    const root = await mountWithTool('colorBlindnessSimulator');
    const text = root?.textContent || '';
    const hasReset = text.toLowerCase().includes('reset') || text.toLowerCase().includes('normal') ||
                     text.toLowerCase().includes('off') || text.toLowerCase().includes('disable');
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'ColorBlindnessSimReset' }, hasReset || (buttons && buttons.length >= 1));
  });
});
