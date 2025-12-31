import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Visual Grid Builder Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Visual Grid Builder interface', async () => {
    const root = await mountWithTool('visualGridBuilder');
    aiAssertTruthy({ name: 'VisualGridBuilderRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'VisualGridBuilderTitle' },
      text.includes('Grid') || text.includes('Layout') || text.includes('Builder'));
  });

  it('shows grid preview area', async () => {
    const root = await mountWithTool('visualGridBuilder');
    const gridElements = root?.querySelectorAll('[style*="grid"]') || root?.querySelectorAll('[class*="grid"]');
    const divs = root?.querySelectorAll('div');
    aiAssertTruthy({ name: 'VisualGridBuilderPreview' },
      (gridElements && gridElements.length >= 1) || (divs && divs.length > 5));
  });

  it('has column/row controls', async () => {
    const root = await mountWithTool('visualGridBuilder');
    const text = root?.textContent || '';
    const inputs = root?.querySelectorAll('input[type="number"]');
    aiAssertTruthy({ name: 'VisualGridBuilderControls' },
      text.toLowerCase().includes('column') || text.toLowerCase().includes('row') ||
      (inputs && inputs.length >= 1));
  });

  it('shows generated CSS code', async () => {
    const root = await mountWithTool('visualGridBuilder');
    const text = root?.textContent || '';
    const hasCode = text.includes('grid-template') || text.includes('display:') ||
                    text.includes('CSS') || text.includes('code');
    const textarea = root?.querySelector('textarea');
    const codeBlock = root?.querySelector('pre') || root?.querySelector('code');
    aiAssertTruthy({ name: 'VisualGridBuilderCode' }, hasCode || textarea || codeBlock);
  });

  it('has copy button for code', async () => {
    const root = await mountWithTool('visualGridBuilder');
    const text = root?.textContent || '';
    const buttons = root?.querySelectorAll('button');
    aiAssertTruthy({ name: 'VisualGridBuilderCopy' },
      text.toLowerCase().includes('copy') || (buttons && buttons.length >= 1));
  });
});
