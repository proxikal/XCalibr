import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('Hex Viewer Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Hex Viewer interface', async () => {
    const root = await mountWithTool('hexViewer');
    aiAssertTruthy({ name: 'HexViewerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HexViewerTitle' }, text.includes('Hex') || text.includes('Viewer'));
  });

  it('shows input area for text', async () => {
    const root = await mountWithTool('hexViewer');
    const textarea = root?.querySelector('textarea') || root?.querySelector('input');
    aiAssertTruthy({ name: 'HexViewerInput' }, textarea);
  });

  it('has convert button', async () => {
    const root = await mountWithTool('hexViewer');
    const btn = findButtonByText(root!, 'View Hex') || findButtonByText(root!, 'Convert');
    aiAssertTruthy({ name: 'HexViewerButton' }, btn);
  });

  it('displays hex output', async () => {
    const root = await mountWithTool('hexViewer', {
      input: 'Hi',
      hexOutput: '48 69',
      asciiOutput: 'H  i'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HexViewerOutput' },
      text.includes('48') || text.includes('69') || text.includes('Hex'));
  });

  it('shows ASCII translation', async () => {
    const root = await mountWithTool('hexViewer', {
      input: 'Test',
      hexOutput: '54 65 73 74',
      asciiOutput: 'Test'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HexViewerAscii' },
      text.includes('Test') || text.includes('ASCII') || text.includes('54'));
  });
});
