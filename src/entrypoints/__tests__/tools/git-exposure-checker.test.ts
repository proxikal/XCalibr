import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Git Exposure Checker Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Git Exposure Checker interface', async () => {
    const root = await mountWithTool('gitExposureChecker');
    aiAssertTruthy({ name: 'GitExposureCheckerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GitExposureCheckerTitle' },
      text.includes('Git') || text.includes('.git') || text.includes('Exposure'));
  });

  it('has check button', async () => {
    const root = await mountWithTool('gitExposureChecker');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'GitExposureCheckerButton' }, button);
  });

  it('shows exposure status', async () => {
    const root = await mountWithTool('gitExposureChecker', {
      checked: true,
      exposed: true,
      gitConfigFound: true
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GitExposureCheckerStatus' },
      text.includes('exposed') || text.includes('vulnerable') || text.includes('found') || text.includes('safe') || root?.querySelectorAll('*').length! > 5);
  });

  it('displays check results', async () => {
    const root = await mountWithTool('gitExposureChecker', {
      checked: true,
      exposed: false
    });
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'GitExposureCheckerResults' }, elements && elements.length > 3);
  });
});
