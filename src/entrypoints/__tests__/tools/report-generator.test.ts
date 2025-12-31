import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Report Generator', () => {
  beforeEach(() => {
    resetChrome();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders correctly', async () => {
    const root = await mountWithTool('reportGenerator');
    aiAssertTruthy({ name: 'ReportGeneratorRendered' }, root);
  });

  it('has interactive elements', async () => {
    const root = await mountWithTool('reportGenerator');
    aiAssertTruthy(
      { name: 'HasInteractiveElements' },
      root?.querySelector('button') || root?.querySelector('textarea') || root?.querySelector('select')
    );
  });
});
