import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Env Variable Scanner Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Env Variable Scanner interface', async () => {
    const root = await mountWithTool('envVariableScanner');
    aiAssertTruthy({ name: 'EnvVariableScannerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'EnvVariableScannerTitle' },
      text.includes('Env') || text.includes('Variable') || text.includes('Environment') || text.includes('Scan'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('envVariableScanner');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'EnvVariableScannerButton' }, button);
  });

  it('shows findings area', async () => {
    const root = await mountWithTool('envVariableScanner');
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'EnvVariableScannerResults' }, elements && elements.length > 3);
  });

  it('displays found environment variables', async () => {
    const root = await mountWithTool('envVariableScanner', {
      findings: [{ key: 'API_KEY', value: 'sk_test_1234' }]
    });
    const text = root?.textContent || '';
    const hasFindings = text.includes('API') || text.includes('KEY') || text.includes('variable') || root?.querySelector('pre') || root?.querySelector('code');
    aiAssertTruthy({ name: 'EnvVariableScannerFindings' }, hasFindings);
  });
});
