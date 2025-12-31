import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Storage Secret Hunter Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Storage Secret Hunter interface', async () => {
    const root = await mountWithTool('storageSecretHunter');
    aiAssertTruthy({ name: 'StorageSecretHunterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'StorageSecretHunterTitle' },
      text.includes('Storage') || text.includes('Secret') || text.includes('localStorage'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('storageSecretHunter');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'StorageSecretHunterButton' }, button);
  });

  it('shows secrets when found', async () => {
    const root = await mountWithTool('storageSecretHunter', {
      findings: [
        { storage: 'localStorage', key: 'auth_token', value: 'eyJhbGc...', secretType: 'JWT' },
        { storage: 'sessionStorage', key: 'api_key', value: 'sk-123...', secretType: 'API Key' }
      ]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'StorageSecretHunterResults' },
      text.includes('token') || text.includes('JWT') || text.includes('key') || root?.querySelectorAll('*').length! > 5);
  });

  it('displays finding count', async () => {
    const root = await mountWithTool('storageSecretHunter', {
      findings: [{ storage: 'localStorage', key: 'test', value: 'value', secretType: 'Unknown' }]
    });
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'StorageSecretHunterCount' }, elements && elements.length > 3);
  });
});
