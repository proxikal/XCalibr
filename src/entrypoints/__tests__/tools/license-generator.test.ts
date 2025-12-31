import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('License Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the License Generator interface', async () => {
    const root = await mountWithTool('licenseGenerator');
    aiAssertTruthy({ name: 'LicenseGeneratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'LicenseGeneratorTitle' }, text.includes('License') || text.includes('license'));
  });

  it('shows license types', async () => {
    const root = await mountWithTool('licenseGenerator');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'LicenseGeneratorTypes' },
      text.includes('MIT') || text.includes('Apache') || text.includes('GPL'));
  });

  it('has name input field', async () => {
    const root = await mountWithTool('licenseGenerator');
    const inputs = root?.querySelectorAll('input');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'LicenseGeneratorNameInput' },
      (inputs && inputs.length >= 1) || text.includes('Name') || text.includes('Author'));
  });

  it('displays generated license', async () => {
    const root = await mountWithTool('licenseGenerator', {
      license: 'MIT',
      output: 'MIT License\n\nCopyright (c) 2025'
    });
    const text = root?.textContent || '';
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'LicenseGeneratorOutput' },
      textarea || text.includes('MIT') || text.includes('Copyright'));
  });

  it('has generate button', async () => {
    const root = await mountWithTool('licenseGenerator');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'LicenseGeneratorButton' }, button);
  });
});
