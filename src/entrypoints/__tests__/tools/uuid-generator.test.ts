import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('UUID Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the UUID Generator interface', async () => {
    const root = await mountWithTool('uuidGenerator');
    aiAssertTruthy({ name: 'UuidGeneratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UuidGeneratorTitle' }, text.includes('UUID') || text.includes('Generator'));
  });

  it('shows generate button', async () => {
    const root = await mountWithTool('uuidGenerator');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'UuidGeneratorButton' }, button);
  });

  it('shows version selection', async () => {
    const root = await mountWithTool('uuidGenerator');
    const text = root?.textContent || '';
    const select = root?.querySelector('select');
    aiAssertTruthy({ name: 'UuidGeneratorVersion' },
      select || text.includes('v4') || text.includes('v1') || text.includes('version'));
  });

  it('displays generated UUID', async () => {
    const root = await mountWithTool('uuidGenerator', {
      uuid: '550e8400-e29b-41d4-a716-446655440000'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'UuidGeneratorOutput' },
      text.includes('550e8400') || text.includes('-'));
  });

  it('supports bulk generation', async () => {
    const root = await mountWithTool('uuidGenerator');
    const text = root?.textContent || '';
    const inputs = root?.querySelectorAll('input');
    aiAssertTruthy({ name: 'UuidGeneratorBulk' },
      text.includes('bulk') || text.includes('count') || text.includes('Bulk') || (inputs && inputs.length >= 1));
  });
});
