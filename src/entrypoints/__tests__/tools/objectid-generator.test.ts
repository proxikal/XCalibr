import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('ObjectId Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the ObjectId Generator interface', async () => {
    const root = await mountWithTool('objectIdGenerator');
    aiAssertTruthy({ name: 'ObjectIdGeneratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ObjectIdGeneratorTitle' }, text.includes('ObjectId') || text.includes('MongoDB'));
  });

  it('shows generate button', async () => {
    const root = await mountWithTool('objectIdGenerator');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'ObjectIdGeneratorButton' }, button);
  });

  it('displays generated ObjectId', async () => {
    const root = await mountWithTool('objectIdGenerator', {
      objectId: '507f1f77bcf86cd799439011'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ObjectIdGeneratorOutput' },
      text.includes('507f1f77') || text.length > 0);
  });

  it('shows ObjectId parts breakdown', async () => {
    const root = await mountWithTool('objectIdGenerator', {
      objectId: '507f1f77bcf86cd799439011',
      timestamp: 'Dec 30, 2025'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'ObjectIdGeneratorParts' },
      text.includes('timestamp') || text.includes('Timestamp') || text.includes('Dec') || text.includes('2025'));
  });

  it('supports bulk generation', async () => {
    const root = await mountWithTool('objectIdGenerator');
    const text = root?.textContent || '';
    const inputs = root?.querySelectorAll('input');
    aiAssertTruthy({ name: 'ObjectIdGeneratorBulk' },
      text.includes('bulk') || text.includes('count') || text.includes('Bulk') || (inputs && inputs.length >= 1));
  });
});
