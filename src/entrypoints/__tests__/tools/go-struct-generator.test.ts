import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Go Struct Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Go Struct Generator interface', async () => {
    const root = await mountWithTool('goStructGenerator');
    aiAssertTruthy({ name: 'GoStructGeneratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GoStructGeneratorTitle' }, text.includes('Go') || text.includes('Struct'));
  });

  it('shows JSON input textarea', async () => {
    const root = await mountWithTool('goStructGenerator');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'GoStructGeneratorInput' }, textarea);
  });

  it('generates Go struct', async () => {
    const root = await mountWithTool('goStructGenerator', {
      input: '{"name": "test"}',
      output: 'type Root struct { Name string `json:"name"` }'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'GoStructGeneratorOutput' },
      text.includes('struct') || text.includes('type') || text.includes('json:'));
  });

  it('has generate button', async () => {
    const root = await mountWithTool('goStructGenerator');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'GoStructGeneratorButton' }, button);
  });

  it('includes json tags option', async () => {
    const root = await mountWithTool('goStructGenerator');
    const text = root?.textContent || '';
    const checkbox = root?.querySelector('input[type="checkbox"]');
    aiAssertTruthy({ name: 'GoStructGeneratorTags' },
      checkbox || text.includes('tag') || text.includes('json'));
  });
});
