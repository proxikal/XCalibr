import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('JSON to YAML Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the JSON to YAML interface', async () => {
    const root = await mountWithTool('jsonToYaml');
    aiAssertTruthy({ name: 'JsonToYamlRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JsonToYamlTitle' }, text.includes('JSON') || text.includes('YAML'));
  });

  it('shows textarea for JSON input', async () => {
    const root = await mountWithTool('jsonToYaml');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'JsonToYamlTextarea' }, textarea);
  });

  it('has convert button', async () => {
    const root = await mountWithTool('jsonToYaml');
    const btn = findButtonByText(root!, 'Convert to YAML');
    aiAssertTruthy({ name: 'JsonToYamlButton' }, btn);
  });

  it('displays YAML output when converted', async () => {
    const root = await mountWithTool('jsonToYaml', {
      input: '{"name":"John","age":30}',
      output: 'name: John\nage: 30'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JsonToYamlOutput' },
      text.includes('John') || text.includes('name') || text.includes('30'));
  });

  it('shows error for invalid JSON', async () => {
    const root = await mountWithTool('jsonToYaml', {
      input: '{invalid json}',
      error: 'Invalid JSON'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'JsonToYamlError' },
      text.includes('error') || text.includes('Error') || text.includes('Invalid'));
  });
});
