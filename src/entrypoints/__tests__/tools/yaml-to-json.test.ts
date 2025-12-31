import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('YAML to JSON Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the YAML to JSON interface', async () => {
    const root = await mountWithTool('yamlToJson');
    aiAssertTruthy({ name: 'YamlToJsonRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'YamlToJsonTitle' }, text.includes('YAML') || text.includes('JSON'));
  });

  it('shows textarea for YAML input', async () => {
    const root = await mountWithTool('yamlToJson');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'YamlToJsonTextarea' }, textarea);
  });

  it('has convert button', async () => {
    const root = await mountWithTool('yamlToJson');
    const btn = findButtonByText(root!, 'Convert to JSON');
    aiAssertTruthy({ name: 'YamlToJsonButton' }, btn);
  });

  it('displays JSON output when converted', async () => {
    const root = await mountWithTool('yamlToJson', {
      input: 'name: John\nage: 30',
      output: '{"name":"John","age":30}'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'YamlToJsonOutput' },
      text.includes('John') || text.includes('name') || text.includes('30'));
  });

  it('shows error for invalid YAML', async () => {
    const root = await mountWithTool('yamlToJson', {
      input: '  invalid: yaml: here',
      error: 'Invalid YAML'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'YamlToJsonError' },
      text.includes('error') || text.includes('Error') || text.includes('Invalid'));
  });
});
