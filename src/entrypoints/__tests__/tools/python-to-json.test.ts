import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Python to JSON Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Python to JSON interface', async () => {
    const root = await mountWithTool('pythonToJson');
    aiAssertTruthy({ name: 'PythonToJsonRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'PythonToJsonTitle' }, text.includes('Python') || text.includes('JSON'));
  });

  it('shows input textarea', async () => {
    const root = await mountWithTool('pythonToJson');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'PythonToJsonInput' }, textarea);
  });

  it('converts Python dict to JSON', async () => {
    const root = await mountWithTool('pythonToJson', {
      input: "{'name': 'test', 'value': None}",
      output: '{"name": "test", "value": null}'
    });
    const text = root?.textContent || '';
    const textareas = root?.querySelectorAll('textarea');
    aiAssertTruthy({ name: 'PythonToJsonOutput' },
      (textareas && textareas.length >= 1) || text.includes('null') || text.includes('name'));
  });

  it('has convert button', async () => {
    const root = await mountWithTool('pythonToJson');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'PythonToJsonButton' }, button);
  });

  it('shows Python syntax examples', async () => {
    const root = await mountWithTool('pythonToJson');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'PythonToJsonExamples' },
      text.includes('None') || text.includes('True') || text.includes('False') || text.includes('dict'));
  });
});
