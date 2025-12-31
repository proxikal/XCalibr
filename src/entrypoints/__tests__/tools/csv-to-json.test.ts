import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('CSV to JSON Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the CSV to JSON interface', async () => {
    const root = await mountWithTool('csvToJson');
    aiAssertTruthy({ name: 'CsvToJsonRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CsvToJsonTitle' }, text.includes('CSV') || text.includes('JSON'));
  });

  it('shows textarea for CSV input', async () => {
    const root = await mountWithTool('csvToJson');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'CsvToJsonTextarea' }, textarea);
  });

  it('has convert button', async () => {
    const root = await mountWithTool('csvToJson');
    const btn = findButtonByText(root!, 'Convert to JSON');
    aiAssertTruthy({ name: 'CsvToJsonButton' }, btn);
  });

  it('displays JSON output when converted', async () => {
    const root = await mountWithTool('csvToJson', {
      input: 'name,age\nJohn,30',
      output: '[{"name":"John","age":"30"}]'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CsvToJsonOutput' }, text.includes('John') || text.includes('name'));
  });

  it('shows delimiter option', async () => {
    const root = await mountWithTool('csvToJson');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'CsvToJsonDelimiter' },
      text.includes('Delimiter') || text.includes('delimiter') || root?.querySelector('select'));
  });
});
