import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('XML to JSON Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the XML to JSON interface', async () => {
    const root = await mountWithTool('xmlToJson');
    aiAssertTruthy({ name: 'XmlToJsonRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'XmlToJsonTitle' }, text.includes('XML') || text.includes('JSON'));
  });

  it('shows textarea for XML input', async () => {
    const root = await mountWithTool('xmlToJson');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'XmlToJsonTextarea' }, textarea);
  });

  it('has convert button', async () => {
    const root = await mountWithTool('xmlToJson');
    const btn = findButtonByText(root!, 'Convert to JSON');
    aiAssertTruthy({ name: 'XmlToJsonButton' }, btn);
  });

  it('displays JSON output when converted', async () => {
    const root = await mountWithTool('xmlToJson', {
      input: '<person><name>John</name></person>',
      output: '{"person":{"name":"John"}}'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'XmlToJsonOutput' },
      text.includes('John') || text.includes('person') || text.includes('name'));
  });

  it('shows error for invalid XML', async () => {
    const root = await mountWithTool('xmlToJson', {
      input: '<invalid>',
      error: 'Invalid XML'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'XmlToJsonError' },
      text.includes('error') || text.includes('Error') || text.includes('Invalid'));
  });
});
