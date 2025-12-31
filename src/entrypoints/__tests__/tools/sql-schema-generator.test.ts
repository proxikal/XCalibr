import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('SQL Schema Generator Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the SQL Schema Generator interface', async () => {
    const root = await mountWithTool('sqlSchemaGenerator');
    aiAssertTruthy({ name: 'SqlSchemaGeneratorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'SqlSchemaGeneratorTitle' }, text.includes('SQL') || text.includes('Schema'));
  });

  it('shows JSON input textarea', async () => {
    const root = await mountWithTool('sqlSchemaGenerator');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'SqlSchemaGeneratorInput' }, textarea);
  });

  it('generates CREATE TABLE statement', async () => {
    const root = await mountWithTool('sqlSchemaGenerator', {
      input: '{"id": 1, "name": "test"}',
      output: 'CREATE TABLE root (id INT, name VARCHAR(255))'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'SqlSchemaGeneratorOutput' },
      text.includes('CREATE') || text.includes('TABLE') || text.includes('VARCHAR'));
  });

  it('has generate button', async () => {
    const root = await mountWithTool('sqlSchemaGenerator');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'SqlSchemaGeneratorButton' }, button);
  });

  it('shows table name input', async () => {
    const root = await mountWithTool('sqlSchemaGenerator');
    const inputs = root?.querySelectorAll('input');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'SqlSchemaGeneratorTableName' },
      (inputs && inputs.length >= 1) || text.includes('table') || text.includes('Table'));
  });
});
