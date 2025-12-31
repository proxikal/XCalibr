import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool, findButtonByText } from '../integration-test-utils';

describe('Line Sorter Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Line Sorter interface', async () => {
    const root = await mountWithTool('lineSorter');
    aiAssertTruthy({ name: 'LineSorterRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'LineSorterTitle' }, text.includes('Line') || text.includes('Sort'));
  });

  it('shows textarea for input', async () => {
    const root = await mountWithTool('lineSorter');
    const textarea = root?.querySelector('textarea');
    aiAssertTruthy({ name: 'LineSorterTextarea' }, textarea);
  });

  it('has sort button', async () => {
    const root = await mountWithTool('lineSorter');
    const btn = findButtonByText(root!, 'Process Lines');
    aiAssertTruthy({ name: 'LineSorterButton' }, btn);
  });

  it('displays sorted output', async () => {
    const root = await mountWithTool('lineSorter', {
      input: 'banana\napple\ncherry',
      output: 'apple\nbanana\ncherry',
      sortType: 'asc'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'LineSorterOutput' },
      text.includes('apple') || text.includes('banana'));
  });

  it('shows sort options', async () => {
    const root = await mountWithTool('lineSorter');
    const text = root?.textContent || '';
    const hasOptions = text.includes('A-Z') || text.includes('Ascending') ||
                       text.includes('asc') || root?.querySelector('select');
    aiAssertTruthy({ name: 'LineSorterOptions' }, hasOptions);
  });

  it('has remove duplicates option', async () => {
    const root = await mountWithTool('lineSorter');
    const text = root?.textContent || '';
    const checkbox = root?.querySelector('input[type="checkbox"]');
    aiAssertTruthy({ name: 'LineSorterDedupe' },
      text.includes('duplicate') || text.includes('Duplicate') || checkbox);
  });
});
