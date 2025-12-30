import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState,
  typeInput
} from '../../../__tests__/integration-test-utils';

describe('SqlQueryBuilderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('builds SQL query', async () => {
      const root = await mountWithTool('sqlQueryBuilder');
      if (!root) return;
      const tableInput = root.querySelector('input[placeholder="Table name"]') as HTMLInputElement | null;
      const columnsInput = root.querySelector('input[placeholder="Columns (comma separated)"]') as HTMLInputElement | null;
      if (!tableInput || !columnsInput) return;
      typeInput(tableInput, 'users');
      typeInput(columnsInput, 'id,name');
      await waitForState((state) => {
        const toolData = state.toolData as Record<string, { table?: string; columns?: string }>;
        return toolData.sqlQueryBuilder?.table === 'users';
      });
      const buildButton = await waitFor(() => findButtonByText(root, 'Build Query'));
      buildButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const output = root.querySelector('textarea[placeholder="SQL output..."]') as HTMLTextAreaElement | null;
      aiAssertIncludes({ name: 'SqlQueryBuilderOutput' }, output?.value ?? '', 'SELECT');
    });
  });
});
