import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('MongoQueryBuilderTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('builds Mongo queries', async () => {
      const root = await mountWithTool('mongoQueryBuilder', {
        collection: 'users',
        filter: '{}',
        projection: '{}',
        sort: '{}',
        limit: '',
        output: '',
        error: ''
      });
      if (!root) return;
      const buildButton = findButtonByText(root, 'Build Query');
      buildButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.mongoQueryBuilder?.output ?? '').includes('db.users.find');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.mongoQueryBuilder?.output ?? '';
      aiAssertIncludes({ name: 'MongoQueryBuilderOutput' }, output, 'db.users.find');
    });
  });
});
