import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('BsonViewerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('normalizes BSON values', async () => {
      const root = await mountWithTool('bsonViewer', {
        input: '{"count":{"$numberInt":"5"}}',
        output: '',
        error: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Normalize');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.bsonViewer?.output ?? '').includes('5');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.bsonViewer?.output ?? '';
      aiAssertIncludes({ name: 'BsonViewerOutput' }, output, '5');
    });
  });
});
