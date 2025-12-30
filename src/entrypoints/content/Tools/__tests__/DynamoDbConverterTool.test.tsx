import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('DynamoDbConverterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('converts DynamoDB JSON', async () => {
      const root = await mountWithTool('dynamoDbConverter', {
        input: '{"a":1}',
        output: '',
        mode: 'toDynamo',
        error: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Convert');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.dynamoDbConverter?.output ?? '').includes('"N"');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.dynamoDbConverter?.output ?? '';
      aiAssertIncludes({ name: 'DynamoConverterOutput' }, output, '"N"');
    });
  });
});
