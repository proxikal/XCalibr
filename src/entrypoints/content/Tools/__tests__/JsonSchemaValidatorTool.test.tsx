import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  waitFor,
  findButtonByText,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('JsonSchemaValidatorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('validates JSON schema', async () => {
      const root = await mountWithTool('jsonSchemaValidator', {
        schema: '{"type":"object","required":["a"],"properties":{"a":{"type":"string"}}}',
        input: '{"a":1}',
        issues: [],
        error: ''
      });
      if (!root) return;
      const validateButton = await waitFor(() => findButtonByText(root, 'Validate'));
      validateButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { issues?: string[] }>;
        return (toolData.jsonSchemaValidator?.issues?.length ?? 0) > 0;
      });
      const issues = (stored?.toolData as Record<string, { issues?: string[] }> | undefined)
        ?.jsonSchemaValidator?.issues ?? [];
      aiAssertTruthy({ name: 'JsonSchemaIssues', state: issues }, issues.some((issue) => issue.includes('Expected')));
    });
  });
});
