import { beforeEach, describe, it } from 'vitest';
import { aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  flushPromises,
  findButtonByText,
  waitForState,
  setRuntimeHandler
} from '../../../__tests__/integration-test-utils';

describe('GraphqlExplorerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('runs GraphQL queries', async () => {
      setRuntimeHandler('xcalibr-http-request', () => ({
        status: 200,
        statusText: 'OK',
        headers: [],
        body: '{"data":{"ok":true}}'
      }));
      const root = await mountWithTool('graphqlExplorer', {
        url: 'https://api.example.com/graphql',
        query: '{ ping }',
        variables: '',
        response: '',
        error: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Run Query');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { response?: string }>;
        return (toolData.graphqlExplorer?.response ?? '').includes('data');
      });
      const output = (stored?.toolData as Record<string, { response?: string }> | undefined)
        ?.graphqlExplorer?.response ?? '';
      aiAssertIncludes({ name: 'GraphqlExplorerOutput' }, output, 'data');
    });
  });
});
