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

describe('CouchDbDocExplorerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('fetches CouchDB documents', async () => {
      setRuntimeHandler('xcalibr-couchdb-fetch', () => ({ output: '{"ok":true}', error: '' }));
      const root = await mountWithTool('couchDbDocExplorer', {
        url: 'https://db.example.com/mydb/docid',
        output: '',
        error: ''
      });
      if (!root) return;
      const button = findButtonByText(root, 'Fetch Doc');
      button?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { output?: string }>;
        return (toolData.couchDbDocExplorer?.output ?? '').includes('ok');
      });
      const output = (stored?.toolData as Record<string, { output?: string }> | undefined)
        ?.couchDbDocExplorer?.output ?? '';
      aiAssertIncludes({ name: 'CouchDbDocOutput' }, output, 'ok');
    });
  });
});
