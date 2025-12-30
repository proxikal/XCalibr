import { beforeEach, describe, it } from 'vitest';
import { aiAssertTruthy } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitFor
} from '../../../__tests__/integration-test-utils';

describe('ParamAnalyzerTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('parses query params in Param Analyzer', async () => {
      const root = await mountWithTool('paramAnalyzer', {
        url: 'https://example.com/?a=1&b=2',
        params: [
          { key: 'a', value: '1' },
          { key: 'b', value: '2' }
        ]
      });
      if (!root) return;
      const keyInputs = await waitFor(() =>
        Array.from(root.querySelectorAll('input[placeholder="Key"]'))
      );
      aiAssertTruthy(
        { name: 'ParamAnalyzerInputs', state: { count: keyInputs?.length } },
        (keyInputs?.length ?? 0) === 2
      );
    });
  });
});
