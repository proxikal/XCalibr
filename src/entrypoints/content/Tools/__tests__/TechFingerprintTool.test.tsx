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

describe('TechFingerprintTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  describe('Integration tests', () => {
    it('detects tech fingerprint signals', async () => {
      document.head.innerHTML = '<meta name="generator" content="WordPress" />';
      const root = await mountWithTool('techFingerprint');
      if (!root) return;
      const scanButton = await waitFor(() => findButtonByText(root, 'Scan'));
      aiAssertTruthy({ name: 'TechFingerprintScan' }, scanButton);
      scanButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<
          string,
          { findings?: { value: string }[] }
        >;
        return (toolData.techFingerprint?.findings?.length ?? 0) > 0;
      });
      const toolData = stored?.toolData as Record<
        string,
        { findings?: { value: string }[] }
      >;
      const findings = toolData?.techFingerprint?.findings ?? [];
      aiAssertTruthy(
        { name: 'TechFingerprintFindings', state: findings },
        findings.some((entry) => entry.value.includes('WordPress'))
      );
    });
  });
});
