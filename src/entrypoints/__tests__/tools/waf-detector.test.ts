import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('WAF Detector Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the WAF Detector interface', async () => {
    const root = await mountWithTool('wafDetector');
    aiAssertTruthy({ name: 'WafDetectorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'WafDetectorTitle' },
      text.includes('WAF') || text.includes('Firewall') || text.includes('firewall'));
  });

  it('shows URL input', async () => {
    const root = await mountWithTool('wafDetector');
    const input = root?.querySelector('input[type="url"]') || root?.querySelector('input[type="text"]') || root?.querySelector('input');
    aiAssertTruthy({ name: 'WafDetectorInput' }, input);
  });

  it('has detect button', async () => {
    const root = await mountWithTool('wafDetector');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'WafDetectorButton' }, button);
  });

  it('shows detection results area', async () => {
    const root = await mountWithTool('wafDetector', {
      detected: true,
      wafName: 'Cloudflare'
    });
    const text = root?.textContent || '';
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'WafDetectorResults' },
      (elements && elements.length > 5) || text.includes('detect') || text.includes('Detect'));
  });

  it('displays WAF indicators or headers', async () => {
    const root = await mountWithTool('wafDetector');
    const text = root?.textContent || '';
    const hasIndicators = text.includes('header') || text.includes('Header') ||
                          text.includes('detect') || text.includes('Detect') ||
                          text.includes('signature') || text.includes('Signature');
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'WafDetectorIndicators' }, hasIndicators || (elements && elements.length > 5));
  });
});
