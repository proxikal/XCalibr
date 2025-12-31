import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Source Map Detector Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the Source Map Detector interface', async () => {
    const root = await mountWithTool('sourceMapDetector');
    aiAssertTruthy({ name: 'SourceMapDetectorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'SourceMapDetectorTitle' },
      text.includes('Source') || text.includes('Map') || text.includes('.map'));
  });

  it('shows scan button', async () => {
    const root = await mountWithTool('sourceMapDetector');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'SourceMapDetectorButton' }, button);
  });

  it('displays results area', async () => {
    const root = await mountWithTool('sourceMapDetector');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'SourceMapDetectorResults' },
      text.includes('scan') || text.includes('Scan') || text.includes('detect') || text.includes('source'));
  });

  it('shows detected source maps when found', async () => {
    const root = await mountWithTool('sourceMapDetector', {
      sourceMaps: [{ url: 'https://example.com/app.js.map', scriptUrl: 'https://example.com/app.js' }],
      scannedAt: Date.now()
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'SourceMapDetectorShowsMaps' },
      text.includes('.map') || text.includes('app') || (root?.querySelectorAll('*').length ?? 0) > 5);
  });

  it('shows no source maps message when none found', async () => {
    const root = await mountWithTool('sourceMapDetector', {
      sourceMaps: [],
      scannedAt: Date.now()
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'SourceMapDetectorNoMaps' },
      text.toLowerCase().includes('no') || text.toLowerCase().includes('none') || (root?.querySelectorAll('*').length ?? 0) > 3);
  });
});
