import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('Base64ImageConverterTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('base64ImageConverter');
      aiAssertTruthy({ name: 'Base64ImgMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Base64ImgTitle' }, text, 'Base64 Image');
    });

    it('renders mode toggle', async () => {
      const root = await mountWithTool('base64ImageConverter');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Base64ImgMode' }, text, 'Image');
    });

    it('renders file input', async () => {
      const root = await mountWithTool('base64ImageConverter');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Base64ImgSelect' }, text, 'Select');
    });
  });

  describe('Conversion', () => {
    it('handles base64 input', async () => {
      const root = await mountWithTool('base64ImageConverter', {
        mode: 'base64ToImage',
        input: 'data:image/png;base64,iVBORw0KGgo='
      });
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'Base64ImgBase64' }, text, 'Base64');
    });
  });

  describe('Persistence', () => {
    it('persists mode value', async () => {
      await mountWithTool('base64ImageConverter', {
        mode: 'imageToBase64'
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { mode?: string }>;
        return toolData.base64ImageConverter?.mode === 'imageToBase64';
      });
      aiAssertTruthy({ name: 'Base64ImgPersist' }, stored);
    });
  });
});
