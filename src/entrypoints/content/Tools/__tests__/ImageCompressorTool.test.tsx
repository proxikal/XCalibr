import { beforeEach, describe, it, afterEach, vi } from 'vitest';
import { aiAssertTruthy, aiAssertIncludes } from '../../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  waitForState
} from '../../../__tests__/integration-test-utils';

describe('ImageCompressorTool', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Rendering', () => {
    it('renders the tool with title', async () => {
      const root = await mountWithTool('imageCompressor');
      aiAssertTruthy({ name: 'CompressorMount' }, root);
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CompressorTitle' }, text, 'Image Compressor');
    });

    it('renders quality slider', async () => {
      const root = await mountWithTool('imageCompressor');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CompressorQuality' }, text, 'Quality');
    });

    it('renders format selector', async () => {
      const root = await mountWithTool('imageCompressor');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CompressorFormat' }, text, 'Format');
    });

    it('renders upload area', async () => {
      const root = await mountWithTool('imageCompressor');
      const text = root?.textContent || '';
      aiAssertIncludes({ name: 'CompressorUpload' }, text, 'image');
    });
  });

  describe('Persistence', () => {
    it('persists quality value', async () => {
      await mountWithTool('imageCompressor', {
        quality: 75
      });
      const stored = await waitForState((state) => {
        const toolData = state.toolData as Record<string, { quality?: number }>;
        return toolData.imageCompressor?.quality === 75;
      });
      aiAssertTruthy({ name: 'CompressorPersist' }, stored);
    });
  });
});
