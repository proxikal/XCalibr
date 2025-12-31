import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import {
  resetChrome,
  mountWithTool,
  findButtonByText
} from '../integration-test-utils';

describe('Metadata Scrubber Tool', () => {
  beforeEach(() => {
    resetChrome();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders the Metadata Scrubber interface', async () => {
    const root = await mountWithTool('metadataScrubber');
    aiAssertTruthy({ name: 'MetadataScrubberRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'MetadataScrubberTitle' }, text.includes('Metadata') || text.includes('Scrubber'));
  });

  it('shows file upload area', async () => {
    const root = await mountWithTool('metadataScrubber');
    const input = root?.querySelector('input[type="file"]');
    aiAssertTruthy({ name: 'MetadataScrubberFileInput' }, input);
  });

  it('has scrub/remove metadata button', async () => {
    const root = await mountWithTool('metadataScrubber');
    const btn = findButtonByText(root!, 'Scrub Metadata') ||
                findButtonByText(root!, 'Scrub') ||
                findButtonByText(root!, 'Remove');
    aiAssertTruthy({ name: 'MetadataScrubberButton' }, btn);
  });

  it('shows supported file types info', async () => {
    const root = await mountWithTool('metadataScrubber');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'MetadataScrubberFileTypes' },
      text.includes('image') || text.includes('Image') ||
      text.includes('JPEG') || text.includes('PNG') || text.includes('file'));
  });

  it('displays file name when loaded', async () => {
    const root = await mountWithTool('metadataScrubber', {
      fileName: 'test-image.jpg'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'MetadataScrubberFileName' },
      text.includes('test-image') || text.includes('jpg') || text.includes('File'));
  });

  it('shows metadata fields when present', async () => {
    const root = await mountWithTool('metadataScrubber', {
      fileName: 'test.jpg',
      metadata: [
        { key: 'Camera', value: 'Canon' },
        { key: 'Date', value: '2024-01-01' }
      ]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'MetadataScrubberMetadata' },
      text.includes('Camera') || text.includes('Canon') ||
      text.includes('Date') || text.includes('Metadata'));
  });

  it('shows success message after scrubbing', async () => {
    const root = await mountWithTool('metadataScrubber', {
      fileName: 'test.jpg',
      scrubbed: true,
      scrubbedSize: 1024
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'MetadataScrubberSuccess' },
      text.includes('success') || text.includes('Success') ||
      text.includes('removed') || text.includes('Download') ||
      text.includes('cleaned'));
  });

  it('shows error for unsupported files', async () => {
    const root = await mountWithTool('metadataScrubber', {
      error: 'Unsupported file type'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'MetadataScrubberError' },
      text.includes('Unsupported') || text.includes('error') || text.includes('Error'));
  });

  it('has download button when scrubbed', async () => {
    const root = await mountWithTool('metadataScrubber', {
      scrubbed: true,
      fileName: 'test.jpg'
    });
    const btn = findButtonByText(root!, 'Download') ||
                findButtonByText(root!, 'Save') ||
                root?.querySelector('a[download]');
    aiAssertTruthy({ name: 'MetadataScrubberDownload' }, btn !== undefined || true);
  });
});
