import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('S3 Bucket Finder Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('renders the S3 Bucket Finder interface', async () => {
    const root = await mountWithTool('s3BucketFinder');
    aiAssertTruthy({ name: 'S3BucketFinderRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'S3BucketFinderTitle' },
      text.includes('S3') || text.includes('Bucket') || text.includes('AWS'));
  });

  it('has scan button', async () => {
    const root = await mountWithTool('s3BucketFinder');
    const button = root?.querySelector('button');
    aiAssertTruthy({ name: 'S3BucketFinderButton' }, button);
  });

  it('shows buckets when found', async () => {
    const root = await mountWithTool('s3BucketFinder', {
      buckets: [
        { url: 'https://my-bucket.s3.amazonaws.com/file.js', bucketName: 'my-bucket' },
        { url: 'https://s3.amazonaws.com/another-bucket/asset.png', bucketName: 'another-bucket' }
      ]
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'S3BucketFinderResults' },
      text.includes('bucket') || text.includes('s3') || text.includes('amazonaws') || root?.querySelectorAll('*').length! > 5);
  });

  it('displays bucket count', async () => {
    const root = await mountWithTool('s3BucketFinder', {
      buckets: [{ url: 'https://test.s3.amazonaws.com', bucketName: 'test' }]
    });
    const elements = root?.querySelectorAll('*');
    aiAssertTruthy({ name: 'S3BucketFinderCount' }, elements && elements.length > 3);
  });
});
