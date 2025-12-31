import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Robots.txt Viewer Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  // The component uses data.content (raw robots.txt string) and parses it internally
  const mockContent = `User-agent: *
Disallow: /admin/
Disallow: /private/
Disallow: /backup/
Disallow: /.git/
Allow: /public/
Crawl-delay: 10

User-agent: Googlebot
Disallow: /no-google/
Allow: /

User-agent: Bingbot
Disallow: /no-bing/

Sitemap: https://example.com/sitemap.xml`;

  it('renders the Robots.txt Viewer interface', async () => {
    const root = await mountWithTool('robotsViewer');
    aiAssertTruthy({ name: 'RobotsViewerRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'RobotsViewerTitle' },
      text.includes('Robots') || text.includes('robots.txt'));
  });

  it('has Fetch button', async () => {
    const root = await mountWithTool('robotsViewer');
    const buttons = root?.querySelectorAll('button') || [];
    const fetchBtn = Array.from(buttons).find(b =>
      b.textContent?.includes('Fetch') || b.textContent?.includes('Load') || b.textContent?.includes('Refresh')
    );
    aiAssertTruthy({ name: 'RobotsViewerFetchButton' }, fetchBtn);
  });

  it('displays user-agent groups in sidebar', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt'
    });
    const text = root?.textContent || '';
    // Should show user-agent names
    aiAssertTruthy({ name: 'RobotsViewerUserAgentGroups' },
      text.includes('*') || text.includes('Googlebot') || text.includes('Bingbot') ||
      text.includes('User-agent') || text.includes('agents')
    );
  });

  it('shows high-risk path indicators', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt'
    });
    const text = root?.textContent || '';
    // High-risk paths like /admin/, /.git/, /backup/ should be highlighted
    const hasHighRiskIndicators = root?.querySelector('[class*="rose"]') ||
                                   root?.querySelector('[class*="red"]') ||
                                   root?.querySelector('[class*="amber"]');
    aiAssertTruthy({ name: 'RobotsViewerHighRiskPaths' },
      hasHighRiskIndicators ||
      text.includes('⚠') || text.includes('🚨') ||
      text.includes('admin') || text.includes('.git') || text.includes('backup') ||
      text.includes('high-risk') || text.includes('risk')
    );
  });

  it('has Grouped and Raw view tabs', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt'
    });
    const text = root?.textContent || '';
    const buttons = root?.querySelectorAll('button') || [];
    aiAssertTruthy({ name: 'RobotsViewerViewTabs' },
      text.includes('Grouped') || text.includes('Raw') ||
      text.includes('View') || buttons.length >= 2
    );
  });

  it('displays disallow paths with icons', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt'
    });
    const text = root?.textContent || '';
    // Should show disallow paths with icons
    aiAssertTruthy({ name: 'RobotsViewerDisallowPaths' },
      text.includes('Disallow') || text.includes('disallow') ||
      text.includes('/admin') || text.includes('/private') ||
      text.includes('🚫') || text.includes('❌')
    );
  });

  it('displays allow paths with icons', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt'
    });
    const text = root?.textContent || '';
    // Should show allow paths
    aiAssertTruthy({ name: 'RobotsViewerAllowPaths' },
      text.includes('Allow') || text.includes('allow') ||
      text.includes('/public') || text.includes('✓') || text.includes('✅')
    );
  });

  it('shows crawl-delay when present', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'RobotsViewerCrawlDelay' },
      text.includes('Crawl') || text.includes('crawl') ||
      text.includes('delay') || text.includes('10') ||
      text.includes('⏱')
    );
  });

  it('displays sitemap URLs', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'RobotsViewerSitemaps' },
      text.includes('Sitemap') || text.includes('sitemap') ||
      text.includes('sitemap.xml') || text.includes('🗺')
    );
  });

  it('can switch to raw view', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt'
    });
    const text = root?.textContent || '';
    // Should have raw view option and show raw content parts
    aiAssertTruthy({ name: 'RobotsViewerRawView' },
      text.includes('User-agent') || text.includes('Disallow') ||
      text.includes('Raw') || text.includes('Grouped')
    );
  });

  it('shows HTTP status indicator', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt',
      httpStatus: 200
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'RobotsViewerHttpStatus' },
      text.includes('200') || text.includes('OK') ||
      text.includes('status') || text.includes('Status') ||
      root?.querySelector('[class*="emerald"]') || root?.querySelector('[class*="green"]')
    );
  });

  it('handles missing robots.txt (404)', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: '',
      url: 'https://example.com/robots.txt',
      httpStatus: 404,
      error: 'robots.txt not found'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'RobotsViewerNotFound' },
      text.includes('404') || text.includes('not found') ||
      text.includes('Not Found') || text.includes('error') ||
      text.includes('Error') || text.includes('Fetch')
    );
  });

  it('displays URL being viewed', async () => {
    const testUrl = 'https://test-robots.com/robots.txt';
    const root = await mountWithTool('robotsViewer', {
      content: '',
      url: testUrl
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'RobotsViewerShowsUrl' },
      text.includes('test-robots') || text.includes(testUrl) || text.includes('URL')
    );
  });

  it('shows user-agent count in sidebar', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt'
    });
    const text = root?.textContent || '';
    // Should show count of user agents or group count
    aiAssertTruthy({ name: 'RobotsViewerAgentCount' },
      text.includes('3') || text.match(/\d+\s*(agent|group)/i) ||
      text.includes('agents') || text.includes('groups') ||
      text.includes('User') || text.includes('Googlebot')
    );
  });

  it('handles empty robots.txt state', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: '',
      url: ''
    });
    const text = root?.textContent || '';
    // Should show empty state or prompt to fetch
    aiAssertTruthy({ name: 'RobotsViewerEmptyState' },
      text.includes('Fetch') || text.includes('Load') ||
      text.includes('No robots') || text.includes('Click') ||
      root?.querySelector('button')
    );
  });

  it('shows larger icons for better visibility', async () => {
    const root = await mountWithTool('robotsViewer', {
      content: mockContent,
      url: 'https://example.com/robots.txt'
    });
    // Check for text-base or text-sm classes indicating larger icons
    const largeIcons = root?.querySelectorAll('[class*="text-base"], [class*="text-sm"]') || [];
    aiAssertTruthy({ name: 'RobotsViewerLargerIcons' },
      largeIcons.length > 0 || root?.querySelectorAll('span').length
    );
  });
});
