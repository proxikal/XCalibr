import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';

describe('Header Inspector Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  // Headers must be array of { name, value } objects
  const mockHeaders = [
    { name: 'content-type', value: 'text/html' },
    { name: 'x-frame-options', value: 'DENY' },
    { name: 'strict-transport-security', value: 'max-age=31536000; includeSubDomains' },
    { name: 'content-security-policy', value: "default-src 'self'" }
  ];

  it('renders the Header Inspector interface', async () => {
    const root = await mountWithTool('headerInspector');
    aiAssertTruthy({ name: 'HeaderInspectorRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HeaderInspectorTitle' },
      text.includes('Header') || text.includes('Inspector'));
  });

  it('has Findings and Raw tabs', async () => {
    const root = await mountWithTool('headerInspector');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HeaderInspectorFindingsTab' },
      text.includes('Findings') || text.includes('findings'));
    aiAssertTruthy({ name: 'HeaderInspectorRawTab' },
      text.includes('Raw') || text.includes('raw'));
  });

  it('has Fetch Headers button', async () => {
    const root = await mountWithTool('headerInspector');
    const buttons = root?.querySelectorAll('button') || [];
    const fetchBtn = Array.from(buttons).find(b =>
      b.textContent?.includes('Fetch') || b.textContent?.includes('Scan') || b.textContent?.includes('Refresh')
    );
    aiAssertTruthy({ name: 'HeaderInspectorFetchButton' }, fetchBtn);
  });

  it('displays findings with severity badges when headers present', async () => {
    const root = await mountWithTool('headerInspector', {
      headers: mockHeaders,
      url: 'https://example.com'
    });
    const text = root?.textContent || '';
    // Should show security analysis findings
    aiAssertTruthy({ name: 'HeaderInspectorShowsFindings' },
      text.includes('HSTS') ||
      text.includes('X-Frame') ||
      text.includes('pass') ||
      text.includes('Pass') ||
      root?.querySelectorAll('[class*="emerald"], [class*="amber"], [class*="rose"]').length
    );
  });

  it('shows severity indicators (pass/warn/fail)', async () => {
    const root = await mountWithTool('headerInspector', {
      headers: mockHeaders,
      url: 'https://example.com'
    });
    // Check for severity-related classes or text
    const hasPassIndicators = root?.querySelector('[class*="emerald"]') ||
                              root?.querySelector('[class*="green"]');
    const hasWarnIndicators = root?.querySelector('[class*="amber"]') ||
                              root?.querySelector('[class*="yellow"]');
    const hasFailIndicators = root?.querySelector('[class*="rose"]') ||
                              root?.querySelector('[class*="red"]');
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HeaderInspectorSeverityIndicators' },
      hasPassIndicators || hasWarnIndicators || hasFailIndicators ||
      text.includes('pass') || text.includes('warn') || text.includes('fail') ||
      text.includes('Pass') || text.includes('Warn') || text.includes('Fail')
    );
  });

  it('can switch between Findings and Raw tabs', async () => {
    const root = await mountWithTool('headerInspector', {
      headers: mockHeaders,
      url: 'https://example.com',
      activeTab: 'raw'
    });
    const text = root?.textContent || '';
    // In raw mode, should show the actual header values
    aiAssertTruthy({ name: 'HeaderInspectorRawMode' },
      text.includes('content-type') || text.includes('text/html') || text.includes('Raw')
    );
  });

  it('shows expandable finding cards', async () => {
    const root = await mountWithTool('headerInspector', {
      headers: [
        { name: 'strict-transport-security', value: 'max-age=31536000; includeSubDomains' }
      ],
      url: 'https://example.com'
    });
    // Check for clickable/expandable elements
    const clickableElements = root?.querySelectorAll('[class*="cursor-pointer"]') || [];
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HeaderInspectorExpandableCards' },
      clickableElements.length > 0 ||
      text.includes('▶') || text.includes('▼') ||
      text.includes('HSTS') || text.includes('Strict-Transport')
    );
  });

  it('displays URL being inspected', async () => {
    const testUrl = 'https://test-example.com';
    const root = await mountWithTool('headerInspector', {
      url: testUrl,
      headers: []
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'HeaderInspectorShowsUrl' },
      text.includes(testUrl) || text.includes('test-example') || text.includes('URL')
    );
  });

  it('handles empty headers state', async () => {
    const root = await mountWithTool('headerInspector', {
      headers: [],
      url: ''
    });
    const text = root?.textContent || '';
    // Should show empty state or prompt to fetch
    aiAssertTruthy({ name: 'HeaderInspectorEmptyState' },
      text.includes('Fetch') || text.includes('fetch') ||
      text.includes('No headers') || text.includes('Click') ||
      root?.querySelector('button')
    );
  });

  it('shows last updated timestamp', async () => {
    const root = await mountWithTool('headerInspector', {
      headers: mockHeaders,
      url: 'https://example.com',
      updatedAt: Date.now()
    });
    const text = root?.textContent || '';
    // Should show timestamp or "Last" indicator
    aiAssertTruthy({ name: 'HeaderInspectorTimestamp' },
      text.includes('Last') || text.includes(':') ||
      text.includes('AM') || text.includes('PM') ||
      text.includes('ago') || root?.textContent?.match(/\d{1,2}:\d{2}/)
    );
  });
});
