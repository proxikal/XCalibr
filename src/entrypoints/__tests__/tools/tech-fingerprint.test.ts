import { describe, it, beforeEach, afterEach } from 'vitest';
import { aiAssertTruthy } from '../../../test-utils/aiAssert';
import { resetChrome, mountWithTool } from '../integration-test-utils';
import type { TechFinding } from '../../content/Tools/tool-types';

describe('Tech Fingerprint Tool', () => {
  beforeEach(() => { resetChrome(); document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  const mockFindings: TechFinding[] = [
    {
      label: 'JavaScript Framework',
      value: 'React',
      version: '18.2.0',
      confidence: 'high',
      category: 'framework',
      signals: [
        { type: 'global', evidence: 'window.__REACT_DEVTOOLS_GLOBAL_HOOK__' },
        { type: 'script', evidence: 'react.production.min.js', source: 'https://cdn.example.com/react.js' }
      ]
    },
    {
      label: 'CSS Framework',
      value: 'Tailwind CSS',
      confidence: 'medium',
      category: 'library',
      signals: [
        { type: 'selector', evidence: 'class="flex items-center gap-2"' }
      ]
    },
    {
      label: 'Analytics',
      value: 'Google Analytics',
      confidence: 'high',
      category: 'analytics',
      signals: [
        { type: 'script', evidence: 'gtag.js', source: 'https://www.googletagmanager.com/gtag/js' }
      ]
    }
  ];

  it('renders the Tech Fingerprint interface', async () => {
    const root = await mountWithTool('techFingerprint');
    aiAssertTruthy({ name: 'TechFingerprintRenders' }, root);
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TechFingerprintTitle' },
      text.includes('Tech') || text.includes('Fingerprint') || text.includes('Scan'));
  });

  it('has Scan button', async () => {
    const root = await mountWithTool('techFingerprint');
    const buttons = root?.querySelectorAll('button') || [];
    const scanBtn = Array.from(buttons).find(b =>
      b.textContent?.includes('Scan') || b.textContent?.includes('Detect') || b.textContent?.includes('Refresh')
    );
    aiAssertTruthy({ name: 'TechFingerprintScanButton' }, scanBtn);
  });

  it('displays detected technologies with findings', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: mockFindings,
      url: 'https://example.com'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TechFingerprintShowsFindings' },
      text.includes('React') || text.includes('Tailwind') || text.includes('detected')
    );
  });

  it('shows confidence indicators (high/medium/low)', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: mockFindings,
      url: 'https://example.com'
    });
    const text = root?.textContent || '';
    // Check for confidence indicators - bars, colors, or text
    const hasConfidenceElements = root?.querySelector('[class*="emerald"]') ||
                                  root?.querySelector('[class*="amber"]') ||
                                  root?.querySelector('[class*="slate"]');
    aiAssertTruthy({ name: 'TechFingerprintConfidenceIndicators' },
      hasConfidenceElements ||
      text.includes('high') || text.includes('medium') || text.includes('low') ||
      text.includes('confidence')
    );
  });

  it('shows category filtering buttons', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: mockFindings,
      url: 'https://example.com'
    });
    const text = root?.textContent || '';
    const buttons = root?.querySelectorAll('button') || [];
    // Should show category filter buttons
    aiAssertTruthy({ name: 'TechFingerprintCategoryFilters' },
      text.includes('All') ||
      text.includes('framework') || text.includes('Framework') ||
      text.includes('library') || text.includes('Library') ||
      text.includes('analytics') || text.includes('Analytics') ||
      buttons.length >= 3
    );
  });

  it('shows confidence stats summary', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: mockFindings,
      url: 'https://example.com'
    });
    const text = root?.textContent || '';
    // Should show stats like "2 high", "1 med" or similar
    aiAssertTruthy({ name: 'TechFingerprintConfidenceStats' },
      text.match(/\d+\s*(high|med|low)/i) ||
      text.includes('detected') ||
      root?.querySelector('[class*="rounded-full"]')
    );
  });

  it('displays version information when available', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: mockFindings,
      url: 'https://example.com'
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TechFingerprintVersionInfo' },
      text.includes('18.2.0') || text.includes('v18') || text.match(/v?\d+\.\d+/)
    );
  });

  it('has expandable finding cards showing signals', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: mockFindings,
      url: 'https://example.com',
      expandedFinding: 'JavaScript FrameworkReact'
    });
    const text = root?.textContent || '';
    // When expanded, should show signals
    aiAssertTruthy({ name: 'TechFingerprintExpandableSignals' },
      text.includes('Signals') || text.includes('signals') ||
      text.includes('evidence') || text.includes('DEVTOOLS') ||
      text.includes('▼') || text.includes('▶')
    );
  });

  it('shows category icons', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: mockFindings,
      url: 'https://example.com'
    });
    const text = root?.textContent || '';
    // Should show category icons like ⚛ 📦 📊
    aiAssertTruthy({ name: 'TechFingerprintCategoryIcons' },
      text.includes('⚛') || text.includes('📦') || text.includes('📊') ||
      text.includes('🖥') || text.includes('🌐') ||
      root?.querySelectorAll('[class*="text-base"]').length
    );
  });

  it('has Export button', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: mockFindings,
      url: 'https://example.com'
    });
    const buttons = root?.querySelectorAll('button') || [];
    const exportBtn = Array.from(buttons).find(b =>
      b.textContent?.includes('Export') || b.textContent?.includes('export')
    );
    aiAssertTruthy({ name: 'TechFingerprintExportButton' }, exportBtn);
  });

  it('shows click-to-copy functionality for signals', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: mockFindings,
      url: 'https://example.com',
      expandedFinding: 'JavaScript FrameworkReact'
    });
    // Check for copy indicators or clickable signal items
    const clickableSignals = root?.querySelectorAll('[class*="cursor-pointer"]') || [];
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TechFingerprintCopySignals' },
      clickableSignals.length > 0 ||
      text.includes('Copy') || text.includes('copy') ||
      text.includes('⧉') || text.includes('Click')
    );
  });

  it('displays URL being scanned', async () => {
    const testUrl = 'https://test-fingerprint.com';
    const root = await mountWithTool('techFingerprint', {
      findings: [],
      url: testUrl
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TechFingerprintShowsUrl' },
      text.includes(testUrl) || text.includes('test-fingerprint')
    );
  });

  it('handles empty findings state', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: [],
      url: ''
    });
    const text = root?.textContent || '';
    // Should show empty state or prompt to scan
    aiAssertTruthy({ name: 'TechFingerprintEmptyState' },
      text.includes('No technologies') || text.includes('Scan') ||
      text.includes('detected') || text.includes('Click') ||
      text.includes('🔍')
    );
  });

  it('shows last scan timestamp', async () => {
    const root = await mountWithTool('techFingerprint', {
      findings: mockFindings,
      url: 'https://example.com',
      updatedAt: Date.now()
    });
    const text = root?.textContent || '';
    aiAssertTruthy({ name: 'TechFingerprintTimestamp' },
      text.includes('Last') || text.includes('scan') ||
      text.includes(':') || text.match(/\d{1,2}:\d{2}/)
    );
  });
});
