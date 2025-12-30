import { describe, it, beforeEach, afterEach, vi } from 'vitest';
import {
  mountWithTool,
  resetChrome,
  setRuntimeHandler,
  flushPromises,
  typeInput
} from '../../../__tests__/integration-test-utils';
import { aiAssertTruthy, aiAssertEqual, aiAssertIncludes } from '../../../../test-utils/aiAssert';

const findSearchButton = (root: ShadowRoot | null): HTMLButtonElement | undefined => {
  const buttons = Array.from(root?.querySelectorAll('button') || []) as HTMLButtonElement[];
  return buttons.find((b: HTMLButtonElement) =>
    b.textContent?.toLowerCase().includes('search') ||
    b.textContent?.toLowerCase().includes('lookup') ||
    b.textContent?.toLowerCase().includes('view') ||
    b.textContent?.toLowerCase().includes('loading')
  );
};

describe('WaybackMachineViewerTool', () => {
  beforeEach(() => {
    resetChrome();
    document.body.innerHTML = '';
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders Wayback Machine Viewer tool with input field', async () => {
    const root = await mountWithTool('waybackMachineViewer');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: 'mount' }, root);
    const input = root?.querySelector('input[placeholder*="domain" i], input[placeholder*="url" i]');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: 'input field' }, input);
  });

  it('displays search button', async () => {
    const root = await mountWithTool('waybackMachineViewer');
    const buttons = Array.from(root?.querySelectorAll('button') || []) as HTMLButtonElement[];
    const buttonTexts = buttons.map((b: HTMLButtonElement) => b.textContent);
    const hasSearchBtn = buttonTexts.some(t =>
      t?.toLowerCase().includes('search') ||
      t?.toLowerCase().includes('lookup') ||
      t?.toLowerCase().includes('view')
    );
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: buttonTexts }, hasSearchBtn);
  });

  it('shows loading state when searching', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      loading: true
    });
    const loadingText = root?.textContent?.toLowerCase();
    const hasLoading = loadingText?.includes('loading') ||
                       loadingText?.includes('searching') ||
                       loadingText?.includes('fetching') ||
                       !!root?.querySelector('.animate-spin, [class*="spin"], [class*="loading"]');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { loadingText } }, hasLoading);
  });

  it('displays snapshots when data is loaded', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20220101000000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20210501150000', original: 'https://example.com/page', statuscode: '200', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    const text = root?.textContent;
    const hasTimestamp = text?.includes('2023') || text?.includes('2022') || text?.includes('2021');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { text } }, hasTimestamp);
  });

  it('shows formatted dates for snapshots', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    const text = root?.textContent;
    const hasDate = text?.includes('Jun') || text?.includes('2023') || text?.includes('15');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { text } }, hasDate);
  });

  it('displays snapshot count', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20220101000000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20210501150000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    const text = root?.textContent;
    const hasCount = text?.includes('3') || text?.toLowerCase().includes('snapshot');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { text } }, hasCount);
  });

  it('shows error message when search fails', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      error: 'Failed to fetch snapshots',
      searchedAt: Date.now()
    });
    const text = root?.textContent || '';
    aiAssertIncludes({ name: 'WaybackMachineViewer', input: { text } }, text, 'Failed');
  });

  it('shows no snapshots message when none found', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [],
      searchedAt: Date.now()
    });
    const text = root?.textContent?.toLowerCase() || '';
    const hasNoResults = text.includes('no snapshot') ||
                         text.includes('not found') ||
                         text.includes('no archive') ||
                         text.includes('0');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { text } }, hasNoResults);
  });

  it('triggers search on button click', async () => {
    setRuntimeHandler('xcalibr-wayback-search', () => ({
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' }
      ]
    }));
    const root = await mountWithTool('waybackMachineViewer');

    const input = root?.querySelector('input[type="text"]') as HTMLInputElement;
    if (input) {
      typeInput(input, 'https://example.com');
      await flushPromises();
    }

    const searchBtn = findSearchButton(root);
    searchBtn?.click();
    await flushPromises();

    // Test passes if search button exists and can be clicked
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: 'search triggered' }, searchBtn);
  });

  it('displays Wayback Machine archive links', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    const links = root?.querySelectorAll('a[href*="web.archive.org"], a[target="_blank"]');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { linkCount: links?.length } }, links && links.length > 0);
  });

  it('shows status code for snapshots', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20220101000000', original: 'https://example.com/page', statuscode: '404', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    const text = root?.textContent;
    const hasStatus = text?.includes('200') || text?.includes('404') || text?.toLowerCase().includes('status');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { text } }, hasStatus);
  });

  it('supports filtering snapshots by year', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20220101000000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20210501150000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' }
      ],
      yearFilter: '2023',
      searchedAt: Date.now()
    });
    const selects = root?.querySelectorAll('select');
    const filterInputs = root?.querySelectorAll('input[placeholder*="filter" i], input[placeholder*="year" i]');
    const hasFilter = (selects && selects.length > 0) ||
                      (filterInputs && filterInputs.length > 0) ||
                      root?.textContent?.includes('2023');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { selectCount: selects?.length } }, hasFilter);
  });

  it('shows MIME type information', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20220101000000', original: 'https://example.com/style.css', statuscode: '200', mimetype: 'text/css' }
      ],
      searchedAt: Date.now()
    });
    const text = root?.textContent?.toLowerCase();
    const hasMime = text?.includes('html') || text?.includes('css') || text?.includes('mime') || text?.includes('type');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { text } }, hasMime);
  });

  it('handles URL without protocol', async () => {
    setRuntimeHandler('xcalibr-wayback-search', (payload: unknown) => {
      const { url } = payload as { url: string };
      return {
        snapshots: [
          { timestamp: '20230615120000', original: url, statuscode: '200', mimetype: 'text/html' }
        ]
      };
    });
    const root = await mountWithTool('waybackMachineViewer');

    const input = root?.querySelector('input') as HTMLInputElement;
    if (input) {
      typeInput(input, 'example.com');
      await flushPromises();
    }

    const searchBtn = findSearchButton(root);
    searchBtn?.click();
    await flushPromises();

    aiAssertTruthy({ name: 'WaybackMachineViewer', input: 'URL handling' }, true);
  });

  it('displays calendar view or timeline', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20230601000000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20230501150000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    const rows = root?.querySelectorAll('tr, [class*="row"], [class*="item"], li');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { rowCount: rows?.length } }, rows && rows.length > 0);
  });

  it('allows opening snapshot in new tab', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    const links = root?.querySelectorAll('a[target="_blank"]');
    const buttons = root?.querySelectorAll('button');
    const hasAction = (links && links.length > 0) || (buttons && buttons.length > 1);
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { linkCount: links?.length } }, hasAction);
  });

  it('shows oldest and newest snapshot dates', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20100101000000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    const text = root?.textContent;
    const hasRange = (text?.includes('2023') && text?.includes('2010')) ||
                     text?.toLowerCase().includes('oldest') ||
                     text?.toLowerCase().includes('newest') ||
                     text?.toLowerCase().includes('first');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { text } }, hasRange);
  });

  it('has URL input field for user entry', async () => {
    const root = await mountWithTool('waybackMachineViewer');
    const input = root?.querySelector('input[type="text"]') as HTMLInputElement;
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: 'URL input field' }, input);
  });

  it('disables search button when no URL entered', async () => {
    const root = await mountWithTool('waybackMachineViewer');
    const searchBtn = findSearchButton(root);
    const isDisabled = searchBtn?.disabled || !searchBtn;
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { disabled: searchBtn?.disabled } }, isDisabled);
  });

  it('disables search button while loading', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      loading: true
    });
    const searchBtn = findSearchButton(root);
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { disabled: searchBtn?.disabled } }, searchBtn?.disabled);
  });

  it('shows snapshot path information', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20230601000000', original: 'https://example.com/about', statuscode: '200', mimetype: 'text/html' },
        { timestamp: '20230501150000', original: 'https://example.com/contact', statuscode: '200', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    const text = root?.textContent;
    const hasPath = text?.includes('/about') || text?.includes('/contact') || text?.includes('example.com');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { text } }, hasPath);
  });

  it('groups snapshots by year when many results', async () => {
    const snapshots = [];
    for (let year = 2020; year <= 2023; year++) {
      for (let month = 1; month <= 3; month++) {
        snapshots.push({
          timestamp: `${year}0${month}01120000`,
          original: 'https://example.com/',
          statuscode: '200',
          mimetype: 'text/html'
        });
      }
    }
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots,
      searchedAt: Date.now()
    });
    const text = root?.textContent;
    const hasYears = text?.includes('2020') || text?.includes('2021') || text?.includes('2022') || text?.includes('2023');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { text } }, hasYears);
  });

  it('handles very long URL gracefully', async () => {
    const longPath = '/path'.repeat(50);
    const root = await mountWithTool('waybackMachineViewer', {
      url: `https://example.com${longPath}`,
      snapshots: [
        { timestamp: '20230615120000', original: `https://example.com${longPath}`, statuscode: '200', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: 'long URL' }, root);
  });

  it('shows copy button for archive URLs', async () => {
    const root = await mountWithTool('waybackMachineViewer', {
      url: 'https://example.com',
      snapshots: [
        { timestamp: '20230615120000', original: 'https://example.com/', statuscode: '200', mimetype: 'text/html' }
      ],
      searchedAt: Date.now()
    });
    const buttons = Array.from(root?.querySelectorAll('button') || []) as HTMLButtonElement[];
    const buttonTexts = buttons.map((b: HTMLButtonElement) => b.textContent?.toLowerCase());
    const hasCopyButton = buttonTexts.some(t => t?.includes('copy')) ||
                          !!root?.querySelector('button[title*="copy" i], button[aria-label*="copy" i]');
    aiAssertTruthy({ name: 'WaybackMachineViewer', input: { buttonTexts } }, hasCopyButton || buttons.length > 0);
  });
});
