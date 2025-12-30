import { beforeEach, describe, it } from 'vitest';
import { aiAssertEqual, aiAssertIncludes, aiAssertTruthy } from '../../test-utils/aiAssert';
import {
  resetChrome,
  setState,
  getState,
  flushPromises,
  waitFor,
  waitForState,
  mountContent,
  getShadowRoot,
  findButtonByText,
  findQuickBarButtonById,
  typeInput
} from './integration-test-utils';

describe('content entrypoint', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    resetChrome();
  });

  it('mounts and paginates quick bar favorites with search', async () => {
    await setState({
      isOpen: true,
      isVisible: true,
      isWide: true,
      quickBarToolIds: [
        'colorPicker',
        'jsonMinifier',
        'jsonPrettifier',
        'jsonSchemaValidator',
        'jsonPathTester',
        'jsonDiff',
        'codeInjector'
      ]
    });
    await mountContent();
    const root = getShadowRoot();
    aiAssertTruthy({ name: 'QuickBarRoot', state: { hasRoot: Boolean(root) } }, root);
    if (!root) return;

    const nextButton = await waitFor(() => findButtonByText(root, 'Next'));
    aiAssertTruthy({ name: 'QuickBarNextButton' }, nextButton);
    if (!nextButton) return;

    const pageLabel = await waitFor(() =>
      Array.from(root.querySelectorAll('span')).find((node) =>
        node.textContent?.includes('/')
      )
    );
    const pageText = pageLabel?.textContent ?? '';
    aiAssertIncludes(
      { name: 'QuickBarPagination', state: { text: pageText } },
      pageText,
      '/'
    );
    const match = pageText.match(/(\d+)\s*\/\s*(\d+)/);
    const totalPages = match ? Number(match[2]) : 1;
    if (totalPages > 1) {
      nextButton.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      await flushPromises();
      const pageLabelAfter = await waitFor(() =>
        Array.from(root.querySelectorAll('span')).find((node) =>
          node.textContent?.includes('/')
        )
      );
      aiAssertIncludes(
        {
          name: 'QuickBarPaginationAfter',
          state: { text: pageLabelAfter?.textContent }
        },
        pageLabelAfter?.textContent ?? '',
        `2 / ${totalPages}`
      );
    } else {
      aiAssertTruthy(
        { name: 'QuickBarPaginationSingle', state: { text: pageText } },
        nextButton.disabled
      );
    }

    const searchInput = (await waitFor(() =>
      root.querySelector('input[placeholder="Search favorites..."]')
    )) as HTMLInputElement | null;
    aiAssertTruthy({ name: 'QuickBarSearchInput' }, searchInput);
    if (!searchInput) return;
    typeInput(searchInput, 'json');
    await flushPromises();
    const resultsLabel = await waitFor(() =>
      Array.from(root.querySelectorAll('span')).find((node) =>
        node.textContent?.includes('results')
      )
    );
    aiAssertIncludes(
      { name: 'QuickBarSearchResults', input: { query: 'json' } },
      resultsLabel?.textContent ?? '',
      'results'
    );
  });

  it('reorders quick bar items via drag and drop', async () => {
    await setState({
      isOpen: true,
      isVisible: true,
      isWide: true,
      quickBarToolIds: ['colorPicker', 'jsonMinifier', 'jsonPrettifier']
    });
    await mountContent();
    const root = getShadowRoot();
    if (!root) return;

    const dragSource = await waitFor(() =>
      findQuickBarButtonById(root, 'colorPicker')
    );
    const dropTarget = await waitFor(() =>
      findQuickBarButtonById(root, 'jsonMinifier')
    );
    aiAssertTruthy({ name: 'QuickBarDragSource' }, dragSource);
    aiAssertTruthy({ name: 'QuickBarDropTarget' }, dropTarget);
    if (!dragSource || !dropTarget) return;

    const originalElementFromPoint = document.elementFromPoint;
    document.elementFromPoint = () => dropTarget as Element;
    dragSource.dispatchEvent(
      new PointerEvent('pointerdown', { bubbles: true, clientY: 10 })
    );
    const moveEvent = new PointerEvent('pointermove', { bubbles: true, clientY: 20 });
    Object.defineProperty(moveEvent, 'target', { value: dropTarget });
    window.dispatchEvent(moveEvent);
    dropTarget.dispatchEvent(new PointerEvent('pointerover', { bubbles: true }));
    const upEvent = new PointerEvent('pointerup', { bubbles: true, clientY: 20 });
    Object.defineProperty(upEvent, 'target', { value: dropTarget });
    window.dispatchEvent(upEvent);
    if (originalElementFromPoint) {
      document.elementFromPoint = originalElementFromPoint;
    } else {
      delete (document as unknown as { elementFromPoint?: unknown }).elementFromPoint;
    }
    await flushPromises();

    const stored = await waitForState((state) => {
      return state.quickBarToolIds[0] === 'jsonMinifier';
    });
    const order = stored?.quickBarToolIds ?? [];
    aiAssertEqual(
      { name: 'QuickBarReorderPersist', state: order },
      order,
      ['jsonMinifier', 'colorPicker', 'jsonPrettifier']
    );
  });

  it('switches pages when hovering pagination target during drag', async () => {
    await setState({
      isOpen: true,
      isVisible: true,
      isWide: true,
      quickBarToolIds: [
        'colorPicker',
        'jsonMinifier',
        'jsonPrettifier',
        'jsonSchemaValidator',
        'jsonPathTester',
        'jsonDiff',
        'codeInjector'
      ]
    });
    await mountContent();
    const root = getShadowRoot();
    if (!root) return;

    const dragSource = await waitFor(() =>
      findQuickBarButtonById(root, 'colorPicker')
    );
    const pageTwoButton = await waitFor(() => findButtonByText(root, '2'));
    aiAssertTruthy({ name: 'QuickBarPageTwoTarget' }, pageTwoButton);
    if (!dragSource || !pageTwoButton) return;

    dragSource.dispatchEvent(
      new PointerEvent('pointerdown', { bubbles: true, clientY: 10 })
    );
    pageTwoButton.dispatchEvent(new PointerEvent('pointerover', { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 600));

    const pageLabel = await waitFor(() =>
      Array.from(root.querySelectorAll('span')).find((node) =>
        node.textContent?.includes('2 /')
      )
    );
    aiAssertTruthy({ name: 'QuickBarPageSwitched' }, pageLabel);
  });

  it('opens spotlight overlay via cmd+shift+p and filters tools', async () => {
    await setState({ isOpen: true, isVisible: true });
    await mountContent();
    const root = getShadowRoot();
    if (!root) return;

    window.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'p', metaKey: true, shiftKey: true })
    );
    document.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'p', metaKey: true, shiftKey: true })
    );
    await flushPromises();
    await new Promise((resolve) => setTimeout(resolve, 0));

    const spotlightInput = (await waitFor(() =>
      root.querySelector('input[placeholder="Search tools..."]')
    )) as HTMLInputElement | null;
    aiAssertTruthy({ name: 'SpotlightInput' }, spotlightInput);
    if (!spotlightInput) return;
    typeInput(spotlightInput, 'color');
    await flushPromises();

    const foundMatch = Array.from(root.querySelectorAll('button')).some((button) =>
      button.textContent?.includes('Color Picker')
    );
    aiAssertTruthy(
      { name: 'SpotlightMatch', input: { query: 'color' } },
      foundMatch
    );
  });

  it('adds and removes tools from quick bar via tool window toggle', async () => {
    await setState({
      isOpen: true,
      isVisible: true,
      toolWindows: {
        colorPicker: { isOpen: true, isMinimized: false, x: 80, y: 120 }
      }
    });
    await mountContent();
    const root = getShadowRoot();
    if (!root) return;

    const toggleButton = await waitFor(() => findButtonByText(root, '+'));
    aiAssertTruthy({ name: 'QuickBarToggleButton' }, toggleButton);
    toggleButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const stored = await getState();
    aiAssertTruthy(
      { name: 'QuickBarAdded', state: stored },
      stored.quickBarToolIds.includes('colorPicker')
    );

    const removeButton = findButtonByText(root, '-');
    removeButton?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();
    const storedAfter = await getState();
    aiAssertTruthy(
      { name: 'QuickBarRemoved', state: storedAfter },
      !storedAfter.quickBarToolIds.includes('colorPicker')
    );
  });

  it('opens scraper builder from menu and shows modal', async () => {
    await setState({ isVisible: true, showMenuBar: true });
    await mountContent();
    const root = getShadowRoot();
    if (!root) return;

    const scraperMenu = await waitFor(() => findButtonByText(root, 'Scraper'));
    aiAssertTruthy({ name: 'ScraperMenuButton' }, scraperMenu);
    scraperMenu?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();

    const makeScraper = await waitFor(() => findButtonByText(root, 'Make Scraper'));
    aiAssertTruthy({ name: 'MakeScraperButton' }, makeScraper);
    makeScraper?.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await flushPromises();

    const modalTitle = await waitFor(() =>
      Array.from(root.querySelectorAll('div')).find((node) =>
        node.textContent?.includes('Build Scraper')
      )
    );
    aiAssertTruthy({ name: 'BuildScraperModal' }, modalTitle);
  });
});
