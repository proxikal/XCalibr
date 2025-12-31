import React, { useEffect, useMemo, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { defineContentScript } from 'wxt/sandbox';
import tailwindStyles from '../styles/index.css?inline';
import { updateState } from '../shared/state';
import { useAppState } from './content/hooks/useAppState';
import { useScraperBuilder } from './content/hooks/useScraperBuilder';
import { useLinkPreview } from './content/hooks/useLinkPreview';
import { useQuickBar } from './content/hooks/useQuickBar';
import {
  SpotlightSearch,
  ScraperBuilder,
  ScraperRunner,
  MenuBar,
  QuickBar,
  ToolWindow,
  MinimizedToolsBar
} from './content/components';
import { ROOT_ID, MENU_HEIGHT, MENU_BAR_HEIGHT } from './content/constants';

const App = () => {
  const appState = useAppState();
  const {
    state,
    setState,
    menuItems,
    toolRegistry,
    getToolEntry,
    toggleOpen,
    toggleWide,
    updateMenuBar,
    openTool,
    closeTool,
    minimizeTool,
    restoreTool,
    updateToolPosition,
    updateToolData,
    toggleQuickBarTool,
    menuBarRef
  } = appState;

  const scraperBuilder = useScraperBuilder(state, setState);
  const {
    pickerRect,
    pickerLabel,
    pickerNotice,
    showScraperHelp,
    setShowScraperHelp,
    regexPreviewMap,
    activeScraper,
    updateScraperDraft,
    openScraperBuilder,
    closeScraperBuilder,
    saveScraperDraft,
    updateScraperField,
    removeScraperField,
    openScraperRunner,
    rerunScraper,
    closeScraperRunner
  } = scraperBuilder;

  useLinkPreview(state);

  const quickBar = useQuickBar(state, setState, toolRegistry);
  const {
    quickBarSearch,
    setQuickBarSearch,
    quickBarPage,
    setQuickBarPage,
    quickBarDragId,
    quickBarDragOverIndex,
    quickBarDragOverPage,
    quickBarTools,
    filteredQuickBarTools,
    pagedQuickBarTools,
    quickBarTotalPages,
    quickBarDragEnabled,
    quickBarListRef,
    handleQuickBarPointerDown,
    handleQuickBarPageHover,
    clearQuickBarPageHover
  } = quickBar;

  const [spotlightOpen, setSpotlightOpen] = useState(false);
  const [dragOffsetY, setDragOffsetY] = useState<number | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [dragAnchored, setDragAnchored] = useState<boolean | null>(null);

  const dragStateRef = useRef({
    startY: 0,
    startOffset: 0,
    moved: false,
    lastOffset: 0,
    unanchored: false
  });

  // Spotlight keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (!(event.metaKey && event.shiftKey)) return;
      if (event.key.toLowerCase() !== 'p') return;
      event.preventDefault();
      setSpotlightOpen(true);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const clampTabOffset = (value: number, minOffset = 0) => {
    const maxOffset = Math.max(minOffset, window.innerHeight - tabHeight);
    return Math.min(Math.max(value, minOffset), maxOffset);
  };

  const handleTabPointerDown = (event: React.PointerEvent<HTMLButtonElement>) => {
    event.preventDefault();
    event.stopPropagation();
    const startOffset = clampTabOffset(
      state.tabOffsetY,
      state.showMenuBar && !state.isAnchored ? MENU_BAR_HEIGHT : 0
    );
    dragStateRef.current = {
      startY: event.clientY,
      startOffset,
      moved: false,
      lastOffset: startOffset,
      unanchored: false
    };
    setDragOffsetY(startOffset);
    setIsDragging(true);
    setDragAnchored(state.isAnchored);

    const handleMove = (moveEvent: PointerEvent) => {
      const delta = moveEvent.clientY - dragStateRef.current.startY;
      if (Math.abs(delta) > 3) {
        dragStateRef.current.moved = true;
      }
      if (
        state.showMenuBar &&
        state.isAnchored &&
        !dragStateRef.current.unanchored &&
        Math.abs(delta) > 3
      ) {
        dragStateRef.current.unanchored = true;
        dragStateRef.current.startOffset = MENU_BAR_HEIGHT;
        setDragAnchored(false);
      }
      const nextOffset = clampTabOffset(
        dragStateRef.current.startOffset + delta,
        state.showMenuBar && !dragStateRef.current.unanchored ? MENU_BAR_HEIGHT : 0
      );
      dragStateRef.current.lastOffset = nextOffset;
      setDragOffsetY(nextOffset);
    };

    const handleUp = async () => {
      window.removeEventListener('pointermove', handleMove);
      window.removeEventListener('pointerup', handleUp);

      const { moved, lastOffset } = dragStateRef.current;
      setIsDragging(false);
      setDragOffsetY(null);
      setDragAnchored(null);

      if (moved) {
        await updateState((current) => ({
          ...current,
          tabOffsetY: clampTabOffset(
            lastOffset,
            current.showMenuBar && !dragStateRef.current.unanchored ? MENU_BAR_HEIGHT : 0
          ),
          isAnchored:
            current.showMenuBar && !dragStateRef.current.unanchored
              ? current.isAnchored
              : false
        }));
        return;
      }

      await toggleOpen();
    };

    window.addEventListener('pointermove', handleMove);
    window.addEventListener('pointerup', handleUp, { once: true });
  };

  const panelWidth = useMemo(() => {
    if (!state.isOpen) return 0;
    return state.isWide ? 300 : 160;
  }, [state.isOpen, state.isWide]);

  if (!state.isVisible) {
    return null;
  }

  const isAnchoredEffective = state.showMenuBar && (dragAnchored ?? state.isAnchored);
  const tabHeight = isAnchoredEffective ? MENU_BAR_HEIGHT : 48;
  const topInset = state.showMenuBar && !isAnchoredEffective ? MENU_BAR_HEIGHT : 0;
  const effectiveOffset = clampTabOffset(
    isDragging && dragOffsetY !== null ? dragOffsetY : state.tabOffsetY,
    topInset
  );
  const viewportHeight = window.innerHeight;
  const tabCenter = effectiveOffset + tabHeight / 2;
  const transitionStart = viewportHeight * 0.5;
  const transitionEnd = viewportHeight * 0.85;
  const transitionRange = Math.max(1, transitionEnd - transitionStart);
  const transitionProgress = Math.min(
    Math.max((tabCenter - transitionStart) / transitionRange, 0),
    1
  );
  const anchorOffset = state.isOpen
    ? transitionProgress * (MENU_HEIGHT - tabHeight)
    : 0;
  const maxPanelTop = Math.max(topInset, viewportHeight - MENU_HEIGHT);
  const panelTop = isAnchoredEffective
    ? 0
    : Math.min(Math.max(effectiveOffset - anchorOffset, topInset), maxPanelTop);
  const tabTranslateY = Math.min(
    Math.max(effectiveOffset - panelTop, 0),
    MENU_HEIGHT - tabHeight
  );

  // Prepare minimized tools data
  const minimizedTools = Object.entries(state.toolWindows)
    .filter(([, toolState]) => toolState.isOpen && toolState.isMinimized)
    .map(([toolId]) => {
      const entry = getToolEntry(toolId);
      return entry ? { toolId, title: entry.title } : null;
    })
    .filter((item): item is { toolId: string; title: string } => item !== null);

  // Prepare open tool windows
  const openToolWindows = Object.entries(state.toolWindows)
    .filter(([, toolState]) => toolState.isOpen && !toolState.isMinimized)
    .map(([toolId, toolState]) => {
      const entry = getToolEntry(toolId);
      if (!entry) return null;
      return { toolId, toolState, entry };
    })
    .filter((item): item is { toolId: string; toolState: typeof state.toolWindows[string]; entry: NonNullable<ReturnType<typeof getToolEntry>> } => item !== null);

  return (
    <>
      {spotlightOpen && (
        <SpotlightSearch
          toolRegistry={toolRegistry}
          onOpenTool={openTool}
          onClose={() => setSpotlightOpen(false)}
        />
      )}

      {state.scraperBuilderOpen && !state.scraperDraft.isPicking && (
        <ScraperBuilder
          draft={state.scraperDraft}
          showHelp={showScraperHelp}
          regexPreviewMap={regexPreviewMap}
          onUpdateDraft={updateScraperDraft}
          onUpdateField={updateScraperField}
          onRemoveField={removeScraperField}
          onSave={saveScraperDraft}
          onClose={closeScraperBuilder}
          onShowHelp={() => setShowScraperHelp(true)}
          onHideHelp={() => setShowScraperHelp(false)}
        />
      )}

      {state.scraperBuilderOpen && state.scraperDraft.isPicking && (
        <div className="fixed top-4 left-1/2 z-[95] -translate-x-1/2 space-y-2">
          <div className="rounded-full border border-slate-700 bg-slate-900/90 px-4 py-2 text-[11px] text-slate-200 shadow-lg">
            <span className="mr-3">Picker active. Click elements to add fields.</span>
            <button
              type="button"
              onClick={() => updateScraperDraft({ isPicking: false })}
              className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
            >
              Stop Picking
            </button>
          </div>
          {pickerNotice && (
            <div className="rounded-full border border-slate-700 bg-slate-900/90 px-4 py-2 text-[11px] text-slate-200 shadow-lg">
              {pickerNotice}
            </div>
          )}
        </div>
      )}

      {state.scraperRunnerOpen && activeScraper && (
        <ScraperRunner
          scraper={activeScraper}
          results={state.scraperRunnerResults}
          onRerun={rerunScraper}
          onClose={closeScraperRunner}
        />
      )}

      {state.scraperDraft.isPicking && pickerRect && (
        <div className="fixed inset-0 z-[96] pointer-events-none">
          <div
            className="absolute border-2 border-blue-500/80 bg-blue-500/10"
            style={{
              left: pickerRect.left,
              top: pickerRect.top,
              width: pickerRect.width,
              height: pickerRect.height
            }}
          />
          <div
            className="absolute rounded bg-slate-900/90 px-2 py-1 text-[10px] text-slate-200"
            style={{
              left: pickerRect.left,
              top: Math.max(0, pickerRect.top - 24)
            }}
          >
            {pickerLabel}
          </div>
        </div>
      )}

      {state.showMenuBar && (
        <MenuBar
          menuBarRef={menuBarRef}
          state={state}
          setState={setState}
          menuItems={menuItems}
          getToolEntry={getToolEntry}
          onOpenTool={openTool}
          onOpenScraperRunner={openScraperRunner}
          onOpenScraperBuilder={openScraperBuilder}
        />
      )}

      <QuickBar
        isOpen={state.isOpen}
        isWide={state.isWide}
        isAnchored={isAnchoredEffective}
        showMenuBar={state.showMenuBar}
        panelWidth={panelWidth}
        panelTop={panelTop}
        tabTranslateY={tabTranslateY}
        tabHeight={tabHeight}
        quickBarSearch={quickBarSearch}
        setQuickBarSearch={setQuickBarSearch}
        quickBarPage={quickBarPage}
        setQuickBarPage={setQuickBarPage}
        quickBarTools={quickBarTools}
        filteredQuickBarTools={filteredQuickBarTools}
        pagedQuickBarTools={pagedQuickBarTools}
        quickBarTotalPages={quickBarTotalPages}
        quickBarDragId={quickBarDragId}
        quickBarDragOverIndex={quickBarDragOverIndex}
        quickBarDragOverPage={quickBarDragOverPage}
        quickBarDragEnabled={quickBarDragEnabled}
        quickBarListRef={quickBarListRef}
        onTabPointerDown={handleTabPointerDown}
        onToggleWide={toggleWide}
        onUpdateMenuBar={updateMenuBar}
        onQuickBarPointerDown={(event, item, index) =>
          handleQuickBarPointerDown(event, item, index, openTool)
        }
        onPageHover={handleQuickBarPageHover}
        onClearPageHover={clearQuickBarPageHover}
      />

      <MinimizedToolsBar tools={minimizedTools} onRestore={restoreTool} />

      {openToolWindows.map(({ toolId, toolState, entry }) => (
        <ToolWindow
          key={toolId}
          toolId={toolId}
          entry={entry}
          toolState={toolState}
          toolData={state.toolData[toolId]}
          isPinned={state.quickBarToolIds.includes(toolId)}
          onClose={() => closeTool(toolId)}
          onMinimize={() => minimizeTool(toolId)}
          onTogglePin={() => toggleQuickBarTool(toolId)}
          onUpdatePosition={(x, y) => updateToolPosition(toolId, x, y)}
          onUpdateData={(data) => updateToolData(toolId, data)}
        />
      ))}
    </>
  );
};

const mount = () => {
  if (document.getElementById(ROOT_ID)) return;

  const host = document.createElement('div');
  host.id = ROOT_ID;
  Object.assign(host.style, {
    position: 'fixed',
    top: '0',
    right: '0',
    zIndex: '2147483647',
    pointerEvents: 'none'
  });

  const shadow = host.attachShadow({ mode: 'open' });
  const styleTag = document.createElement('style');
  styleTag.textContent = tailwindStyles;
  shadow.appendChild(styleTag);

  const appRoot = document.createElement('div');
  appRoot.style.pointerEvents = 'auto';
  shadow.appendChild(appRoot);

  (document.body ?? document.documentElement).appendChild(host);

  const root = ReactDOM.createRoot(appRoot);
  root.render(<App />);
};

export default defineContentScript({
  matches: ['<all_urls>'],
  main() {
    mount();
  }
});
