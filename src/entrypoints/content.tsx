import React, { useEffect, useMemo, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faBolt,
  faChevronLeft,
  faChevronRight,
  faCompress,
  faExpand,
  faGear,
  faSearch
} from '@fortawesome/free-solid-svg-icons';
import { defineContentScript } from 'wxt/sandbox';
import tailwindStyles from '../styles/index.css?inline';
import { DEFAULT_STATE, getState, subscribeState, updateState } from '../shared/state';
import { baseMenuBarItems, type MenuBarItem } from './content/menu';
import {
  TOOL_DEFAULT_POSITION,
  ToolRegistryEntry,
  buildToolRegistry
} from './content/tool-registry';
import {
  ScraperDefinition,
  ScraperDraft,
  ScraperField,
  buildScraperId,
  buildCsvFromResults,
  extractScraperResults,
  getRegexMatchCount,
  generateCssSelector,
  generateXPath
} from '../shared/scraper';
import { moveItem } from '../shared/array-tools';
import { getAutoScrollDelta } from '../shared/drag-tools';
import { parseCookieString } from '../shared/web-tools';
import {
  createPreviewHost,
  isValidPreviewUrl,
  PREVIEW_SCALE,
  PREVIEW_WIDTH,
  PREVIEW_HEIGHT,
  PREVIEW_MARGIN
} from './content/Tools/helpers';
import type {
  RequestLogData,
  DebuggerData,
  CookieManagerData,
  LiveLinkPreviewData
} from './content/Tools/tool-types';

const ROOT_ID = 'xcalibr-root';

const App = () => {
  const [state, setState] = useState(DEFAULT_STATE);
  const [dragOffsetY, setDragOffsetY] = useState<number | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [dragAnchored, setDragAnchored] = useState<boolean | null>(null);
  const [spotlightOpen, setSpotlightOpen] = useState(false);
  const [spotlightQuery, setSpotlightQuery] = useState('');
  const [pickerRect, setPickerRect] = useState<DOMRect | null>(null);
  const [pickerLabel, setPickerLabel] = useState('');
  const [pickerNotice, setPickerNotice] = useState<string | null>(null);
  const [showScraperHelp, setShowScraperHelp] = useState(false);
  const [quickBarSearch, setQuickBarSearch] = useState('');
  const [quickBarPage, setQuickBarPage] = useState(1);
  const [quickBarDragId, setQuickBarDragId] = useState<string | null>(null);
  const [quickBarDragOverIndex, setQuickBarDragOverIndex] = useState<number | null>(
    null
  );
  const [quickBarDragOverPage, setQuickBarDragOverPage] = useState<number | null>(
    null
  );
  const menuBarRef = useRef<HTMLDivElement | null>(null);
  const spotlightInputRef = useRef<HTMLInputElement | null>(null);
  const requestLogSeenRef = useRef<Set<string>>(new Set());
  const debuggerSeenRef = useRef<number>(0);
  const quickBarDragIdRef = useRef<string | null>(null);
  const quickBarDragStartRef = useRef<{ x: number; y: number } | null>(null);
  const quickBarDidDragRef = useRef(false);
  const quickBarPageHoverRef = useRef<number | null>(null);
  const quickBarListRef = useRef<HTMLDivElement | null>(null);
  const quickBarPageRef = useRef(quickBarPage);
  const quickBarDragOverIndexRef = useRef<number | null>(quickBarDragOverIndex);
  const quickBarDragOverPageRef = useRef<number | null>(quickBarDragOverPage);
  const pagedQuickBarToolsRef = useRef(0);
  const linkPreviewHostRef = useRef<{
    host: HTMLDivElement;
    wrapper: HTMLDivElement;
    frame: HTMLIFrameElement;
    title: HTMLDivElement;
  } | null>(null);
  const linkPreviewAnchorRef = useRef<HTMLAnchorElement | null>(null);
  const linkPreviewTimeoutRef = useRef<number | null>(null);
  const toolDragRef = useRef<{
    toolId: string;
    offsetX: number;
    offsetY: number;
    startX: number;
    startY: number;
    moved: boolean;
    windowEl: HTMLElement | null;
  } | null>(null);
  const dragStateRef = useRef({
    startY: 0,
    startOffset: 0,
    moved: false,
    lastOffset: 0,
    unanchored: false
  });
  const iconSizeClass = 'w-3 h-3';
  const menuHeight = 550;
  const menuBarHeight = 32;

  const menuItems = useMemo((): MenuBarItem[] => {
    const scraperItems =
      state.scrapers.length > 0
        ? state.scrapers.map((scraper) => ({
            label: scraper.name,
            scraperId: scraper.id
          }))
        : ['No saved scrapers'];
    const scraperMenu: MenuBarItem = {
      label: 'Scraper',
      items: [
        { label: 'Make Scraper', action: 'makeScraper' },
        { label: 'Scraper List', items: scraperItems }
      ]
    };
    const items: MenuBarItem[] = [...baseMenuBarItems];
    const cyberIndex = items.findIndex((item) => item.label === 'CyberSec');
    if (cyberIndex === -1) {
      items.push(scraperMenu);
    } else {
      items.splice(cyberIndex + 1, 0, scraperMenu);
    }
    return items;
  }, [state.scrapers]);

  useEffect(() => {
    let mounted = true;
    getState().then((next) => {
      if (mounted) setState(next);
    });
    const unsubscribe = subscribeState(setState);
    return () => {
      mounted = false;
      unsubscribe();
    };
  }, []);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (!(event.metaKey && event.shiftKey)) return;
      if (event.key.toLowerCase() !== 'p') return;
      event.preventDefault();
      setSpotlightOpen(true);
      setSpotlightQuery('');
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    if (!spotlightOpen) return;
    requestAnimationFrame(() => spotlightInputRef.current?.focus());
  }, [spotlightOpen]);

  useEffect(() => {
    const isOpen = state.toolWindows.requestLog?.isOpen;
    if (!isOpen) return;

    const observer = new PerformanceObserver((list) => {
      const entries = list.getEntries() as PerformanceResourceTiming[];
      if (!entries.length) return;
      updateState((current) => {
        const existing =
          (current.toolData.requestLog as RequestLogData | undefined)?.entries ?? [];
        const nextEntries = [...existing];
        entries.forEach((entry) => {
          const key = `${entry.name}-${entry.startTime}`;
          if (requestLogSeenRef.current.has(key)) return;
          requestLogSeenRef.current.add(key);
          nextEntries.unshift({
            name: entry.name,
            initiatorType: entry.initiatorType,
            duration: entry.duration,
            transferSize: entry.transferSize,
            startTime: entry.startTime
          });
        });
        return {
          ...current,
          toolData: {
            ...current.toolData,
            requestLog: { entries: nextEntries.slice(0, 200) }
          }
        };
      }).then(setState);
    });

    try {
      observer.observe({ type: 'resource', buffered: true });
    } catch {
      // PerformanceObserver might not support resource entries on all pages.
    }
    return () => observer.disconnect();
  }, [state.toolWindows.requestLog?.isOpen]);

  useEffect(() => {
    const isOpen = state.toolWindows.debuggerTool?.isOpen;
    if (!isOpen) return;

    const addEntry = (message: string, source: string) => {
      updateState((current) => {
        const existing =
          (current.toolData.debuggerTool as DebuggerData | undefined)?.entries ?? [];
        const next = [
          { message, source, time: Date.now() },
          ...existing
        ].slice(0, 100);
        return {
          ...current,
          toolData: {
            ...current.toolData,
            debuggerTool: { entries: next }
          }
        };
      }).then(setState);
    };

    const handleError = (event: ErrorEvent) => {
      addEntry(event.message, 'error');
    };
    const handleRejection = (event: PromiseRejectionEvent) => {
      addEntry(
        event.reason instanceof Error ? event.reason.message : String(event.reason),
        'unhandledrejection'
      );
    };

    window.addEventListener('error', handleError);
    window.addEventListener('unhandledrejection', handleRejection);
    return () => {
      window.removeEventListener('error', handleError);
      window.removeEventListener('unhandledrejection', handleRejection);
    };
  }, [state.toolWindows.debuggerTool?.isOpen]);

  useEffect(() => {
    if (!state.scraperBuilderOpen || !state.scraperDraft.isPicking) return;

    const host = document.getElementById(ROOT_ID);

    const handleMove = (event: MouseEvent) => {
      const target = document.elementFromPoint(event.clientX, event.clientY);
      if (!target || (host && host.contains(target))) {
        setPickerRect(null);
        setPickerLabel('');
        return;
      }
      const rect = (target as Element).getBoundingClientRect();
      setPickerRect(rect);
      setPickerLabel(
        `${(target as Element).tagName.toLowerCase()}${(target as Element).id ? `#${(target as Element).id}` : ''}`
      );
    };

    const handleClick = (event: MouseEvent) => {
      const target = document.elementFromPoint(event.clientX, event.clientY);
      if (!target || (host && host.contains(target))) return;
      event.preventDefault();
      event.stopPropagation();
      const element = target as Element;
      const selector = generateCssSelector(element);
      const xpath = generateXPath(element);
      const isDuplicate = state.scraperDraft.fields.some(
        (field) => field.selector === selector || field.xpath === xpath
      );
      if (isDuplicate) {
        setPickerNotice('Element already added.');
        return;
      }
      const nextField: ScraperField = {
        id: `field_${Date.now()}_${Math.random().toString(16).slice(2)}`,
        name: `Field ${state.scraperDraft.fields.length + 1}`,
        selector,
        xpath,
        mode: 'single',
        source: 'text'
      };
      updateScraperDraft({ fields: [...state.scraperDraft.fields, nextField] });
      setPickerNotice('Element added.');
    };

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        updateScraperDraft({ isPicking: false });
        setPickerRect(null);
        setPickerLabel('');
      }
    };

    document.addEventListener('mousemove', handleMove, true);
    document.addEventListener('click', handleClick, true);
    window.addEventListener('keydown', handleKey, true);

    return () => {
      document.removeEventListener('mousemove', handleMove, true);
      document.removeEventListener('click', handleClick, true);
      window.removeEventListener('keydown', handleKey, true);
    };
  }, [state.scraperBuilderOpen, state.scraperDraft.isPicking, state.scraperDraft.fields.length]);

  useEffect(() => {
    if (!pickerNotice) return;
    const timeout = window.setTimeout(() => setPickerNotice(null), 1400);
    return () => window.clearTimeout(timeout);
  }, [pickerNotice]);

  const panelWidth = useMemo(() => {
    if (!state.isOpen) return 0;
    return state.isWide ? 300 : 160;
  }, [state.isOpen, state.isWide]);

  const categoryBadge = (category: string) => {
    switch (category) {
      case 'Web Dev':
        return 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30';
      case 'Front End':
        return 'bg-blue-500/10 text-blue-300 border-blue-500/30';
      case 'Back End':
        return 'bg-amber-500/10 text-amber-300 border-amber-500/30';
      case 'CyberSec':
        return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
      default:
        return 'bg-slate-500/10 text-slate-300 border-slate-500/30';
    }
  };

  const activeScraper = useMemo(
    () => state.scrapers.find((entry) => entry.id === state.scraperRunnerId) ?? null,
    [state.scrapers, state.scraperRunnerId]
  );

  const regexPreviewMap = useMemo(() => {
    const previews = new Map<string, { count: number; error: string | null; capped: boolean }>();
    if (!state.scraperBuilderOpen) return previews;
    const text = document.body?.innerText ?? '';
    state.scraperDraft.fields.forEach((field) => {
      if (field.source !== 'regex') return;
      previews.set(
        field.id,
        getRegexMatchCount(text, field.regex ?? '', field.regexFlags ?? '')
      );
    });
    return previews;
  }, [state.scraperBuilderOpen, state.scraperDraft.fields]);

  const clampTabOffset = (value: number, minOffset = 0) => {
    const maxOffset = Math.max(minOffset, window.innerHeight - tabHeight);
    return Math.min(Math.max(value, minOffset), maxOffset);
  };

  const toggleOpen = async () => {
    const next = await updateState((current) => ({
      ...current,
      isOpen: !current.isOpen
    }));
    setState(next);
  };

  const toggleWide = async () => {
    const next = await updateState((current) => ({
      ...current,
      isWide: !current.isWide
    }));
    setState(next);
  };

  const handleTabPointerDown = (event: React.PointerEvent<HTMLButtonElement>) => {
    event.preventDefault();
    event.stopPropagation();
    const startOffset = clampTabOffset(
      state.tabOffsetY,
      state.showMenuBar && !state.isAnchored ? menuBarHeight : 0
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
        dragStateRef.current.startOffset = menuBarHeight;
        setDragAnchored(false);
      }
      const nextOffset = clampTabOffset(
        dragStateRef.current.startOffset + delta,
        state.showMenuBar && !dragStateRef.current.unanchored ? menuBarHeight : 0
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
            current.showMenuBar && !dragStateRef.current.unanchored
              ? menuBarHeight
              : 0
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

  const updateMenuBar = async (value: boolean) => {
    const next = await updateState((current) => ({
      ...current,
      showMenuBar: value
    }));
    setState(next);
  };

  const toggleQuickBarTool = async (toolId: string) => {
    const next = await updateState((current) => {
      const isPinned = current.quickBarToolIds.includes(toolId);
      return {
        ...current,
        quickBarToolIds: isPinned
          ? current.quickBarToolIds.filter((id) => id !== toolId)
          : [...current.quickBarToolIds, toolId]
      };
    });
    setState(next);
  };

  const updateQuickBarOrder = async (fromIndex: number, toIndex: number) => {
    const next = await updateState((current) => ({
      ...current,
      quickBarToolIds: moveItem(current.quickBarToolIds, fromIndex, toIndex)
    }));
    setState(next);
  };

  const setQuickBarDragOver = (page: number, index: number) => {
    setQuickBarDragOverPage(page);
    setQuickBarDragOverIndex(index);
    quickBarDragOverPageRef.current = page;
    quickBarDragOverIndexRef.current = index;
  };

  const clearQuickBarDragState = () => {
    setQuickBarDragId(null);
    quickBarDragIdRef.current = null;
    quickBarDragStartRef.current = null;
    quickBarDidDragRef.current = false;
    setQuickBarDragOverIndex(null);
    setQuickBarDragOverPage(null);
    if (quickBarPageHoverRef.current) {
      window.clearTimeout(quickBarPageHoverRef.current);
      quickBarPageHoverRef.current = null;
    }
  };

  const refreshStorageExplorer = async () => {
    const local = Object.keys(localStorage).map((key) => ({
      key,
      value: localStorage.getItem(key) ?? ''
    }));
    const session = Object.keys(sessionStorage).map((key) => ({
      key,
      value: sessionStorage.getItem(key) ?? ''
    }));
    const next = await updateState((current) => ({
      ...current,
      toolData: {
        ...current.toolData,
        storageExplorer: { local, session }
      }
    }));
    setState(next);
  };

  const refreshCookies = async () => {
    const cookies = parseCookieString(document.cookie);
    const next = await updateState((current) => ({
      ...current,
      toolData: {
        ...current.toolData,
        cookieManager: { ...((current.toolData.cookieManager as CookieManagerData) ?? {}), cookies }
      }
    }));
    setState(next);
  };

  const toolRegistry = useMemo(
    () =>
      buildToolRegistry({
        refreshStorageExplorer,
        refreshCookies
      }),
    [refreshStorageExplorer, refreshCookies]
  );

  const getToolEntry = (toolId: string) =>
    toolRegistry.find((tool) => tool.id === toolId) ?? null;

  const quickBarTools = useMemo(
    () =>
      state.quickBarToolIds
        .map((toolId) => getToolEntry(toolId))
        .filter((entry): entry is ToolRegistryEntry => Boolean(entry)),
    [state.quickBarToolIds, toolRegistry]
  );

  const quickBarPageSize = 6;
  const filteredQuickBarTools = useMemo(() => {
    const query = quickBarSearch.trim().toLowerCase();
    if (!query) return quickBarTools;
    return quickBarTools.filter((tool) => {
      const title = tool.title.toLowerCase();
      const subtitle = tool.subtitle.toLowerCase();
      return title.includes(query) || subtitle.includes(query);
    });
  }, [quickBarSearch, quickBarTools]);
  const quickBarTotalPages = Math.max(
    1,
    Math.ceil(filteredQuickBarTools.length / quickBarPageSize)
  );
  const quickBarDragEnabled = quickBarSearch.trim().length === 0;
  const pagedQuickBarTools = useMemo(() => {
    const start = (quickBarPage - 1) * quickBarPageSize;
    return filteredQuickBarTools.slice(start, start + quickBarPageSize);
  }, [filteredQuickBarTools, quickBarPage]);
  useEffect(() => {
    quickBarPageRef.current = quickBarPage;
  }, [quickBarPage]);
  useEffect(() => {
    quickBarDragOverIndexRef.current = quickBarDragOverIndex;
  }, [quickBarDragOverIndex]);
  useEffect(() => {
    quickBarDragOverPageRef.current = quickBarDragOverPage;
  }, [quickBarDragOverPage]);
  useEffect(() => {
    pagedQuickBarToolsRef.current = pagedQuickBarTools.length;
  }, [pagedQuickBarTools.length]);

  useEffect(() => {
    setQuickBarPage(1);
  }, [quickBarSearch, state.quickBarToolIds.length]);

  useEffect(() => {
    if (quickBarPage > quickBarTotalPages) {
      setQuickBarPage(quickBarTotalPages);
    }
  }, [quickBarPage, quickBarTotalPages]);

  const handleQuickBarPageHover = (page: number) => {
    if (!quickBarDragIdRef.current && !quickBarDragId) return;
    if (quickBarPageHoverRef.current) {
      window.clearTimeout(quickBarPageHoverRef.current);
    }
    quickBarPageHoverRef.current = window.setTimeout(() => {
      setQuickBarPage(page);
      setQuickBarDragOverPage(page);
      quickBarDragOverPageRef.current = page;
    }, 500);
  };

  const clearQuickBarPageHover = () => {
    if (quickBarPageHoverRef.current) {
      window.clearTimeout(quickBarPageHoverRef.current);
      quickBarPageHoverRef.current = null;
    }
  };

  const searchableTools = useMemo(
    () =>
      toolRegistry.map((tool) => ({
        id: tool.id,
        label: tool.title,
        subtitle: tool.subtitle
      })),
    [toolRegistry]
  );

  const spotlightMatches = useMemo(() => {
    const query = spotlightQuery.trim().toLowerCase();
    if (!query) return searchableTools;
    return searchableTools.filter((entry) => {
      const label = entry.label.toLowerCase();
      const subtitle = entry.subtitle?.toLowerCase() ?? '';
      return label.includes(query) || subtitle.includes(query);
    });
  }, [spotlightQuery, searchableTools]);

  const updateScraperDraft = async (nextDraft: Partial<ScraperDraft>) => {
    const next = await updateState((current) => ({
      ...current,
      scraperDraft: {
        ...current.scraperDraft,
        ...nextDraft
      }
    }));
    setState(next);
  };

  const openScraperBuilder = async () => {
    const next = await updateState((current) => ({
      ...current,
      scraperBuilderOpen: true
    }));
    setState(next);
  };

  const closeScraperBuilder = async () => {
    const next = await updateState((current) => ({
      ...current,
      scraperBuilderOpen: false,
      scraperDraft: { ...current.scraperDraft, isPicking: false }
    }));
    setState(next);
    setPickerRect(null);
    setShowScraperHelp(false);
  };

  const saveScraperDraft = async () => {
    const draft = state.scraperDraft;
    if (!draft.name.trim() || draft.fields.length === 0) return;
    const now = Date.now();
    const newScraper: ScraperDefinition = {
      id: buildScraperId(),
      name: draft.name.trim(),
      fields: draft.fields,
      createdAt: now,
      updatedAt: now
    };
    const next = await updateState((current) => ({
      ...current,
      scrapers: [...current.scrapers, newScraper],
      scraperBuilderOpen: false,
      scraperDraft: { name: '', fields: [], isPicking: false }
    }));
    setState(next);
    setPickerRect(null);
  };

  const updateScraperField = async (fieldId: string, next: Partial<ScraperField>) => {
    const nextFields = state.scraperDraft.fields.map((field) =>
      field.id === fieldId ? { ...field, ...next } : field
    );
    await updateScraperDraft({ fields: nextFields });
  };

  const removeScraperField = async (fieldId: string) => {
    const nextFields = state.scraperDraft.fields.filter((field) => field.id !== fieldId);
    await updateScraperDraft({ fields: nextFields });
  };

  const openScraperRunner = async (scraperId: string) => {
    const scraper = state.scrapers.find((entry) => entry.id === scraperId);
    if (!scraper) return;
    const results = extractScraperResults(document, scraper);
    const next = await updateState((current) => ({
      ...current,
      scraperRunnerOpen: true,
      scraperRunnerId: scraperId,
      scraperRunnerResults: results,
      scraperRunnerError: null
    }));
    setState(next);
  };

  const rerunScraper = async () => {
    if (!state.scraperRunnerId) return;
    const scraper = state.scrapers.find((entry) => entry.id === state.scraperRunnerId);
    if (!scraper) return;
    const results = extractScraperResults(document, scraper);
    const next = await updateState((current) => ({
      ...current,
      scraperRunnerResults: results,
      scraperRunnerError: null
    }));
    setState(next);
  };

  const closeScraperRunner = async () => {
    const next = await updateState((current) => ({
      ...current,
      scraperRunnerOpen: false,
      scraperRunnerId: null,
      scraperRunnerError: null
    }));
    setState(next);
  };


  const openTool = async (toolId: string) => {
    const next = await updateState((current) => {
      const existing = current.toolWindows[toolId];
      return {
        ...current,
        toolWindows: {
          ...current.toolWindows,
          [toolId]: {
            isOpen: true,
            isMinimized: false,
            x: existing?.x ?? TOOL_DEFAULT_POSITION.x,
            y: existing?.y ?? TOOL_DEFAULT_POSITION.y
          }
        }
      };
    });
    setState(next);
  };

  const openToolFromSpotlight = async (toolId: string) => {
    await openTool(toolId);
    setSpotlightOpen(false);
    setSpotlightQuery('');
  };

  const closeTool = async (toolId: string) => {
    const next = await updateState((current) => {
      const existing = current.toolWindows[toolId];
      if (!existing) return current;
      return {
        ...current,
        toolWindows: {
          ...current.toolWindows,
          [toolId]: { ...existing, isOpen: false, isMinimized: false }
        }
      };
    });
    setState(next);
  };

  const minimizeTool = async (toolId: string) => {
    const next = await updateState((current) => {
      const existing = current.toolWindows[toolId];
      if (!existing) return current;
      return {
        ...current,
        toolWindows: {
          ...current.toolWindows,
          [toolId]: { ...existing, isMinimized: true, isOpen: true }
        }
      };
    });
    setState(next);
  };

  const restoreTool = async (toolId: string) => {
    const next = await updateState((current) => {
      const existing = current.toolWindows[toolId];
      if (!existing) return current;
      return {
        ...current,
        toolWindows: {
          ...current.toolWindows,
          [toolId]: { ...existing, isMinimized: false, isOpen: true }
        }
      };
    });
    setState(next);
  };

  const updateToolPosition = async (toolId: string, x: number, y: number) => {
    const next = await updateState((current) => {
      const existing = current.toolWindows[toolId];
      if (!existing) return current;
      return {
        ...current,
        toolWindows: {
          ...current.toolWindows,
          [toolId]: { ...existing, x, y }
        }
      };
    });
    setState(next);
  };

  const updateToolData = async (toolId: string, data: unknown) => {
    const next = await updateState((current) => ({
      ...current,
      toolData: {
        ...current.toolData,
        [toolId]: data
      }
    }));
    setState(next);
  };

  useEffect(() => {
    const handleDocumentClick = (event: MouseEvent) => {
      if (!menuBarRef.current) return;
      const path = typeof event.composedPath === 'function' ? event.composedPath() : [];
      if (path.includes(menuBarRef.current)) return;
      updateState((current) => ({
        ...current,
        menuBarActiveMenu: null,
        menuBarActiveSubmenu: null
      })).then(setState);
    };

    document.addEventListener('mousedown', handleDocumentClick);
    return () => document.removeEventListener('mousedown', handleDocumentClick);
  }, []);

  useEffect(() => {
    const entries =
      (state.toolData.requestLog as RequestLogData | undefined)?.entries ?? [];
    if (entries.length === 0) {
      requestLogSeenRef.current.clear();
    }
  }, [state.toolData.requestLog]);

  useEffect(() => {
    if (!state.showMenuBar) {
      updateState((current) => ({
        ...current,
        menuBarActiveMenu: null,
        menuBarActiveSubmenu: null
      })).then(setState);
      if (state.isAnchored) {
        updateState((current) => ({
          ...current,
          isAnchored: false
        })).then(setState);
      }
      return;
    }
    if (state.tabOffsetY <= menuBarHeight) {
      updateState((current) => ({
        ...current,
        tabOffsetY: 0,
        isAnchored: true
      })).then(setState);
    }
  }, [menuBarHeight, state.showMenuBar, state.tabOffsetY]);

  useEffect(() => {
    const isActive = Boolean(
      (state.toolData.liveLinkPreview as LiveLinkPreviewData | undefined)?.isActive
    );
    if (!isActive) {
      if (linkPreviewTimeoutRef.current) {
        window.clearTimeout(linkPreviewTimeoutRef.current);
        linkPreviewTimeoutRef.current = null;
      }
      if (linkPreviewHostRef.current) {
        linkPreviewHostRef.current.host.remove();
        linkPreviewHostRef.current = null;
      }
      linkPreviewAnchorRef.current = null;
      return;
    }

    const hidePreview = () => {
      if (linkPreviewTimeoutRef.current) {
        window.clearTimeout(linkPreviewTimeoutRef.current);
        linkPreviewTimeoutRef.current = null;
      }
      if (linkPreviewHostRef.current) {
        linkPreviewHostRef.current.host.remove();
        linkPreviewHostRef.current = null;
      }
      linkPreviewAnchorRef.current = null;
    };

    const showPreview = (anchor: HTMLAnchorElement) => {
      const href = anchor.getAttribute('href') ?? '';
      if (!href || !isValidPreviewUrl(anchor.href)) return;
      if (!linkPreviewHostRef.current) {
        linkPreviewHostRef.current = createPreviewHost();
      }
      const { wrapper, frame, title } = linkPreviewHostRef.current;
      frame.src = anchor.href;
      title.textContent = anchor.href;
      const rect = anchor.getBoundingClientRect();
      const width = PREVIEW_WIDTH * PREVIEW_SCALE;
      const height = PREVIEW_HEIGHT * PREVIEW_SCALE;
      const fitsBelow = rect.bottom + height + PREVIEW_MARGIN < window.innerHeight;
      const top = fitsBelow
        ? rect.bottom + PREVIEW_MARGIN
        : Math.max(PREVIEW_MARGIN, rect.top - height - PREVIEW_MARGIN);
      const left = Math.min(
        Math.max(PREVIEW_MARGIN, rect.left),
        window.innerWidth - width - PREVIEW_MARGIN
      );
      wrapper.style.top = `${top}px`;
      wrapper.style.left = `${left}px`;
    };

    const handleMouseOver = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (!target) return;
      const host = document.getElementById(ROOT_ID);
      if (host && host.contains(target)) return;
      const anchor = target.closest('a') as HTMLAnchorElement | null;
      if (!anchor || !anchor.href) return;
      if (linkPreviewAnchorRef.current === anchor) return;
      linkPreviewAnchorRef.current = anchor;
      if (linkPreviewTimeoutRef.current) {
        window.clearTimeout(linkPreviewTimeoutRef.current);
      }
      linkPreviewTimeoutRef.current = window.setTimeout(() => {
        showPreview(anchor);
      }, 500);
    };

    const handleMouseOut = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (!target) return;
      const anchor = target.closest('a') as HTMLAnchorElement | null;
      if (!anchor || anchor !== linkPreviewAnchorRef.current) return;
      hidePreview();
    };

    document.addEventListener('mouseover', handleMouseOver);
    document.addEventListener('mouseout', handleMouseOut);
    return () => {
      document.removeEventListener('mouseover', handleMouseOver);
      document.removeEventListener('mouseout', handleMouseOut);
      hidePreview();
    };
  }, [state.toolData.liveLinkPreview]);

  const handleMenuClick = (label: string) => {
    updateState((current) => ({
      ...current,
      menuBarActiveMenu: current.menuBarActiveMenu === label ? null : label,
      menuBarActiveSubmenu: null
    })).then(setState);
  };

  const handleScraperAction = async (action: string) => {
    if (action === 'makeScraper') {
      await openScraperBuilder();
      const next = await updateState((current) => ({
        ...current,
        menuBarActiveMenu: null,
        menuBarActiveSubmenu: null
      }));
      setState(next);
    }
  };

  if (!state.isVisible) {
    return null;
  }

  const isAnchoredEffective = state.showMenuBar && (dragAnchored ?? state.isAnchored);
  const tabHeight = isAnchoredEffective ? menuBarHeight : 48;
  const topInset = state.showMenuBar && !isAnchoredEffective ? menuBarHeight : 0;
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
    ? transitionProgress * (menuHeight - tabHeight)
    : 0;
  const maxPanelTop = Math.max(topInset, viewportHeight - menuHeight);
  const panelTop = isAnchoredEffective
    ? 0
    : Math.min(Math.max(effectiveOffset - anchorOffset, topInset), maxPanelTop);
  const tabTranslateY = Math.min(
    Math.max(effectiveOffset - panelTop, 0),
    menuHeight - tabHeight
  );
  const quickBarPageStart = (quickBarPage - 1) * quickBarPageSize;

  return (
    <>
      {spotlightOpen ? (
        <div
          className="fixed inset-0 z-[90] flex items-start justify-center bg-slate-950/70 backdrop-blur-sm"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              setSpotlightOpen(false);
            }
          }}
        >
          <div
            className="mt-24 w-full max-w-xl rounded-2xl border border-slate-700/80 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 shadow-[0_24px_60px_rgba(0,0,0,0.55)]"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="flex items-center gap-3 border-b border-slate-800 px-5 py-4">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-slate-800/80 text-slate-300">
                <FontAwesomeIcon icon={faSearch} className="w-4 h-4" />
              </div>
              <div className="flex-1">
                <div className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                  XCalibr Spotlight
                </div>
                <input
                  ref={spotlightInputRef}
                  type="text"
                  value={spotlightQuery}
                  onChange={(event) => setSpotlightQuery(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key !== 'Enter') return;
                    event.preventDefault();
                    const match = spotlightMatches[0];
                    if (!match) return;
                    openToolFromSpotlight(match.id);
                  }}
                  placeholder="Search tools..."
                  className="mt-1 w-full bg-transparent text-lg text-slate-100 placeholder:text-slate-500 focus:outline-none"
                />
              </div>
              <div className="text-[10px] text-slate-500">Cmd+Shift+P</div>
            </div>
            <div className="max-h-72 overflow-y-auto p-2">
              {spotlightMatches.length === 0 ? (
                <div className="px-4 py-6 text-sm text-slate-400">
                  Nothing found. Try another keyword.
                </div>
              ) : (
                spotlightMatches.map((entry) => (
                  <button
                    key={entry.id}
                    type="button"
                    className="w-full rounded-xl px-4 py-3 text-left transition-colors hover:bg-slate-800/80"
                    onClick={() => openToolFromSpotlight(entry.id)}
                  >
                    <div className="text-sm text-slate-100">{entry.label}</div>
                    <div className="text-[11px] text-slate-500">
                      {entry.subtitle ?? 'Open tool'}
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
        </div>
      ) : null}
      {state.scraperBuilderOpen ? (
        state.scraperDraft.isPicking ? (
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
            {pickerNotice ? (
              <div className="rounded-full border border-slate-700 bg-slate-900/90 px-4 py-2 text-[11px] text-slate-200 shadow-lg">
                {pickerNotice}
              </div>
            ) : null}
          </div>
        ) : (
          <div
            className="fixed inset-0 z-[95] flex items-start justify-center bg-slate-950/70 backdrop-blur-sm"
            onMouseDown={(event) => {
              if (event.target === event.currentTarget) {
                closeScraperBuilder();
              }
            }}
          >
            <div
              className="mt-12 w-full max-w-2xl max-h-[85vh] rounded-2xl border border-slate-700/80 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 shadow-[0_24px_60px_rgba(0,0,0,0.55)] flex flex-col"
              onMouseDown={(event) => event.stopPropagation()}
            >
              {showScraperHelp ? (
                <div className="absolute inset-0 z-[96] rounded-2xl bg-slate-950/90 backdrop-blur-sm">
                  <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
                    <div>
                      <div className="text-xs text-slate-200">Scraper Guide</div>
                      <div className="text-[11px] text-slate-500">
                        Learn how to build and run a scraper safely.
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setShowScraperHelp(false)}
                      className="text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      ×
                    </button>
                  </div>
                  <div className="max-h-[70vh] overflow-y-auto px-5 py-4 space-y-4 text-[11px] text-slate-300">
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        1. Name Your Scraper
                      </div>
                      <div>
                        Give the scraper a clear name so you can find it later in
                        the Scraper List.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        2. Pick Elements
                      </div>
                      <div>
                        Click “Pick Elements” and hover the page. Click any element
                        you want to extract. Each click adds a field.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        3. Rename Fields
                      </div>
                      <div>
                        Rename fields so the output makes sense (e.g. Price, Title,
                        Description).
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        4. Choose Mode
                      </div>
                      <div>
                        Use “Single” for one value, or “List” when you want all
                        matching elements on the page.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        4b. Get Every Instance
                      </div>
                      <div>
                        Use List mode with a broad selector or Regex to capture all
                        matches like emails or URLs.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        5. Choose Source
                      </div>
                      <div>
                        Pick Text, HTML, or Attribute. Attribute is useful for
                        links (href) or images (src).
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        5b. Regex Source
                      </div>
                      <div>
                        Add a Regex field to scan the entire page text. Start with
                        presets like Emails or URLs and tweak the pattern if needed.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        6. Save Scraper
                      </div>
                      <div>
                        Save when you have at least one field. It will appear in
                        the Scraper List menu.
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        7. Run Scraper
                      </div>
                      <div>
                        Open Scraper List, choose your scraper, and review results.
                        Use Copy JSON or Copy CSV to export.
                      </div>
                    </div>
                  </div>
                </div>
              ) : null}
              <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
                <div>
                  <div className="text-xs text-slate-200">Build Scraper</div>
                  <div className="text-[11px] text-slate-500">
                    Click elements on the page to capture selectors.
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setShowScraperHelp(true)}
                    className="text-[11px] text-blue-300 hover:text-blue-200 transition-colors"
                  >
                    Explain Scraper
                  </button>
                  <button
                    type="button"
                    onClick={closeScraperBuilder}
                    className="text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    ×
                  </button>
                </div>
              </div>
              <div className="space-y-4 px-5 py-4">
                <div className="space-y-2">
                  <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
                    Scraper Name
                  </div>
                  <input
                    type="text"
                    value={state.scraperDraft.name}
                    onChange={(event) =>
                      updateScraperDraft({ name: event.target.value })
                    }
                    className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
                    placeholder="e.g. Pricing Table"
                  />
                </div>
              </div>
              <div className="flex-1 overflow-y-auto px-5 pb-4 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="text-[11px] text-slate-500">Picker idle</div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        const nextField: ScraperField = {
                          id: `field_${Date.now()}_${Math.random().toString(16).slice(2)}`,
                          name: `Regex ${state.scraperDraft.fields.length + 1}`,
                          selector: 'document',
                          xpath: 'document',
                          mode: 'list',
                          source: 'regex',
                          regex: '',
                          regexFlags: 'gi'
                        };
                        updateScraperDraft({
                          fields: [...state.scraperDraft.fields, nextField]
                        });
                      }}
                      className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                    >
                      Add Regex Field
                    </button>
                    <button
                      type="button"
                      onClick={() => updateScraperDraft({ isPicking: true })}
                      className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                    >
                      Pick Elements
                    </button>
                  </div>
                </div>

                <div className="space-y-3">
                  {state.scraperDraft.fields.length === 0 ? (
                    <div className="text-[11px] text-slate-500">
                      No fields yet. Click “Pick Elements” and select elements on the page.
                    </div>
                  ) : (
                    state.scraperDraft.fields.map((field) => (
                      <div
                        key={field.id}
                        className="rounded border border-slate-800 bg-slate-900/60 p-3 space-y-2"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <input
                            type="text"
                            value={field.name}
                            onChange={(event) =>
                              updateScraperField(field.id, {
                                name: event.target.value
                              })
                            }
                            className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
                          />
                          <button
                            type="button"
                            onClick={() => removeScraperField(field.id)}
                            className="text-slate-500 hover:text-rose-300 transition-colors"
                          >
                            ×
                          </button>
                        </div>

                        <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                          Selector
                        </div>
                        <div className="text-[11px] text-slate-300 break-words">
                          {field.selector}
                        </div>
                        <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                          XPath
                        </div>
                        <div className="text-[11px] text-slate-400 break-words">
                          {field.xpath}
                        </div>

                        <div className="flex gap-2">
                          {(['single', 'list'] as const).map((mode) => (
                            <button
                              key={mode}
                              type="button"
                              onClick={() => updateScraperField(field.id, { mode })}
                              className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
                                field.mode === mode
                                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                              }`}
                            >
                              {mode === 'single' ? 'Single' : 'List'}
                            </button>
                          ))}
                        </div>

                      <div className="flex gap-2">
                        {(['text', 'html', 'attr', 'regex'] as const).map((source) => (
                          <button
                            key={source}
                            type="button"
                            onClick={() =>
                              updateScraperField(field.id, {
                                source,
                                ...(source === 'regex'
                                  ? { selector: 'document', xpath: 'document', mode: 'list' }
                                  : {})
                              })
                            }
                            className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
                              field.source === source
                                ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                                : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                            }`}
                          >
                            {source === 'attr'
                              ? 'Attribute'
                              : source === 'regex'
                                ? 'Regex'
                                : source.toUpperCase()}
                          </button>
                        ))}
                      </div>
                      {field.source === 'attr' ? (
                        <input
                          type="text"
                          value={field.attrName ?? ''}
                          onChange={(event) =>
                            updateScraperField(field.id, {
                              attrName: event.target.value
                            })
                          }
                          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
                          placeholder="Attribute name (e.g. href)"
                        />
                      ) : null}
                      {field.source === 'regex' ? (
                        <div className="space-y-2">
                          <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                            Regex Pattern
                          </div>
                          <input
                            type="text"
                            value={field.regex ?? ''}
                            onChange={(event) =>
                              updateScraperField(field.id, { regex: event.target.value })
                            }
                            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
                            placeholder="e.g. [A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}"
                          />
                          <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                            Flags
                          </div>
                          <input
                            type="text"
                            value={field.regexFlags ?? 'gi'}
                            onChange={(event) =>
                              updateScraperField(field.id, {
                                regexFlags: event.target.value
                              })
                            }
                            className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500 font-mono"
                            placeholder="e.g. gi"
                          />
                          <div className="flex gap-2">
                            <button
                              type="button"
                              onClick={() =>
                                updateScraperField(field.id, {
                                  regex:
                                    '[A-Z0-9._%+-]+@[A-Z0-9.-]+\\\\.[A-Z]{2,}',
                                  regexFlags: 'gi',
                                  mode: 'list'
                                })
                              }
                              className="flex-1 rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                            >
                              Emails
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                updateScraperField(field.id, {
                                  regex: "https?://[^\\s\"'`<>]+",
                                  regexFlags: 'gi',
                                  mode: 'list'
                                })
                              }
                              className="flex-1 rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                            >
                              URLs
                            </button>
                          </div>
                          {regexPreviewMap.get(field.id)?.error ? (
                            <div className="text-[11px] text-rose-300">
                              {regexPreviewMap.get(field.id)?.error}
                            </div>
                          ) : (
                            <div className="text-[11px] text-slate-500">
                              Matches on page:{' '}
                              {regexPreviewMap.get(field.id)?.count ?? 0}
                              {regexPreviewMap.get(field.id)?.capped ? '+' : ''}
                            </div>
                          )}
                          <div className="text-[11px] text-slate-500">
                            Regex runs against full page text.
                          </div>
                        </div>
                      ) : null}
                    </div>
                  ))
                )}
                </div>
              </div>
              <div className="flex items-center justify-end gap-2 border-t border-slate-800 px-5 py-4">
                <button
                  type="button"
                  onClick={closeScraperBuilder}
                  className="rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={saveScraperDraft}
                  disabled={
                    !state.scraperDraft.name.trim() ||
                    state.scraperDraft.fields.length === 0
                  }
                  className="rounded bg-blue-600 px-3 py-1.5 text-xs text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
                >
                  Save Scraper
                </button>
              </div>
            </div>
          </div>
        )
      ) : null}
      {state.scraperRunnerOpen && activeScraper ? (
        <div
          className="fixed inset-0 z-[95] flex items-start justify-center bg-slate-950/70 backdrop-blur-sm"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              closeScraperRunner();
            }
          }}
        >
          <div
            className="mt-12 w-full max-w-2xl max-h-[85vh] rounded-2xl border border-slate-700/80 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 shadow-[0_24px_60px_rgba(0,0,0,0.55)] flex flex-col"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
              <div>
                <div className="text-xs text-slate-200">Run Scraper</div>
                <div className="text-[11px] text-slate-500">
                  {activeScraper.name}
                </div>
              </div>
              <button
                type="button"
                onClick={closeScraperRunner}
                className="text-slate-400 hover:text-slate-200 transition-colors"
              >
                ×
              </button>
            </div>
            <div className="space-y-4 px-5 py-4">
              <div className="flex items-center justify-between">
                <div className="text-[11px] text-slate-500">
                  {state.scraperRunnerResults ? 'Results ready.' : 'No results yet.'}
                </div>
                <button
                  type="button"
                  onClick={rerunScraper}
                  className="rounded bg-slate-800 px-2 py-1 text-[11px] text-slate-300 hover:bg-slate-700 transition-colors"
                >
                  Run Again
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto px-5 pb-4">
              {state.scraperRunnerResults ? (
                <div className="rounded border border-slate-800 bg-slate-900/60 p-3 space-y-2 text-[11px] text-slate-300">
                  {Object.entries(state.scraperRunnerResults).map(([key, value]) => (
                    <div key={key}>
                      <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500">
                        {key}
                      </div>
                      <div className="break-words">
                        {Array.isArray(value) ? value.join(', ') : value}
                      </div>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
            <div className="flex items-center justify-end gap-2 border-t border-slate-800 px-5 py-4">
              <button
                type="button"
                onClick={() =>
                  navigator.clipboard.writeText(
                    JSON.stringify(state.scraperRunnerResults ?? {}, null, 2)
                  )
                }
                className="rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Copy JSON
              </button>
              <button
                type="button"
                onClick={() =>
                  navigator.clipboard.writeText(
                    buildCsvFromResults(state.scraperRunnerResults ?? {})
                  )
                }
                className="rounded bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
              >
                Copy CSV
              </button>
            </div>
          </div>
        </div>
      ) : null}
      {state.scraperDraft.isPicking && pickerRect ? (
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
      ) : null}
      {state.showMenuBar ? (
        <div
          ref={menuBarRef}
          className="pointer-events-auto fixed top-0 left-0 right-0 z-50 bg-slate-900 border-b border-slate-800 text-slate-200 shadow-lg"
          style={{
            fontFamily: "'Inter', ui-sans-serif, system-ui, -apple-system",
            height: menuBarHeight
          }}
        >
          <div className="flex h-full items-center gap-1 px-3">
            <div className="flex items-center gap-2 mr-2">
              <div className="w-5 h-5 rounded bg-blue-600 flex items-center justify-center">
                <FontAwesomeIcon icon={faBolt} className="w-3 h-3 text-white" />
              </div>
              <span className="text-xs font-semibold text-slate-100">XCalibr</span>
            </div>
            {menuItems.map((item) => {
              const isOpen = state.menuBarActiveMenu === item.label;
              return (
                <div
                  key={item.label}
                  className="relative"
                >
                  <button
                    type="button"
                    onClick={() => handleMenuClick(item.label)}
                    className="px-2 py-1 text-xs text-slate-300 rounded hover:bg-slate-800 transition-colors"
                  >
                    {item.label}
                  </button>
                  <div
                    className={`absolute left-0 mt-1 w-44 bg-slate-900 border border-slate-700 rounded shadow-2xl transition-opacity ${
                      isOpen
                        ? 'opacity-100 pointer-events-auto'
                        : 'opacity-0 pointer-events-none'
                    }`}
                  >
                    <div className="py-1">
                      {item.items.map((entry) => {
                      if (typeof entry === 'string') {
                        return (
                          <button
                            key={entry}
                            type="button"
                            className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                          >
                            {entry}
                          </button>
                        );
                      }
                      if ('toolId' in entry) {
                        return (
                          <button
                            key={entry.label}
                            type="button"
                            onClick={async () => {
                              await openTool(entry.toolId);
                              const next = await updateState((current) => ({
                                ...current,
                                menuBarActiveMenu: null,
                                menuBarActiveSubmenu: null
                              }));
                              setState(next);
                            }}
                            className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                          >
                            {entry.label}
                          </button>
                        );
                      }
                      if ('scraperId' in entry) {
                        return (
                          <button
                            key={entry.label}
                            type="button"
                            onClick={async () => {
                              await openScraperRunner(entry.scraperId);
                              const next = await updateState((current) => ({
                                ...current,
                                menuBarActiveMenu: null,
                                menuBarActiveSubmenu: null
                              }));
                              setState(next);
                            }}
                            className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                          >
                            {entry.label}
                          </button>
                        );
                      }
                      if ('action' in entry) {
                        return (
                          <button
                            key={entry.label}
                            type="button"
                            onClick={() => handleScraperAction(entry.action)}
                            className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                          >
                            {entry.label}
                          </button>
                        );
                      }
                      return (
                        <div key={entry.label} className="relative group/menu">
                            <button
                              type="button"
                              onClick={() =>
                                updateState((current) => ({
                                  ...current,
                                  menuBarActiveSubmenu:
                                    current.menuBarActiveSubmenu ===
                                    `${item.label}:${entry.label}`
                                      ? null
                                      : `${item.label}:${entry.label}`
                                })).then(setState)
                              }
                              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors flex items-center justify-between"
                            >
                              <span>{entry.label}</span>
                              <span className="text-slate-500">›</span>
                            </button>
                          <div
                            className={`absolute left-full top-0 -ml-px w-44 bg-slate-900 border border-slate-700 rounded shadow-2xl transition-opacity ${
                              state.menuBarActiveSubmenu ===
                              `${item.label}:${entry.label}`
                                ? 'opacity-100 pointer-events-auto'
                                : 'opacity-0 pointer-events-none'
                            }`}
                          >
                            <div className="py-1">
                              {entry.items.map((subItem) => {
                                if (typeof subItem === 'string') {
                                  return (
                                    <button
                                      key={subItem}
                                      type="button"
                                      className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                                    >
                                      {subItem}
                                    </button>
                                  );
                                }
                                if ('toolId' in subItem) {
                                  return (
                                    <button
                                      key={subItem.label}
                                      type="button"
                                      onClick={async () => {
                                        await openTool(subItem.toolId);
                                        const next = await updateState((current) => ({
                                          ...current,
                                          menuBarActiveMenu: null,
                                          menuBarActiveSubmenu: null
                                        }));
                                        setState(next);
                                      }}
                                      className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                                    >
                                      {subItem.label}
                                    </button>
                                  );
                                }
                                if ('scraperId' in subItem) {
                                  return (
                                    <button
                                      key={subItem.label}
                                      type="button"
                                      onClick={async () => {
                                        await openScraperRunner(subItem.scraperId);
                                        const next = await updateState((current) => ({
                                          ...current,
                                          menuBarActiveMenu: null,
                                          menuBarActiveSubmenu: null
                                        }));
                                        setState(next);
                                      }}
                                      className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                                    >
                                      {subItem.label}
                                    </button>
                                  );
                                }
                                if ('action' in subItem) {
                                  return (
                                    <button
                                      key={subItem.label}
                                      type="button"
                                      onClick={() => handleScraperAction(subItem.action)}
                                      className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                                    >
                                      {subItem.label}
                                    </button>
                                  );
                                }
                                return null;
                              })}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : null}
    <div
      className="xcalibr-app-container pointer-events-auto font-sans text-slate-200 z-[70]"
      style={{
        fontFamily: "'Inter', ui-sans-serif, system-ui, -apple-system",
        top: `${panelTop}px`
      }}
    >
      <button
        type="button"
        onPointerDown={handleTabPointerDown}
        style={{ touchAction: 'none', transform: `translateY(${tabTranslateY}px)` }}
        className={`z-[80] bg-slate-800 text-white flex items-center justify-center rounded-l-lg shadow-lg hover:bg-slate-700 transition-colors border-l border-t border-b border-slate-600 cursor-pointer ${
          isAnchoredEffective ? 'w-7 h-8' : 'w-8 h-12'
        }`}
      >
        <FontAwesomeIcon
          icon={state.isOpen ? faChevronRight : faChevronLeft}
          className={iconSizeClass}
        />
      </button>

      <div
        className={`bg-slate-900 h-full shadow-2xl transition-all duration-300 ease-in-out border-l border-slate-700 flex flex-col overflow-hidden rounded-l-md ${
          state.isOpen ? 'opacity-100' : 'opacity-0'
        }`}
        style={{
          width: panelWidth,
          borderTopLeftRadius: isAnchoredEffective ? 0 : undefined,
          borderBottomLeftRadius: isAnchoredEffective ? 0 : undefined
        }}
      >
        <div
          className={`border-b border-slate-800 flex justify-between items-center bg-slate-900 sticky top-0 z-10 ${
            isAnchoredEffective ? 'px-2' : 'p-3'
          }`}
          style={isAnchoredEffective ? { height: menuBarHeight } : undefined}
        >
          <div className="flex items-center gap-2 overflow-hidden">
            <div className="w-6 h-6 rounded bg-blue-600 flex items-center justify-center shrink-0">
              <FontAwesomeIcon
                icon={faBolt}
                className={`${iconSizeClass} text-white`}
              />
            </div>
            <span
              className={`font-bold text-slate-200 text-[11px] whitespace-nowrap transition-opacity duration-200 ${
                state.isOpen ? 'opacity-100 delay-150' : 'opacity-0'
              }`}
            >
              {isAnchoredEffective ? 'Quick Bar' : 'XCalibr - Quickbar'}
            </span>
          </div>
          <button
            type="button"
            onClick={toggleWide}
            className="text-slate-400 hover:text-white transition-colors shrink-0"
            title={state.isWide ? 'Compress Width' : 'Expand Width'}
          >
            <FontAwesomeIcon
              icon={state.isWide ? faCompress : faExpand}
              className={iconSizeClass}
            />
          </button>
        </div>

        <div className="p-2 border-b border-slate-800">
          <label className="flex items-center gap-2 text-[11px] text-slate-400 mb-2">
            <input
              type="checkbox"
              checked={state.showMenuBar}
              onChange={(event) => updateMenuBar(event.target.checked)}
              className="h-3 w-3 rounded border border-slate-700 bg-slate-800 text-blue-500 focus:ring-0 focus:outline-none"
            />
            <span>Show Menu Bar</span>
          </label>
          <div className="text-[11px] text-slate-500 px-1 py-1.5">
            Hit cmd+shift+p to search.
          </div>
        </div>

        <div className="px-2 pb-1 pt-2">
          <div className="relative">
            <FontAwesomeIcon
              icon={faSearch}
              className={`absolute left-2 top-1/2 -translate-y-1/2 text-slate-500 ${iconSizeClass}`}
            />
            <input
              type="text"
              value={quickBarSearch}
              onChange={(event) => setQuickBarSearch(event.target.value)}
              className="w-full rounded bg-slate-800 text-slate-300 text-xs pl-7 pr-2 py-1.5 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors placeholder-slate-500"
              placeholder="Search favorites..."
            />
          </div>
          <div className="flex items-center justify-between text-[10px] text-slate-500 mt-2 px-1">
            <span>
              {filteredQuickBarTools.length === 0
                ? '0 results'
                : `${filteredQuickBarTools.length} results`}
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setQuickBarPage((prev) => Math.max(1, prev - 1))}
                disabled={quickBarPage === 1}
                className="rounded px-2 py-1 border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors disabled:opacity-50"
              >
                Prev
              </button>
              <div className="flex items-center gap-1">
                {Array.from({ length: quickBarTotalPages }, (_, index) => {
                  const page = index + 1;
                  const isActive = page === quickBarPage;
                  return (
                    <button
                      key={page}
                      type="button"
                      data-quickbar-page-target={page}
                      onClick={() => setQuickBarPage(page)}
                      onPointerEnter={() => handleQuickBarPageHover(page)}
                      onPointerOver={() => handleQuickBarPageHover(page)}
                      onPointerLeave={clearQuickBarPageHover}
                      onPointerOut={clearQuickBarPageHover}
                      className={`h-6 w-6 rounded border text-[10px] transition-colors ${
                        isActive
                          ? 'border-blue-500/50 text-blue-200 bg-blue-500/10'
                          : 'border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500'
                      }`}
                    >
                      {page}
                    </button>
                  );
                })}
              </div>
              <span className="text-slate-500">
                {quickBarPage} / {quickBarTotalPages}
              </span>
              <button
                type="button"
                onClick={() =>
                  setQuickBarPage((prev) =>
                    Math.min(quickBarTotalPages, prev + 1)
                  )
                }
                disabled={quickBarPage === quickBarTotalPages}
                className="rounded px-2 py-1 border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </div>
        </div>
        <div
          ref={quickBarListRef}
          className={`flex-1 overflow-y-auto no-scrollbar p-1 space-y-1 ${
            quickBarDragId ? 'select-none cursor-grabbing' : ''
          }`}
        >
          {quickBarTools.length === 0 ? (
            <div className="px-3 py-4 text-[11px] text-slate-500">
              No favorites yet. Open a tool and press + to pin it here.
            </div>
          ) : filteredQuickBarTools.length === 0 ? (
            <div className="px-3 py-4 text-[11px] text-slate-500">
              No matches found.
            </div>
          ) : (
            <>
              {pagedQuickBarTools.map((item, index) => {
                const isDragging = quickBarDragId === item.id;
                const showDropIndicator =
                  quickBarDragId &&
                  quickBarDragOverPage === quickBarPage &&
                  quickBarDragOverIndex === index;
                return (
                  <React.Fragment key={item.id}>
                    <button
                      type="button"
                      data-quickbar-id={item.id}
                      data-quickbar-index={index}
                      data-quickbar-page={quickBarPage}
                      onPointerDown={(event) => {
                        if (!quickBarDragEnabled) return;
                        event.preventDefault();
                        setQuickBarDragId(item.id);
                        quickBarDragIdRef.current = item.id;
                        quickBarDragStartRef.current = {
                          x: event.clientX,
                          y: event.clientY
                        };
                        quickBarDidDragRef.current = false;
                        setQuickBarDragOver(quickBarPage, index);
                        const handleMove = (moveEvent: PointerEvent) => {
                          const dragId =
                            quickBarDragIdRef.current ?? quickBarDragId;
                          if (!dragId || !quickBarDragEnabled) return;
                          const start = quickBarDragStartRef.current;
                          if (start && !quickBarDidDragRef.current) {
                            const deltaX = moveEvent.clientX - start.x;
                            const deltaY = moveEvent.clientY - start.y;
                            const distance = Math.hypot(deltaX, deltaY);
                            if (distance > 6) {
                              quickBarDidDragRef.current = true;
                            }
                          }
                          const listEl = quickBarListRef.current;
                          let handled = false;
                          if (listEl) {
                            const rect = listEl.getBoundingClientRect();
                            const delta = getAutoScrollDelta({
                              clientY: moveEvent.clientY,
                              rectTop: rect.top,
                              rectBottom: rect.bottom,
                              threshold: 32,
                              speed: 8
                            });
                            if (delta !== 0) {
                              listEl.scrollTop += delta;
                            }
                          }
                          const path =
                            typeof moveEvent.composedPath === 'function'
                              ? moveEvent.composedPath()
                              : [];
                          const pathMatch = path.find(
                            (entry) =>
                              entry instanceof HTMLElement &&
                              entry.dataset?.quickbarIndex
                          ) as HTMLElement | undefined;
                          const targetMatch =
                            moveEvent.target instanceof HTMLElement
                              ? (moveEvent.target.closest(
                                  '[data-quickbar-index]'
                                ) as HTMLElement | null)
                              : null;
                          const pointMatch = document
                            .elementFromPoint(moveEvent.clientX, moveEvent.clientY)
                            ?.closest('[data-quickbar-index]') as HTMLElement | null;
                          const itemEl = pathMatch ?? targetMatch ?? pointMatch ?? undefined;
                          if (itemEl) {
                            const nextIndex = Number(itemEl.dataset.quickbarIndex);
                            const nextPage = Number(itemEl.dataset.quickbarPage);
                            if (!Number.isNaN(nextIndex) && !Number.isNaN(nextPage)) {
                              handled = true;
                              if (
                                quickBarDragOverPageRef.current !== nextPage ||
                                quickBarDragOverIndexRef.current !== nextIndex
                              ) {
                                setQuickBarDragOver(nextPage, nextIndex);
                              }
                            }
                          }
                          if (!handled && listEl) {
                            const items = listEl.querySelectorAll<HTMLElement>(
                              '[data-quickbar-index]'
                            );
                            const lastItem = items[items.length - 1];
                            if (lastItem) {
                              const lastRect = lastItem.getBoundingClientRect();
                              if (moveEvent.clientY > lastRect.bottom) {
                                const endIndex = pagedQuickBarToolsRef.current;
                                if (
                                  quickBarDragOverPageRef.current !==
                                    quickBarPageRef.current ||
                                  quickBarDragOverIndexRef.current !== endIndex
                                ) {
                                  setQuickBarDragOver(
                                    quickBarPageRef.current,
                                    endIndex
                                  );
                                }
                              }
                            }
                          }
                        };
                        const handleUp = async (upEvent: PointerEvent) => {
                          window.removeEventListener('pointermove', handleMove);
                          window.removeEventListener('pointerup', handleUp);
                          const dragId =
                            quickBarDragIdRef.current ?? quickBarDragId;
                          if (!dragId) {
                            clearQuickBarDragState();
                            return;
                          }
                          if (!quickBarDidDragRef.current) {
                            clearQuickBarDragState();
                            openTool(dragId);
                            return;
                          }
                          const fromIndex = state.quickBarToolIds.indexOf(dragId);
                          const resolveTarget = () => {
                            const targetEl =
                              upEvent.target instanceof HTMLElement
                                ? (upEvent.target.closest(
                                    '[data-quickbar-index]'
                                  ) as HTMLElement | null)
                                : null;
                            const pointEl = document
                              .elementFromPoint(upEvent.clientX, upEvent.clientY)
                              ?.closest('[data-quickbar-index]') as HTMLElement | null;
                            const element = targetEl ?? pointEl;
                            if (!element) return null;
                            const nextIndex = Number(element.dataset.quickbarIndex);
                            const nextPage = Number(element.dataset.quickbarPage);
                            if (Number.isNaN(nextIndex) || Number.isNaN(nextPage)) {
                              return null;
                            }
                            return { nextIndex, nextPage };
                          };
                          const resolved = resolveTarget();
                          const targetPage =
                            resolved?.nextPage ??
                            quickBarDragOverPageRef.current ??
                            quickBarPageRef.current;
                          const targetIndex =
                            resolved?.nextIndex ??
                            quickBarDragOverIndexRef.current ??
                            0;
                          const toIndex =
                            (targetPage - 1) * quickBarPageSize + targetIndex;
                          if (fromIndex >= 0 && toIndex >= 0) {
                            await updateQuickBarOrder(fromIndex, toIndex);
                          }
                          clearQuickBarDragState();
                        };
                        window.addEventListener('pointermove', handleMove);
                        window.addEventListener('pointerup', handleUp, { once: true });
                      }}
                      className={`relative w-full flex items-center gap-3 p-2 rounded hover:bg-slate-800 transition-all text-left group ${
                        isDragging
                          ? 'opacity-40 pointer-events-none'
                          : 'transition-transform duration-150 ease-out will-change-transform'
                      }`}
                    >
                      <span
                        aria-hidden="true"
                        className={`pointer-events-none absolute inset-0 rounded border border-blue-500/40 bg-blue-500/5 transition-opacity duration-150 ${
                          showDropIndicator ? 'opacity-100' : 'opacity-0'
                        }`}
                      />
                      <div
                        className={`w-6 h-6 rounded bg-slate-800 border border-slate-700 text-slate-400 transition-colors shrink-0 ${item.hover}`}
                      >
                        <div className="w-full h-full flex items-center justify-center">
                          <FontAwesomeIcon icon={item.icon} className={iconSizeClass} />
                        </div>
                      </div>
                      <div className="flex-1 overflow-hidden">
                        <div className="text-slate-300 text-xs font-medium whitespace-nowrap">
                          {item.title}
                        </div>
                        <div className="text-slate-500 text-[10px] whitespace-nowrap">
                          {item.subtitle}
                        </div>
                      </div>
                      {state.isWide ? (
                        <span
                          className={`text-[7px] uppercase tracking-[0.2em] px-2 py-1 rounded-full border ${categoryBadge(item.category)}`}
                        >
                          {item.category}
                        </span>
                      ) : null}
                    </button>
                  </React.Fragment>
                );
              })}
              {quickBarDragId &&
              quickBarDragOverPage === quickBarPage &&
              quickBarDragOverIndex === pagedQuickBarTools.length ? (
                <div className="h-12 rounded border border-dashed border-blue-500/40 bg-blue-500/5" />
              ) : null}
            </>
          )}
        </div>

        <div className="p-2 border-t border-slate-800 bg-slate-900 mt-auto">
          <button
            type="button"
            className="w-full py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-400 transition-colors flex justify-center items-center gap-2"
          >
            <FontAwesomeIcon icon={faGear} className={iconSizeClass} />
            <span>Settings</span>
          </button>
        </div>
      </div>
    </div>
    <div className="fixed bottom-3 right-3 flex gap-2 z-[80]">
      {Object.entries(state.toolWindows)
        .filter(([, toolState]) => toolState.isOpen && toolState.isMinimized)
        .map(([toolId]) => {
          const entry = getToolEntry(toolId);
          if (!entry) return null;
          return (
            <button
              key={toolId}
              type="button"
              onClick={() => restoreTool(toolId)}
              className="px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs text-slate-200 shadow-lg hover:bg-slate-800 transition-colors"
            >
              {entry.title}
            </button>
          );
        })}
    </div>
    {Object.entries(state.toolWindows)
      .filter(([, toolState]) => toolState.isOpen && !toolState.isMinimized)
      .map(([toolId, toolState]) => {
        const entry = getToolEntry(toolId);
        if (!entry) return null;
        const isPinned = state.quickBarToolIds.includes(toolId);
        return (
          <div
            key={toolId}
            className="fixed z-[80] bg-slate-900 border border-slate-700 rounded-lg shadow-2xl w-72"
            style={{ left: toolState.x, top: toolState.y }}
          >
            <div
              className="flex items-center justify-between px-3 py-2 border-b border-slate-800 bg-slate-900 cursor-move"
              style={{ touchAction: 'none' }}
              onPointerDown={(event) => {
                if (
                  event.target instanceof HTMLElement &&
                  event.target.closest('button')
                ) {
                  return;
                }
                event.preventDefault();
                const windowEl = event.currentTarget.parentElement as HTMLElement | null;
                if (!windowEl) return;
                const rect = windowEl.getBoundingClientRect();
                event.currentTarget.setPointerCapture(event.pointerId);
                toolDragRef.current = {
                  toolId,
                  offsetX: event.clientX - rect.left,
                  offsetY: event.clientY - rect.top,
                  startX: toolState.x,
                  startY: toolState.y,
                  moved: false,
                  windowEl
                };
                const handleMove = (moveEvent: PointerEvent) => {
                  if (!toolDragRef.current?.windowEl) return;
                  toolDragRef.current.moved = true;
                  const nextX = moveEvent.clientX - toolDragRef.current.offsetX;
                  const nextY = moveEvent.clientY - toolDragRef.current.offsetY;
                  toolDragRef.current.windowEl.style.left = `${nextX}px`;
                  toolDragRef.current.windowEl.style.top = `${nextY}px`;
                  toolDragRef.current.startX = nextX;
                  toolDragRef.current.startY = nextY;
                };
                const handleUp = async () => {
                  window.removeEventListener('pointermove', handleMove);
                  window.removeEventListener('pointerup', handleUp);
                  if (toolDragRef.current?.moved) {
                    await updateToolPosition(
                      toolId,
                      toolDragRef.current.startX,
                      toolDragRef.current.startY
                    );
                  }
                  toolDragRef.current = null;
                };
                window.addEventListener('pointermove', handleMove);
                window.addEventListener('pointerup', handleUp, { once: true });
              }}
            >
              <span className="text-xs font-semibold text-slate-200">
                {entry.title}
              </span>
              <div className="flex items-center gap-3 text-slate-400">
                <button
                  type="button"
                  className="hover:text-slate-200 transition-colors text-xs"
                  onClick={() => minimizeTool(toolId)}
                >
                  _
                </button>
                <button
                  type="button"
                  className="hover:text-slate-200 transition-colors text-xs"
                  onClick={() => toggleQuickBarTool(toolId)}
                  title={isPinned ? 'Remove from Quick Bar' : 'Add to Quick Bar'}
                >
                  {isPinned ? '-' : '+'}
                </button>
                <button
                  type="button"
                  className="hover:text-slate-200 transition-colors text-xs"
                  onClick={() => closeTool(toolId)}
                >
                  ×
                </button>
              </div>
            </div>
            <div className="p-3 text-slate-200 text-sm">
              {entry.render(state.toolData[toolId], (next) =>
                updateToolData(toolId, next)
              )}
            </div>
          </div>
        );
      })}
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
