import { useEffect, useMemo, useRef, useState } from 'react';
import { DEFAULT_STATE, getState, subscribeState, updateState, type XcalibrState } from '../../../shared/state';
import { baseMenuBarItems, type MenuBarItem } from '../menu';
import { buildToolRegistry, TOOL_DEFAULT_POSITION, type ToolRegistryEntry } from '../toolregistry';
import { parseCookieString } from '../../../shared/web-tools';
import type { RequestLogData, DebuggerData, CookieManagerData } from '../Tools/tool-types';
import { MENU_BAR_HEIGHT } from '../constants';

export type AppStateHook = {
  state: XcalibrState;
  setState: React.Dispatch<React.SetStateAction<XcalibrState>>;
  menuItems: MenuBarItem[];
  toolRegistry: ToolRegistryEntry[];
  getToolEntry: (toolId: string) => ToolRegistryEntry | null;
  toggleOpen: () => Promise<void>;
  toggleWide: () => Promise<void>;
  updateMenuBar: (value: boolean) => Promise<void>;
  openTool: (toolId: string) => Promise<void>;
  closeTool: (toolId: string) => Promise<void>;
  minimizeTool: (toolId: string) => Promise<void>;
  restoreTool: (toolId: string) => Promise<void>;
  updateToolPosition: (toolId: string, x: number, y: number) => Promise<void>;
  updateToolData: (toolId: string, data: unknown) => Promise<void>;
  toggleQuickBarTool: (toolId: string) => Promise<void>;
  refreshStorageExplorer: () => Promise<void>;
  refreshCookies: () => Promise<void>;
  requestLogSeenRef: React.MutableRefObject<Set<string>>;
  menuBarRef: React.RefObject<HTMLDivElement>;
};

export const useAppState = (): AppStateHook => {
  const [state, setState] = useState(DEFAULT_STATE);
  const menuBarRef = useRef<HTMLDivElement | null>(null);
  const requestLogSeenRef = useRef<Set<string>>(new Set());

  // Initialize state from storage
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

  // Request log observer
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
            startTime: entry.startTime,
            fetchStart: entry.fetchStart,
            domainLookupStart: entry.domainLookupStart,
            domainLookupEnd: entry.domainLookupEnd,
            connectStart: entry.connectStart,
            connectEnd: entry.connectEnd,
            secureConnectionStart: entry.secureConnectionStart,
            requestStart: entry.requestStart,
            responseStart: entry.responseStart,
            responseEnd: entry.responseEnd,
            encodedBodySize: entry.encodedBodySize,
            decodedBodySize: entry.decodedBodySize,
            nextHopProtocol: entry.nextHopProtocol,
            responseStatus: (entry as PerformanceResourceTiming & { responseStatus?: number }).responseStatus
          });
        });
        return {
          ...current,
          toolData: {
            ...current.toolData,
            requestLog: {
              ...(current.toolData.requestLog as RequestLogData | undefined),
              entries: nextEntries.slice(0, 200)
            }
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

  // Debugger observer
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

  // Clear request log seen when entries are cleared
  useEffect(() => {
    const entries =
      (state.toolData.requestLog as RequestLogData | undefined)?.entries ?? [];
    if (entries.length === 0) {
      requestLogSeenRef.current.clear();
    }
  }, [state.toolData.requestLog]);

  // Menu bar state management
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

  // Menu bar visibility effects
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
    if (state.tabOffsetY <= MENU_BAR_HEIGHT) {
      updateState((current) => ({
        ...current,
        tabOffsetY: 0,
        isAnchored: true
      })).then(setState);
    }
  }, [MENU_BAR_HEIGHT, state.showMenuBar, state.tabOffsetY, state.isAnchored]);

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
    []
  );

  const getToolEntry = (toolId: string) =>
    toolRegistry.find((tool) => tool.id === toolId) ?? null;

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

  return {
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
    refreshStorageExplorer,
    refreshCookies,
    requestLogSeenRef,
    menuBarRef
  };
};
