import { useEffect, useMemo, useRef, useState } from 'react';
import { updateState, type XcalibrState } from '../../../shared/state';
import { moveItem } from '../../../shared/array-tools';
import { getAutoScrollDelta } from '../../../shared/drag-tools';
import type { ToolRegistryEntry } from '../toolregistry';
import { QUICK_BAR_PAGE_SIZE } from '../constants';

export type QuickBarHook = {
  quickBarSearch: string;
  setQuickBarSearch: React.Dispatch<React.SetStateAction<string>>;
  quickBarPage: number;
  setQuickBarPage: React.Dispatch<React.SetStateAction<number>>;
  quickBarDragId: string | null;
  quickBarDragOverIndex: number | null;
  quickBarDragOverPage: number | null;
  quickBarTools: ToolRegistryEntry[];
  filteredQuickBarTools: ToolRegistryEntry[];
  pagedQuickBarTools: ToolRegistryEntry[];
  quickBarTotalPages: number;
  quickBarDragEnabled: boolean;
  quickBarListRef: React.RefObject<HTMLDivElement>;
  handleQuickBarPointerDown: (
    event: React.PointerEvent,
    item: ToolRegistryEntry,
    index: number,
    openTool: (toolId: string) => Promise<void>
  ) => void;
  handleQuickBarPageHover: (page: number) => void;
  clearQuickBarPageHover: () => void;
};

export const useQuickBar = (
  state: XcalibrState,
  setState: React.Dispatch<React.SetStateAction<XcalibrState>>,
  toolRegistry: ToolRegistryEntry[]
): QuickBarHook => {
  const [quickBarSearch, setQuickBarSearch] = useState('');
  const [quickBarPage, setQuickBarPage] = useState(1);
  const [quickBarDragId, setQuickBarDragId] = useState<string | null>(null);
  const [quickBarDragOverIndex, setQuickBarDragOverIndex] = useState<number | null>(null);
  const [quickBarDragOverPage, setQuickBarDragOverPage] = useState<number | null>(null);

  const quickBarDragIdRef = useRef<string | null>(null);
  const quickBarDragStartRef = useRef<{ x: number; y: number } | null>(null);
  const quickBarDidDragRef = useRef(false);
  const quickBarPageHoverRef = useRef<number | null>(null);
  const quickBarListRef = useRef<HTMLDivElement | null>(null);
  const quickBarPageRef = useRef(quickBarPage);
  const quickBarDragOverIndexRef = useRef<number | null>(quickBarDragOverIndex);
  const quickBarDragOverPageRef = useRef<number | null>(quickBarDragOverPage);
  const pagedQuickBarToolsRef = useRef(0);

  const getToolEntry = (toolId: string) =>
    toolRegistry.find((tool) => tool.id === toolId) ?? null;

  const quickBarTools = useMemo(
    () =>
      state.quickBarToolIds
        .map((toolId) => getToolEntry(toolId))
        .filter((entry): entry is ToolRegistryEntry => Boolean(entry)),
    [state.quickBarToolIds, toolRegistry]
  );

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
    Math.ceil(filteredQuickBarTools.length / QUICK_BAR_PAGE_SIZE)
  );
  const quickBarDragEnabled = quickBarSearch.trim().length === 0;

  const pagedQuickBarTools = useMemo(() => {
    const start = (quickBarPage - 1) * QUICK_BAR_PAGE_SIZE;
    return filteredQuickBarTools.slice(start, start + QUICK_BAR_PAGE_SIZE);
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

  const updateQuickBarOrder = async (fromIndex: number, toIndex: number) => {
    const next = await updateState((current) => ({
      ...current,
      quickBarToolIds: moveItem(current.quickBarToolIds, fromIndex, toIndex)
    }));
    setState(next);
  };

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

  const handleQuickBarPointerDown = (
    event: React.PointerEvent,
    item: ToolRegistryEntry,
    index: number,
    openTool: (toolId: string) => Promise<void>
  ) => {
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
      const dragId = quickBarDragIdRef.current ?? quickBarDragId;
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
      const dragId = quickBarDragIdRef.current ?? quickBarDragId;
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
        (targetPage - 1) * QUICK_BAR_PAGE_SIZE + targetIndex;
      if (fromIndex >= 0 && toIndex >= 0) {
        await updateQuickBarOrder(fromIndex, toIndex);
      }
      clearQuickBarDragState();
    };

    window.addEventListener('pointermove', handleMove);
    window.addEventListener('pointerup', handleUp, { once: true });
  };

  return {
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
  };
};
