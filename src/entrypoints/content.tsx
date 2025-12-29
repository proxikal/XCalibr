import React, { useEffect, useMemo, useRef, useState } from 'react';
import ReactDOM from 'react-dom/client';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faBolt,
  faChevronLeft,
  faChevronRight,
  faCode,
  faCompress,
  faExpand,
  faEyeDropper,
  faGear,
  faSearch
} from '@fortawesome/free-solid-svg-icons';
import { defineContentScript } from 'wxt/sandbox';
import tailwindStyles from '../styles/index.css?inline';
import { DEFAULT_STATE, getState, subscribeState, updateState } from '../shared/state';

const ROOT_ID = 'xcalibr-root';

const menuBarItems = [
  {
    label: 'File',
    items: ['Help', 'Settings']
  },
  {
    label: 'Web Dev',
    items: [
      { label: 'Code Injector', toolId: 'codeInjector' },
      'Debugger',
      {
        label: 'Front End',
        items: [{ label: 'Color Picker', toolId: 'colorPicker' }]
      }
    ]
  },
  {
    label: 'Database',
    items: [
      {
        label: 'JSON',
        items: ['Minify', 'Prettify', 'Format']
      }
    ]
  },
  {
    label: 'CyberSec',
    items: [
      {
        label: 'Recon',
        items: ['Headers Inspector', 'Tech Fingerprint', 'Robots.txt Viewer']
      },
      {
        label: 'Testing',
        items: ['Form Fuzzer', 'URL Encoder/Decoder', 'Param Analyzer']
      },
      {
        label: 'Content',
        items: ['Link Extractor', 'DOM Snapshot', 'Asset Mapper']
      },
      {
        label: 'Network',
        items: ['Request Log', 'Payload Replay', 'CORS Check']
      }
    ]
  }
];

const TOOL_DEFAULT_POSITION = { x: 80, y: 140 };

type ToolRegistryEntry = {
  id: string;
  title: string;
  subtitle: string;
  category: string;
  icon: typeof faBolt;
  hover: string;
  render: (
    data: unknown,
    onChange: (next: unknown) => void
  ) => React.ReactNode;
};

const hexToRgb = (hex: string) => {
  const normalized = hex.replace('#', '').trim();
  if (![3, 6].includes(normalized.length)) return null;
  const expanded =
    normalized.length === 3
      ? normalized
          .split('')
          .map((char) => `${char}${char}`)
          .join('')
      : normalized;
  const int = Number.parseInt(expanded, 16);
  if (Number.isNaN(int)) return null;
  return {
    r: (int >> 16) & 255,
    g: (int >> 8) & 255,
    b: int & 255
  };
};

const ColorPickerTool = ({
  data,
  onChange
}: {
  data: { color?: string } | undefined;
  onChange: (next: { color: string }) => void;
}) => {
  const color = data?.color ?? '#2563eb';
  const rgb = hexToRgb(color);
  const rgbLabel = rgb ? `rgb(${rgb.r}, ${rgb.g}, ${rgb.b})` : 'Invalid HEX';
  const rgbaLabel = rgb
    ? `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 1)`
    : 'Invalid HEX';
  const pickFromPage = async () => {
    if (!('EyeDropper' in window)) return;
    try {
      const dropper = new (window as Window & { EyeDropper: typeof EyeDropper })
        .EyeDropper();
      const result = await dropper.open();
      onChange({ color: result.sRGBHex });
    } catch {
      // User cancelled the eye dropper.
    }
  };
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <input
          type="color"
          value={color}
          onChange={(event) => onChange({ color: event.target.value })}
          className="h-10 w-10 rounded border border-slate-700 bg-slate-800"
        />
        <div className="text-xs text-slate-400">
          Pick a color to copy its hex value.
        </div>
      </div>
      <button
        type="button"
        className="w-full rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
        onClick={pickFromPage}
        disabled={!('EyeDropper' in window)}
      >
        {('EyeDropper' in window) ? 'Pick from page' : 'EyeDropper not supported'}
      </button>
      <div className="flex items-center gap-2">
        <input
          type="text"
          value={color}
          onChange={(event) => onChange({ color: event.target.value })}
          className="flex-1 rounded bg-slate-800 text-slate-200 text-xs px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
        />
        <button
          type="button"
          className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
          onClick={() => navigator.clipboard.writeText(color)}
        >
          Copy
        </button>
      </div>
      <div className="space-y-1 text-[11px] text-slate-400">
        <div>HEX: <span className="text-slate-200">{color}</span></div>
        <div>RGB: <span className="text-slate-200">{rgbLabel}</span></div>
        <div>RGBA: <span className="text-slate-200">{rgbaLabel}</span></div>
      </div>
    </div>
  );
};

type CodeInjectorData = {
  mode?: 'css' | 'js';
  scope?: 'current' | 'all';
  code?: string;
};

const CodeInjectorTool = ({
  data,
  onChange,
  onInject
}: {
  data: CodeInjectorData | undefined;
  onChange: (next: CodeInjectorData) => void;
  onInject: (payload: Required<CodeInjectorData>) => Promise<void>;
}) => {
  const [isInjecting, setIsInjecting] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const mode = data?.mode ?? 'css';
  const scope = data?.scope ?? 'current';
  const code = data?.code ?? '';
  const update = (next: Partial<CodeInjectorData>) =>
    onChange({ mode, scope, code, ...next });

  const handleInject = async () => {
    if (!code.trim()) {
      setStatus('Add some code to inject.');
      return;
    }
    setIsInjecting(true);
    setStatus(null);
    try {
      await onInject({ mode, scope, code });
      setStatus('Injection sent.');
    } catch {
      setStatus('Injection failed. Check permissions.');
    } finally {
      setIsInjecting(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
          Injection Type
        </div>
        <div className="flex gap-2">
          {(['css', 'js'] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => update({ mode: value })}
              className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
                mode === value
                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {value.toUpperCase()}
            </button>
          ))}
        </div>
        {mode === 'js' ? (
          <div className="text-[11px] text-amber-300">
            Only inject JavaScript you fully understand and trust.
          </div>
        ) : null}
      </div>

      <div className="space-y-2">
        <div className="text-[11px] uppercase tracking-[0.2em] text-slate-500">
          Target
        </div>
        <div className="flex gap-2">
          {([
            { value: 'current', label: 'Current Tab' },
            { value: 'all', label: 'All Tabs' }
          ] as const).map((entry) => (
            <button
              key={entry.value}
              type="button"
              onClick={() => update({ scope: entry.value })}
              className={`flex-1 rounded px-2 py-1 text-[11px] border transition-colors ${
                scope === entry.value
                  ? 'bg-blue-500/10 border-blue-500/50 text-blue-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {entry.label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-2">
        <textarea
          value={code}
          onChange={(event) => update({ code: event.target.value })}
          placeholder={mode === 'css' ? '/* Paste CSS here */' : '// Paste JS here'}
          rows={6}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors placeholder:text-slate-500 font-mono"
        />
        {status ? (
          <div className="text-[11px] text-slate-400">{status}</div>
        ) : null}
      </div>

      <button
        type="button"
        onClick={handleInject}
        disabled={isInjecting}
        className="w-full rounded bg-slate-800 px-2 py-1.5 text-xs text-slate-200 hover:bg-slate-700 transition-colors disabled:opacity-50"
      >
        {isInjecting ? 'Injecting...' : 'Inject Code'}
      </button>
    </div>
  );
};

const toolRegistry: ToolRegistryEntry[] = [
  {
    id: 'codeInjector',
    title: 'Code Injector',
    subtitle: 'Inject CSS or JS',
    category: 'Web Dev',
    icon: faCode,
    hover: 'group-hover:border-cyan-500 group-hover:text-cyan-400',
    render: (data, onChange) => (
      <CodeInjectorTool
        data={data as CodeInjectorData | undefined}
        onChange={(next) => onChange(next)}
        onInject={async (payload) => {
          await chrome.runtime.sendMessage({
            type: 'xcalibr-inject-code',
            payload
          });
        }}
      />
    )
  },
  {
    id: 'colorPicker',
    title: 'Color Picker',
    subtitle: 'Grab hex/rgb',
    category: 'Front End',
    icon: faEyeDropper,
    hover: 'group-hover:border-blue-500 group-hover:text-blue-400',
    render: (data, onChange) => (
      <ColorPickerTool
        data={data as { color?: string } | undefined}
        onChange={(next) => onChange(next)}
      />
    )
  }
];

const getToolEntry = (toolId: string) =>
  toolRegistry.find((tool) => tool.id === toolId) ?? null;

const App = () => {
  const [state, setState] = useState(DEFAULT_STATE);
  const [dragOffsetY, setDragOffsetY] = useState<number | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [dragAnchored, setDragAnchored] = useState<boolean | null>(null);
  const [spotlightOpen, setSpotlightOpen] = useState(false);
  const [spotlightQuery, setSpotlightQuery] = useState('');
  const menuBarRef = useRef<HTMLDivElement | null>(null);
  const spotlightInputRef = useRef<HTMLInputElement | null>(null);
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

  const searchableTools = useMemo(
    () =>
      toolRegistry.map((tool) => ({
        id: tool.id,
        label: tool.title,
        subtitle: tool.subtitle
      })),
    []
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
      default:
        return 'bg-slate-500/10 text-slate-300 border-slate-500/30';
    }
  };

  const quickBarTools = useMemo(
    () =>
      state.quickBarToolIds
        .map((toolId) => getToolEntry(toolId))
        .filter((entry): entry is ToolRegistryEntry => Boolean(entry)),
    [state.quickBarToolIds]
  );

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

  const handleMenuClick = (label: string) => {
    updateState((current) => ({
      ...current,
      menuBarActiveMenu: current.menuBarActiveMenu === label ? null : label,
      menuBarActiveSubmenu: null
    })).then(setState);
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
            {menuBarItems.map((item) => {
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

        <div className="flex-1 overflow-y-auto no-scrollbar p-1 space-y-1">
          {quickBarTools.length === 0 ? (
            <div className="px-3 py-4 text-[11px] text-slate-500">
              No favorites yet. Open a tool and press + to pin it here.
            </div>
          ) : (
            quickBarTools.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => openTool(item.id)}
                className="w-full flex items-center gap-3 p-2 rounded hover:bg-slate-800 transition-all text-left group"
              >
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
            ))
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
