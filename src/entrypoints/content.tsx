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
  faFont,
  faGear,
  faNetworkWired,
  faRulerCombined,
  faSearch
} from '@fortawesome/free-solid-svg-icons';
import { defineContentScript } from 'wxt/sandbox';
import tailwindStyles from '../styles/index.css?inline';
import { DEFAULT_STATE, getState, subscribeState, updateState } from '../shared/state';

const ROOT_ID = 'xcalibr-root';

const tools = [
  {
    category: 'Essentials',
    items: [
      {
        title: 'Color Picker',
        subtitle: 'Grab hex/rgb',
        icon: faEyeDropper,
        hover: 'group-hover:border-blue-500 group-hover:text-blue-400'
      },
      {
        title: 'JSON Formatter',
        subtitle: 'Validate & View',
        icon: faCode,
        hover: 'group-hover:border-purple-500 group-hover:text-purple-400'
      }
    ]
  },
  {
    category: 'Design',
    items: [
      {
        title: 'Page Ruler',
        subtitle: 'Measure elements',
        icon: faRulerCombined,
        hover: 'group-hover:border-pink-500 group-hover:text-pink-400'
      },
      {
        title: 'Font Info',
        subtitle: 'Inspect typography',
        icon: faFont,
        hover: 'group-hover:border-orange-500 group-hover:text-orange-400'
      }
    ]
  },
  {
    category: 'Network',
    items: [
      {
        title: 'Request Log',
        subtitle: 'Monitor fetch/xhr',
        icon: faNetworkWired,
        hover: 'group-hover:border-green-500 group-hover:text-green-400'
      }
    ]
  }
];

const menuBarItems = [
  {
    label: 'Tools',
    items: ['Example Tool 1', 'Example Tool 2']
  },
  {
    label: 'Web Dev',
    items: ['Debugger']
  },
  {
    label: 'Database',
    items: [
      {
        label: 'JSON',
        items: ['Minify', 'Prettify', 'Format']
      }
    ]
  }
];

const App = () => {
  const [state, setState] = useState(DEFAULT_STATE);
  const [dragOffsetY, setDragOffsetY] = useState<number | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const [dragAnchored, setDragAnchored] = useState<boolean | null>(null);
  const menuBarRef = useRef<HTMLDivElement | null>(null);
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

  const panelWidth = useMemo(() => {
    if (!state.isOpen) return 0;
    return state.isWide ? 300 : 160;
  }, [state.isOpen, state.isWide]);

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

  const updateSearch = async (value: string) => {
    const next = await updateState((current) => ({
      ...current,
      searchQuery: value
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

  useEffect(() => {
    const handleDocumentClick = (event: MouseEvent) => {
      if (!menuBarRef.current) return;
      if (menuBarRef.current.contains(event.target as Node)) return;
      setActiveMenu(null);
    };

    document.addEventListener('mousedown', handleDocumentClick);
    return () => document.removeEventListener('mousedown', handleDocumentClick);
  }, []);

  useEffect(() => {
    if (!state.showMenuBar) {
      setActiveMenu(null);
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
    setActiveMenu((current) => (current === label ? null : label));
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
              const isOpen = activeMenu === item.label;
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
                      return (
                        <div key={entry.label} className="relative group/menu">
                            <button
                              type="button"
                              className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors flex items-center justify-between"
                            >
                              <span>{entry.label}</span>
                              <span className="text-slate-500">›</span>
                            </button>
                          <div className="absolute left-full top-0 ml-1 w-44 bg-slate-900 border border-slate-700 rounded shadow-2xl opacity-0 group-hover/menu:opacity-100 pointer-events-none group-hover/menu:pointer-events-auto transition-opacity">
                            <div className="py-1">
                              {entry.items.map((subItem) => (
                                <button
                                  key={subItem}
                                  type="button"
                                    className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors"
                                  >
                                    {subItem}
                                  </button>
                                ))}
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
              className={`font-bold text-slate-200 text-sm whitespace-nowrap transition-opacity duration-200 ${
                state.isOpen ? 'opacity-100 delay-150' : 'opacity-0'
              }`}
            >
              {isAnchoredEffective ? 'Extension' : 'XCalibr'}
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
          <div className="relative">
            <FontAwesomeIcon
              icon={faSearch}
              className={`absolute left-2 top-1/2 -translate-y-1/2 text-slate-500 ${iconSizeClass}`}
            />
            <input
              type="text"
              placeholder="Find tool..."
              value={state.searchQuery}
              onChange={(event) => updateSearch(event.target.value)}
              className="w-full bg-slate-800 text-slate-300 text-xs rounded pl-7 pr-2 py-1.5 border border-slate-700 focus:outline-none focus:border-blue-500 transition-colors placeholder-slate-500"
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto no-scrollbar p-1 space-y-1">
          {tools.map((group) => (
            <div key={group.category}>
              <div className="px-2 py-1 text-[10px] uppercase tracking-wider text-slate-500 font-semibold mt-2 whitespace-nowrap">
                {group.category}
              </div>
              {group.items.map((item) => (
                <button
                  key={item.title}
                  type="button"
                  className="w-full flex items-center gap-3 p-2 rounded hover:bg-slate-800 transition-all text-left group"
                >
                  <div
                    className={`w-6 h-6 rounded bg-slate-800 border border-slate-700 text-slate-400 transition-colors shrink-0 ${item.hover}`}
                  >
                    <div className="w-full h-full flex items-center justify-center">
                      <FontAwesomeIcon
                        icon={item.icon}
                        className={iconSizeClass}
                      />
                    </div>
                  </div>
                  <div className="overflow-hidden">
                    <div className="text-slate-300 text-xs font-medium whitespace-nowrap">
                      {item.title}
                    </div>
                    <div className="text-slate-500 text-[10px] whitespace-nowrap">
                      {item.subtitle}
                    </div>
                  </div>
                </button>
              ))}
            </div>
          ))}
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
