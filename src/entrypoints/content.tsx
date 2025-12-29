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

const App = () => {
  const [state, setState] = useState(DEFAULT_STATE);
  const [dragOffsetY, setDragOffsetY] = useState<number | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const dragStateRef = useRef({
    startY: 0,
    startOffset: 0,
    moved: false,
    lastOffset: 0
  });
  const iconSizeClass = 'w-3 h-3';
  const menuHeight = 550;
  const tabHeight = 48;

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

  const clampTabOffset = (value: number) => {
    const maxOffset = Math.max(0, window.innerHeight - tabHeight);
    return Math.min(Math.max(value, 0), maxOffset);
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
    const startOffset = clampTabOffset(state.tabOffsetY);
    dragStateRef.current = {
      startY: event.clientY,
      startOffset,
      moved: false,
      lastOffset: startOffset
    };
    setDragOffsetY(startOffset);
    setIsDragging(true);

    const handleMove = (moveEvent: PointerEvent) => {
      const delta = moveEvent.clientY - dragStateRef.current.startY;
      if (Math.abs(delta) > 3) {
        dragStateRef.current.moved = true;
      }
      const nextOffset = clampTabOffset(dragStateRef.current.startOffset + delta);
      dragStateRef.current.lastOffset = nextOffset;
      setDragOffsetY(nextOffset);
    };

    const handleUp = async () => {
      window.removeEventListener('pointermove', handleMove);
      window.removeEventListener('pointerup', handleUp);

      const { moved, lastOffset } = dragStateRef.current;
      setIsDragging(false);
      setDragOffsetY(null);

      if (moved) {
        await updateState((current) => ({
          ...current,
          tabOffsetY: clampTabOffset(lastOffset)
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

  if (!state.isVisible) {
    return null;
  }

  const effectiveOffset = clampTabOffset(
    isDragging && dragOffsetY !== null ? dragOffsetY : state.tabOffsetY
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
  const maxPanelTop = Math.max(0, viewportHeight - menuHeight);
  const panelTop = Math.min(Math.max(effectiveOffset - anchorOffset, 0), maxPanelTop);
  const tabTranslateY = Math.min(
    Math.max(effectiveOffset - panelTop, 0),
    menuHeight - tabHeight
  );

  return (
    <div
      className="xcalibr-app-container pointer-events-auto font-sans text-slate-200"
      style={{
        fontFamily: "'Inter', ui-sans-serif, system-ui, -apple-system",
        top: `${panelTop}px`
      }}
    >
      <button
        type="button"
        onPointerDown={handleTabPointerDown}
        style={{ touchAction: 'none', transform: `translateY(${tabTranslateY}px)` }}
        className="z-50 bg-slate-800 text-white w-8 h-12 flex items-center justify-center rounded-l-lg shadow-lg hover:bg-slate-700 transition-colors border-l border-t border-b border-slate-600 cursor-pointer"
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
        style={{ width: panelWidth }}
      >
        <div className="p-3 border-b border-slate-800 flex justify-between items-center bg-slate-900 sticky top-0 z-10">
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
              DevTools
            </span>
          </div>
          <button
            type="button"
            onClick={toggleWide}
            className="text-slate-400 hover:text-white transition-colors"
            title={state.isWide ? 'Compress Width' : 'Expand Width'}
          >
            <FontAwesomeIcon
              icon={state.isWide ? faCompress : faExpand}
              className={iconSizeClass}
            />
          </button>
        </div>

        <div className="p-2 border-b border-slate-800">
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
