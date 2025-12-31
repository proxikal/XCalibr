import React from 'react';
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
import type { ToolRegistryEntry } from '../toolregistry';
import { getCategoryBadge, ICON_SIZE_CLASS, MENU_BAR_HEIGHT, QUICK_BAR_PAGE_SIZE } from '../constants';

type QuickBarProps = {
  isOpen: boolean;
  isWide: boolean;
  isAnchored: boolean;
  showMenuBar: boolean;
  panelWidth: number;
  panelTop: number;
  tabTranslateY: number;
  tabHeight: number;
  // Quick bar state
  quickBarSearch: string;
  setQuickBarSearch: (value: string) => void;
  quickBarPage: number;
  setQuickBarPage: (value: number) => void;
  quickBarTools: ToolRegistryEntry[];
  filteredQuickBarTools: ToolRegistryEntry[];
  pagedQuickBarTools: ToolRegistryEntry[];
  quickBarTotalPages: number;
  quickBarDragId: string | null;
  quickBarDragOverIndex: number | null;
  quickBarDragOverPage: number | null;
  quickBarDragEnabled: boolean;
  quickBarListRef: React.RefObject<HTMLDivElement>;
  // Handlers
  onTabPointerDown: (event: React.PointerEvent<HTMLButtonElement>) => void;
  onToggleWide: () => void;
  onUpdateMenuBar: (value: boolean) => void;
  onQuickBarPointerDown: (
    event: React.PointerEvent,
    item: ToolRegistryEntry,
    index: number
  ) => void;
  onPageHover: (page: number) => void;
  onClearPageHover: () => void;
};

export const QuickBar: React.FC<QuickBarProps> = ({
  isOpen,
  isWide,
  isAnchored,
  showMenuBar,
  panelWidth,
  panelTop,
  tabTranslateY,
  tabHeight,
  quickBarSearch,
  setQuickBarSearch,
  quickBarPage,
  setQuickBarPage,
  quickBarTools,
  filteredQuickBarTools,
  pagedQuickBarTools,
  quickBarTotalPages,
  quickBarDragId,
  quickBarDragOverIndex,
  quickBarDragOverPage,
  quickBarDragEnabled,
  quickBarListRef,
  onTabPointerDown,
  onToggleWide,
  onUpdateMenuBar,
  onQuickBarPointerDown,
  onPageHover,
  onClearPageHover
}) => {
  const isAnchoredEffective = showMenuBar && isAnchored;

  return (
    <div
      className="xcalibr-app-container pointer-events-auto font-sans text-slate-200 z-[70]"
      style={{
        fontFamily: "'Inter', ui-sans-serif, system-ui, -apple-system",
        top: `${panelTop}px`
      }}
    >
      <button
        type="button"
        onPointerDown={onTabPointerDown}
        style={{ touchAction: 'none', transform: `translateY(${tabTranslateY}px)` }}
        className={`z-[80] bg-slate-800 text-white flex items-center justify-center rounded-l-lg shadow-lg hover:bg-slate-700 transition-colors border-l border-t border-b border-slate-600 cursor-pointer ${
          isAnchoredEffective ? 'w-7 h-8' : 'w-8 h-12'
        }`}
      >
        <FontAwesomeIcon
          icon={isOpen ? faChevronRight : faChevronLeft}
          className={ICON_SIZE_CLASS}
        />
      </button>

      <div
        className={`bg-slate-900 h-full shadow-2xl transition-all duration-300 ease-in-out border-l border-slate-700 flex flex-col overflow-hidden rounded-l-md ${
          isOpen ? 'opacity-100' : 'opacity-0'
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
          style={isAnchoredEffective ? { height: MENU_BAR_HEIGHT } : undefined}
        >
          <div className="flex items-center gap-2 overflow-hidden">
            <div className="w-6 h-6 rounded bg-blue-600 flex items-center justify-center shrink-0">
              <FontAwesomeIcon icon={faBolt} className={`${ICON_SIZE_CLASS} text-white`} />
            </div>
            <span
              className={`font-bold text-slate-200 text-[11px] whitespace-nowrap transition-opacity duration-200 ${
                isOpen ? 'opacity-100 delay-150' : 'opacity-0'
              }`}
            >
              {isAnchoredEffective ? 'Quick Bar' : 'XCalibr - Quickbar'}
            </span>
          </div>
          <button
            type="button"
            onClick={onToggleWide}
            className="text-slate-400 hover:text-white transition-colors shrink-0"
            title={isWide ? 'Compress Width' : 'Expand Width'}
          >
            <FontAwesomeIcon
              icon={isWide ? faCompress : faExpand}
              className={ICON_SIZE_CLASS}
            />
          </button>
        </div>

        <div className="p-2 border-b border-slate-800">
          <label className="flex items-center gap-2 text-[11px] text-slate-400 mb-2">
            <input
              type="checkbox"
              checked={showMenuBar}
              onChange={(event) => onUpdateMenuBar(event.target.checked)}
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
              className={`absolute left-2 top-1/2 -translate-y-1/2 text-slate-500 ${ICON_SIZE_CLASS}`}
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
                onClick={() => setQuickBarPage(Math.max(1, quickBarPage - 1))}
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
                      onPointerEnter={() => onPageHover(page)}
                      onPointerOver={() => onPageHover(page)}
                      onPointerLeave={onClearPageHover}
                      onPointerOut={onClearPageHover}
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
                onClick={() => setQuickBarPage(Math.min(quickBarTotalPages, quickBarPage + 1))}
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
                      onPointerDown={(event) => onQuickBarPointerDown(event, item, index)}
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
                          <FontAwesomeIcon icon={item.icon} className={ICON_SIZE_CLASS} />
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
                      {isWide ? (
                        <span
                          className={`text-[7px] uppercase tracking-[0.2em] px-2 py-1 rounded-full border ${getCategoryBadge(item.category)}`}
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
            <FontAwesomeIcon icon={faGear} className={ICON_SIZE_CLASS} />
            <span>Settings</span>
          </button>
        </div>
      </div>
    </div>
  );
};
