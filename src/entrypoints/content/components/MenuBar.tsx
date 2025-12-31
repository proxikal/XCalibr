import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faBolt } from '@fortawesome/free-solid-svg-icons';
import type { MenuBarItem, MenuItem } from '../menu';
import type { ToolRegistryEntry } from '../toolregistry';
import { updateState, type XcalibrState } from '../../../shared/state';
import { MENU_ICONS, MENU_BAR_HEIGHT } from '../constants';

type MenuBarProps = {
  menuBarRef: React.RefObject<HTMLDivElement>;
  state: XcalibrState;
  setState: React.Dispatch<React.SetStateAction<XcalibrState>>;
  menuItems: MenuBarItem[];
  getToolEntry: (toolId: string) => ToolRegistryEntry | null;
  onOpenTool: (toolId: string) => Promise<void>;
  onOpenScraperRunner: (scraperId: string) => Promise<void>;
  onOpenScraperBuilder: () => Promise<void>;
};

export const MenuBar: React.FC<MenuBarProps> = ({
  menuBarRef,
  state,
  setState,
  menuItems,
  getToolEntry,
  onOpenTool,
  onOpenScraperRunner,
  onOpenScraperBuilder
}) => {
  const handleMenuClick = (label: string) => {
    updateState((current) => ({
      ...current,
      menuBarActiveMenu: current.menuBarActiveMenu === label ? null : label,
      menuBarActiveSubmenu: null
    })).then(setState);
  };

  const handleScraperAction = async (action: string) => {
    if (action === 'makeScraper') {
      await onOpenScraperBuilder();
      const next = await updateState((current) => ({
        ...current,
        menuBarActiveMenu: null,
        menuBarActiveSubmenu: null
      }));
      setState(next);
    }
  };

  const closeMenus = async () => {
    const next = await updateState((current) => ({
      ...current,
      menuBarActiveMenu: null,
      menuBarActiveSubmenu: null
    }));
    setState(next);
  };

  const renderMenuItem = (
    entry: MenuItem,
    parentLabel: string
  ): React.ReactNode => {
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
      const toolEntry = getToolEntry(entry.toolId);
      return (
        <button
          key={entry.label}
          type="button"
          onClick={async () => {
            await onOpenTool(entry.toolId);
            await closeMenus();
          }}
          className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors flex items-center gap-2"
        >
          {toolEntry?.icon && (
            <FontAwesomeIcon icon={toolEntry.icon} className="w-3 h-3 text-slate-500" />
          )}
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
            await onOpenScraperRunner(entry.scraperId);
            await closeMenus();
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

    // Submenu
    const submenuKey = `${parentLabel}:${entry.label}`;
    const isSubmenuOpen = state.menuBarActiveSubmenu === submenuKey;

    return (
      <div key={entry.label} className="relative group/menu">
        <button
          type="button"
          onClick={() =>
            updateState((current) => ({
              ...current,
              menuBarActiveSubmenu:
                current.menuBarActiveSubmenu === submenuKey ? null : submenuKey
            })).then(setState)
          }
          className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors flex items-center justify-between"
        >
          <span>{entry.label}</span>
          <span className="text-slate-500">›</span>
        </button>
        <div
          className={`absolute left-full top-0 -ml-px w-44 bg-slate-900 border border-slate-700 rounded shadow-2xl transition-opacity ${
            isSubmenuOpen
              ? 'opacity-100 pointer-events-auto'
              : 'opacity-0 pointer-events-none'
          }`}
        >
          <div className="py-1">
            {entry.items.map((subItem) => renderSubmenuItem(subItem))}
          </div>
        </div>
      </div>
    );
  };

  const renderSubmenuItem = (subItem: MenuItem): React.ReactNode => {
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
      const subToolEntry = getToolEntry(subItem.toolId);
      return (
        <button
          key={subItem.label}
          type="button"
          onClick={async () => {
            await onOpenTool(subItem.toolId);
            await closeMenus();
          }}
          className="w-full text-left px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-800 transition-colors flex items-center gap-2"
        >
          {subToolEntry?.icon && (
            <FontAwesomeIcon icon={subToolEntry.icon} className="w-3 h-3 text-slate-500" />
          )}
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
            await onOpenScraperRunner(subItem.scraperId);
            await closeMenus();
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
  };

  return (
    <div
      ref={menuBarRef}
      className="pointer-events-auto fixed top-0 left-0 right-0 z-50 bg-slate-900 border-b border-slate-800 text-slate-200 shadow-lg"
      style={{
        fontFamily: "'Inter', ui-sans-serif, system-ui, -apple-system",
        height: MENU_BAR_HEIGHT
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
            <div key={item.label} className="relative">
              <button
                type="button"
                onClick={() => handleMenuClick(item.label)}
                className="px-2 py-1 text-xs text-slate-300 rounded hover:bg-slate-800 transition-colors flex items-center gap-1.5"
              >
                {MENU_ICONS[item.label] && (
                  <FontAwesomeIcon icon={MENU_ICONS[item.label]} className="w-3 h-3 text-slate-400" />
                )}
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
                  {item.items.map((entry) => renderMenuItem(entry, item.label))}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
