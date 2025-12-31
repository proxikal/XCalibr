import React, { useRef } from 'react';
import type { ToolRegistryEntry } from '../toolregistry';

type ToolWindowProps = {
  toolId: string;
  entry: ToolRegistryEntry;
  toolState: {
    isOpen: boolean;
    isMinimized: boolean;
    x: number;
    y: number;
  };
  toolData: unknown;
  isPinned: boolean;
  onClose: () => void;
  onMinimize: () => void;
  onTogglePin: () => void;
  onUpdatePosition: (x: number, y: number) => void;
  onUpdateData: (data: unknown) => void;
};

export const ToolWindow: React.FC<ToolWindowProps> = ({
  toolId,
  entry,
  toolState,
  toolData,
  isPinned,
  onClose,
  onMinimize,
  onTogglePin,
  onUpdatePosition,
  onUpdateData
}) => {
  const toolDragRef = useRef<{
    toolId: string;
    offsetX: number;
    offsetY: number;
    startX: number;
    startY: number;
    moved: boolean;
    windowEl: HTMLElement | null;
  } | null>(null);

  const handlePointerDown = (event: React.PointerEvent<HTMLDivElement>) => {
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
        onUpdatePosition(
          toolDragRef.current.startX,
          toolDragRef.current.startY
        );
      }
      toolDragRef.current = null;
    };

    window.addEventListener('pointermove', handleMove);
    window.addEventListener('pointerup', handleUp, { once: true });
  };

  return (
    <div
      className={`fixed z-[80] bg-slate-900 border border-slate-700 rounded-lg shadow-2xl ${entry.width ? '' : 'w-72'} ${entry.height ? 'flex flex-col' : ''}`}
      style={{
        left: toolState.x,
        top: toolState.y,
        ...(entry.width ? { width: entry.width } : {}),
        ...(entry.height ? { height: entry.height } : {})
      }}
    >
      <div
        className="flex items-center justify-between px-3 py-2 border-b border-slate-800 bg-slate-900 cursor-move flex-shrink-0 rounded-t-lg"
        style={{ touchAction: 'none' }}
        onPointerDown={handlePointerDown}
      >
        <span className="text-xs font-semibold text-slate-200">
          {entry.title}
        </span>
        <div className="flex items-center gap-3 text-slate-400">
          <button
            type="button"
            className="hover:text-slate-200 transition-colors text-xs"
            onClick={onMinimize}
          >
            _
          </button>
          <button
            type="button"
            className="hover:text-slate-200 transition-colors text-xs"
            onClick={onTogglePin}
            title={isPinned ? 'Remove from Quick Bar' : 'Add to Quick Bar'}
          >
            {isPinned ? '-' : '+'}
          </button>
          <button
            type="button"
            className="hover:text-slate-200 transition-colors text-xs"
            onClick={onClose}
          >
            ×
          </button>
        </div>
      </div>
      <div className={`p-3 text-slate-200 text-sm ${entry.height ? 'flex-1 overflow-hidden min-h-0' : ''}`}>
        {entry.render(toolData, onUpdateData)}
      </div>
    </div>
  );
};

type MinimizedToolsBarProps = {
  tools: Array<{
    toolId: string;
    title: string;
  }>;
  onRestore: (toolId: string) => void;
};

export const MinimizedToolsBar: React.FC<MinimizedToolsBarProps> = ({
  tools,
  onRestore
}) => {
  if (tools.length === 0) return null;

  return (
    <div className="fixed bottom-3 right-3 flex gap-2 z-[80]">
      {tools.map(({ toolId, title }) => (
        <button
          key={toolId}
          type="button"
          onClick={() => onRestore(toolId)}
          className="px-3 py-2 rounded bg-slate-900 border border-slate-700 text-xs text-slate-200 shadow-lg hover:bg-slate-800 transition-colors"
        >
          {title}
        </button>
      ))}
    </div>
  );
};
