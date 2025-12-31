import type { ReactNode } from 'react';
import type { IconDefinition } from '@fortawesome/fontawesome-svg-core';

export const TOOL_DEFAULT_POSITION = { x: 80, y: 140 };

export type ToolRegistryEntry = {
  id: string;
  title: string;
  subtitle: string;
  category: string;
  icon: IconDefinition;
  hover: string;
  width?: number;
  height?: number;
  render: (
    data: unknown,
    onChange: (next: unknown) => void
  ) => ReactNode;
};

export type ToolRegistryHandlers = {
  refreshStorageExplorer: () => void;
  refreshCookies: () => void;
};
