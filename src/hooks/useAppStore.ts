/**
 * React Hook for AppStore
 * Provides type-safe access to the centralized persistent store
 */

import { useState, useEffect, useCallback } from 'react';
import { appStore, type AppState } from '@/stores/appStore';
import type { TabCategory } from '@/types';

/**
 * Hook to use the entire app state
 */
export function useAppStore(): [AppState, (updater: Partial<AppState> | ((state: AppState) => Partial<AppState>)) => void] {
  const [state, setState] = useState<AppState>(appStore.getState());

  useEffect(() => {
    const unsubscribe = appStore.subscribe(setState);
    return unsubscribe;
  }, []);

  const updateState = useCallback((updater: Partial<AppState> | ((state: AppState) => Partial<AppState>)) => {
    appStore.setState(updater);
  }, []);

  return [state, updateState];
}

/**
 * Hook to use active tab state
 */
export function useActiveTab(): [TabCategory, (tab: TabCategory) => void] {
  const [state, setState] = useAppStore();

  const setActiveTab = useCallback((tab: TabCategory) => {
    setState({ activeTab: tab });
  }, [setState]);

  return [state.activeTab, setActiveTab];
}

/**
 * Hook to use app settings
 */
export function useSettings() {
  const [state, setState] = useAppStore();

  const updateSettings = useCallback((settings: Partial<AppState['settings']>) => {
    setState((currentState) => ({
      settings: {
        ...currentState.settings,
        ...settings,
      },
    }));
  }, [setState]);

  return [state.settings, updateSettings] as const;
}

/**
 * Hook to use tool state (favorites, usage tracking, etc.)
 */
export function useToolState() {
  const [state, setState] = useAppStore();

  const recordToolUsage = useCallback((toolId: string) => {
    setState((currentState) => ({
      toolState: {
        ...currentState.toolState,
        lastUsedTool: toolId,
        toolUsageCount: {
          ...currentState.toolState.toolUsageCount,
          [toolId]: (currentState.toolState.toolUsageCount[toolId] || 0) + 1,
        },
      },
    }));
  }, [setState]);

  const toggleFavorite = useCallback((toolId: string) => {
    setState((currentState) => {
      const favorites = currentState.toolState.favoriteTools;
      const isFavorite = favorites.includes(toolId);

      return {
        toolState: {
          ...currentState.toolState,
          favoriteTools: isFavorite
            ? favorites.filter((id) => id !== toolId)
            : [...favorites, toolId],
        },
      };
    });
  }, [setState]);

  return {
    toolState: state.toolState,
    recordToolUsage,
    toggleFavorite,
  };
}

/**
 * Hook to detect and handle crash recovery
 */
export function useCrashRecovery(): {
  hasCrashRecoveryData: boolean;
  crashRecoveryData: AppState['crashRecoveryData'];
  clearCrashRecoveryData: () => void;
} {
  const [state] = useAppStore();

  const clearCrashRecoveryData = useCallback(() => {
    appStore.clearCrashRecoveryData();
  }, []);

  return {
    hasCrashRecoveryData: !!state.crashRecoveryData,
    crashRecoveryData: state.crashRecoveryData,
    clearCrashRecoveryData,
  };
}

/**
 * Hook to use UI state (search, filters, pagination)
 */
export function useUIState() {
  const [state, setState] = useAppStore();

  const setSearchQuery = useCallback((query: string) => {
    setState((currentState) => ({
      uiState: {
        ...currentState.uiState,
        searchQuery: query,
        currentPage: 1, // Reset to page 1 when searching
      },
    }));
  }, [setState]);

  const setShowFavoritesOnly = useCallback((show: boolean) => {
    setState((currentState) => ({
      uiState: {
        ...currentState.uiState,
        showFavoritesOnly: show,
        currentPage: 1, // Reset to page 1 when toggling favorites
      },
    }));
  }, [setState]);

  const setCurrentPage = useCallback((page: number) => {
    setState((currentState) => ({
      uiState: {
        ...currentState.uiState,
        currentPage: page,
      },
    }));
  }, [setState]);

  return {
    uiState: state.uiState,
    setSearchQuery,
    setShowFavoritesOnly,
    setCurrentPage,
  };
}
