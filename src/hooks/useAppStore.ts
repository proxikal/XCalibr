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

/**
 * Hook to use navigation state
 */
export function useNavigation() {
  const [state, setState] = useAppStore();

  const openTool = useCallback((toolId: string) => {
    setState((currentState) => ({
      uiState: {
        ...currentState.uiState,
        activeView: 'tool-detail',
        activeToolId: toolId,
      },
    }));
  }, [setState]);

  const closeTool = useCallback(() => {
    setState((currentState) => ({
      uiState: {
        ...currentState.uiState,
        activeView: 'tool-list',
        activeToolId: null,
      },
    }));
  }, [setState]);

  return {
    activeView: state.uiState.activeView,
    activeToolId: state.uiState.activeToolId,
    openTool,
    closeTool,
  };
}

/**
 * Hook to use JSON Formatter state
 */
export function useJSONFormatter() {
  const [state, setState] = useAppStore();

  const setInputJSON = useCallback((input: string) => {
    setState((currentState) => ({
      jsonFormatterState: {
        ...currentState.jsonFormatterState,
        inputJSON: input,
      },
    }));
  }, [setState]);

  const setFormattedJSON = useCallback((formatted: string) => {
    setState((currentState) => ({
      jsonFormatterState: {
        ...currentState.jsonFormatterState,
        formattedJSON: formatted,
      },
    }));
  }, [setState]);

  const setIndentSize = useCallback((size: number) => {
    setState((currentState) => ({
      jsonFormatterState: {
        ...currentState.jsonFormatterState,
        indentSize: size,
      },
    }));
  }, [setState]);

  const setSortKeys = useCallback((sort: boolean) => {
    setState((currentState) => ({
      jsonFormatterState: {
        ...currentState.jsonFormatterState,
        sortKeys: sort,
      },
    }));
  }, [setState]);

  const setError = useCallback((error: string | null) => {
    setState((currentState) => ({
      jsonFormatterState: {
        ...currentState.jsonFormatterState,
        error,
      },
    }));
  }, [setState]);

  const clearAll = useCallback(() => {
    setState((currentState) => ({
      jsonFormatterState: {
        ...currentState.jsonFormatterState,
        inputJSON: '',
        formattedJSON: '',
        error: null,
      },
    }));
  }, [setState]);

  return {
    jsonFormatterState: state.jsonFormatterState,
    setInputJSON,
    setFormattedJSON,
    setIndentSize,
    setSortKeys,
    setError,
    clearAll,
  };
}

/**
 * Hook to use Regex Tester state
 */
export function useRegexTester() {
  const [state, setState] = useAppStore();

  const setPattern = useCallback((pattern: string) => {
    setState((currentState) => ({
      regexTesterState: {
        ...currentState.regexTesterState,
        pattern,
      },
    }));
  }, [setState]);

  const setTestString = useCallback((testString: string) => {
    setState((currentState) => ({
      regexTesterState: {
        ...currentState.regexTesterState,
        testString,
      },
    }));
  }, [setState]);

  const setFlag = useCallback((flag: keyof AppState['regexTesterState']['flags'], value: boolean) => {
    setState((currentState) => ({
      regexTesterState: {
        ...currentState.regexTesterState,
        flags: {
          ...currentState.regexTesterState.flags,
          [flag]: value,
        },
      },
    }));
  }, [setState]);

  const setMatches = useCallback((matches: AppState['regexTesterState']['matches']) => {
    setState((currentState) => ({
      regexTesterState: {
        ...currentState.regexTesterState,
        matches,
      },
    }));
  }, [setState]);

  const setError = useCallback((error: string | null) => {
    setState((currentState) => ({
      regexTesterState: {
        ...currentState.regexTesterState,
        error,
      },
    }));
  }, [setState]);

  const setReplacePattern = useCallback((replacePattern: string) => {
    setState((currentState) => ({
      regexTesterState: {
        ...currentState.regexTesterState,
        replacePattern,
      },
    }));
  }, [setState]);

  const setReplaceResult = useCallback((replaceResult: string) => {
    setState((currentState) => ({
      regexTesterState: {
        ...currentState.regexTesterState,
        replaceResult,
      },
    }));
  }, [setState]);

  const clearAll = useCallback(() => {
    setState((currentState) => ({
      regexTesterState: {
        ...currentState.regexTesterState,
        pattern: '',
        testString: '',
        matches: [],
        error: null,
        replacePattern: '',
        replaceResult: '',
      },
    }));
  }, [setState]);

  return {
    regexTesterState: state.regexTesterState,
    setPattern,
    setTestString,
    setFlag,
    setMatches,
    setError,
    setReplacePattern,
    setReplaceResult,
    clearAll,
  };
}

/**
 * Hook to use Element Metadata Overlay state
 */
export function useElementMetadata() {
  const [state, setState] = useAppStore();

  const toggleActive = useCallback(() => {
    setState((currentState) => ({
      elementMetadataState: {
        ...currentState.elementMetadataState,
        isActive: !currentState.elementMetadataState.isActive,
      },
    }));
  }, [setState]);

  const setActive = useCallback((active: boolean) => {
    setState((currentState) => ({
      elementMetadataState: {
        ...currentState.elementMetadataState,
        isActive: active,
      },
    }));
  }, [setState]);

  const setLastInspectedElement = useCallback(
    (element: AppState['elementMetadataState']['lastInspectedElement']) => {
      setState((currentState) => ({
        elementMetadataState: {
          ...currentState.elementMetadataState,
          lastInspectedElement: element,
        },
      }));
    },
    [setState]
  );

  const addToHistory = useCallback(
    (item: { tagName: string; selector: string }) => {
      setState((currentState) => ({
        elementMetadataState: {
          ...currentState.elementMetadataState,
          inspectionHistory: [
            {
              timestamp: Date.now(),
              ...item,
            },
            ...currentState.elementMetadataState.inspectionHistory.slice(0, 19), // Keep last 20
          ],
        },
      }));
    },
    [setState]
  );

  const clearHistory = useCallback(() => {
    setState((currentState) => ({
      elementMetadataState: {
        ...currentState.elementMetadataState,
        inspectionHistory: [],
      },
    }));
  }, [setState]);

  return {
    elementMetadataState: state.elementMetadataState,
    toggleActive,
    setActive,
    setLastInspectedElement,
    addToHistory,
    clearHistory,
  };
}
