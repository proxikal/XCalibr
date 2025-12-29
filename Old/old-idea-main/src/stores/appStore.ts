/**
 * Centralized Application Store with Chrome Storage Persistence
 *
 * This store ensures all critical application state is persisted to chrome.storage.local
 * and can survive browser crashes, extension reloads, and other interruptions.
 */

import type { TabCategory } from '@/types';

export interface AppSettings {
  theme: 'dark' | 'light';
  notifications: boolean;
}

export interface ToolState {
  lastUsedTool: string | null;
  favoriteTools: string[];
  toolUsageCount: Record<string, number>;
}

export interface UIState {
  searchQuery: string;
  showFavoritesOnly: boolean;
  currentPage: number;
  itemsPerPage: number;
  activeView: 'tool-list' | 'tool-detail';
  activeToolId: string | null;
}

export interface JSONFormatterState {
  inputJSON: string;
  formattedJSON: string;
  indentSize: number;
  sortKeys: boolean;
  error: string | null;
}

export interface RegexTesterState {
  pattern: string;
  testString: string;
  flags: {
    global: boolean;
    multiline: boolean;
    caseInsensitive: boolean;
    dotAll: boolean;
    unicode: boolean;
    sticky: boolean;
  };
  matches: Array<{
    fullMatch: string;
    groups: string[];
    index: number;
  }>;
  error: string | null;
  replacePattern: string;
  replaceResult: string;
}

export interface ElementInspection {
  timestamp: number;
  selector: string;
  tagName: string;
  id: string | null;
  classes: string[];
  fontFamily: string;
  fontSize: string;
  color: string;
  colorHex: string;
  backgroundColor: string;
  backgroundColorHex: string;
  contrastRatio: number | null;
  boxModel: {
    margin: string;
    padding: string;
    border: string;
    width: string;
    height: string;
  };
  zIndex: string;
  position: string;
}

export interface ElementMetadataState {
  isActive: boolean;
  lastInspectedElement: ElementInspection | null;
  inspectionHistory: ElementInspection[];
}

export interface FeatureItem {
  id: string;
  name: string;
  description: string;
  icon: string;
  enabled: boolean;
  category: 'productivity' | 'development' | 'ui';
}

export interface FeaturesState {
  features: FeatureItem[];
  currentPage: number;
}

export interface CSSScratchpadState {
  domains: Record<string, {
    css: string;
    enabled: boolean;
    lastModified: number;
  }>;
}

export interface LiveCSSState {
  input: string;
  currentDomain: string | null;
  isInjected: boolean;
}

export interface AppState {
  activeTab: TabCategory;
  settings: AppSettings;
  toolState: ToolState;
  uiState: UIState;
  jsonFormatterState: JSONFormatterState;
  regexTesterState: RegexTesterState;
  elementMetadataState: ElementMetadataState;
  featuresState: FeaturesState;
  cssScratchpadState: CSSScratchpadState;
  liveCSSState: LiveCSSState;
  lastActiveTimestamp: number;
  sessionId: string;
  crashRecoveryData?: {
    timestamp: number;
    activeTab: TabCategory;
    wasUnexpectedClose: boolean;
  };
}

const DEFAULT_STATE: AppState = {
  activeTab: 'frontend',
  settings: {
    theme: 'dark',
    notifications: true,
  },
  toolState: {
    lastUsedTool: null,
    favoriteTools: [],
    toolUsageCount: {},
  },
  uiState: {
    searchQuery: '',
    showFavoritesOnly: false,
    currentPage: 1,
    itemsPerPage: 5,
    activeView: 'tool-list',
    activeToolId: null,
  },
  jsonFormatterState: {
    inputJSON: '',
    formattedJSON: '',
    indentSize: 2,
    sortKeys: false,
    error: null,
  },
  regexTesterState: {
    pattern: '',
    testString: '',
    flags: {
      global: true,
      multiline: false,
      caseInsensitive: false,
      dotAll: false,
      unicode: false,
      sticky: false,
    },
    matches: [],
    error: null,
    replacePattern: '',
    replaceResult: '',
  },
  elementMetadataState: {
    isActive: false,
    lastInspectedElement: null,
    inspectionHistory: [],
  },
  featuresState: {
    features: [
      {
        id: 'link-preview',
        name: 'Link Preview on Hover',
        description: 'Preview links without opening tabs',
        icon: `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" class="w-5 h-5">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
        </svg>`,
        enabled: false,
        category: 'productivity',
      },
    ],
    currentPage: 1,
  },
  cssScratchpadState: {
    domains: {},
  },
  liveCSSState: {
    input: '',
    currentDomain: null,
    isInjected: false,
  },
  lastActiveTimestamp: Date.now(),
  sessionId: generateSessionId(),
};

function generateSessionId(): string {
  return `session_${Date.now()}_${Math.random().toString(36).substring(7)}`;
}

class AppStore {
  private state: AppState = DEFAULT_STATE;
  private listeners: Set<(state: AppState) => void> = new Set();
  private saveTimeout: number | null = null;
  private readonly STORAGE_KEY = 'xcalibr_app_state';
  private readonly HEARTBEAT_INTERVAL = 5000; // 5 seconds
  private heartbeatTimer: number | null = null;

  constructor() {
    this.initialize();
  }

  /**
   * Initialize the store from chrome.storage
   * Detects and handles crash recovery
   */
  private async initialize(): Promise<void> {
    try {
      const result = await chrome.storage.local.get([this.STORAGE_KEY]);
      const savedState = result[this.STORAGE_KEY] as AppState | undefined;

      if (savedState) {
        // Check if previous session ended unexpectedly (crash detection)
        const timeSinceLastActive = Date.now() - savedState.lastActiveTimestamp;
        const wasUnexpectedClose = timeSinceLastActive > this.HEARTBEAT_INTERVAL * 2;

        if (wasUnexpectedClose) {
          console.warn('⚠️ Crash detected - recovering previous state');
          savedState.crashRecoveryData = {
            timestamp: savedState.lastActiveTimestamp,
            activeTab: savedState.activeTab,
            wasUnexpectedClose: true,
          };
        }

        // Migrate old state format - merge with defaults for new properties
        this.state = {
          ...DEFAULT_STATE,
          ...savedState,
          // Ensure uiState exists (for migration from older versions)
          uiState: {
            ...DEFAULT_STATE.uiState,
            ...(savedState.uiState || {}),
          },
          // Ensure toolState exists and has all required properties
          toolState: {
            ...DEFAULT_STATE.toolState,
            ...(savedState.toolState || {}),
          },
          // Ensure settings exists
          settings: {
            ...DEFAULT_STATE.settings,
            ...(savedState.settings || {}),
          },
          // Ensure jsonFormatterState exists
          jsonFormatterState: {
            ...DEFAULT_STATE.jsonFormatterState,
            ...(savedState.jsonFormatterState || {}),
          },
          // Ensure regexTesterState exists
          regexTesterState: {
            ...DEFAULT_STATE.regexTesterState,
            ...(savedState.regexTesterState || {}),
          },
          // Ensure elementMetadataState exists
          elementMetadataState: {
            ...DEFAULT_STATE.elementMetadataState,
            ...(savedState.elementMetadataState || {}),
          },
          // Ensure featuresState exists
          featuresState: {
            ...DEFAULT_STATE.featuresState,
            ...(savedState.featuresState || {}),
          },
          // Ensure cssScratchpadState exists
          cssScratchpadState: {
            ...DEFAULT_STATE.cssScratchpadState,
            ...(savedState.cssScratchpadState || {}),
          },
          // Ensure liveCSSState exists
          liveCSSState: {
            ...DEFAULT_STATE.liveCSSState,
            ...(savedState.liveCSSState || {}),
          },
          sessionId: generateSessionId(),
          lastActiveTimestamp: Date.now(),
        };

        console.log('✅ State migrated successfully:', this.state);
      }

      // Start heartbeat to track active sessions
      this.startHeartbeat();

      // Listen for storage changes from other extension contexts
      chrome.storage.onChanged.addListener(this.handleStorageChange);

      // Initial save to mark session as active
      await this.persist();

      console.log('✅ AppStore initialized:', this.state);
    } catch (error) {
      console.error('❌ Failed to initialize AppStore:', error);
      this.state = DEFAULT_STATE;
    }
  }

  /**
   * Start heartbeat to detect crashes
   */
  private startHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    this.heartbeatTimer = setInterval(() => {
      this.state.lastActiveTimestamp = Date.now();
      this.persist();
    }, this.HEARTBEAT_INTERVAL);
  }

  /**
   * Handle storage changes from other contexts
   */
  private handleStorageChange = (
    changes: { [key: string]: chrome.storage.StorageChange },
    areaName: string
  ): void => {
    if (areaName === 'local' && changes[this.STORAGE_KEY]) {
      const newState = changes[this.STORAGE_KEY].newValue as AppState;
      if (newState && newState.sessionId !== this.state.sessionId) {
        // Update from another context
        this.state = newState;
        this.notifyListeners();
      }
    }
  };

  /**
   * Persist state to chrome.storage with debouncing
   */
  private async persist(): Promise<void> {
    if (this.saveTimeout) {
      clearTimeout(this.saveTimeout);
    }

    this.saveTimeout = setTimeout(async () => {
      try {
        await chrome.storage.local.set({
          [this.STORAGE_KEY]: this.state,
        });
      } catch (error) {
        console.error('❌ Failed to persist state:', error);
      }
    }, 100); // Debounce saves
  }

  /**
   * Get current state
   */
  public getState(): AppState {
    return this.state;
  }

  /**
   * Update state and persist
   */
  public setState(updater: Partial<AppState> | ((state: AppState) => Partial<AppState>)): void {
    const updates = typeof updater === 'function' ? updater(this.state) : updater;

    this.state = {
      ...this.state,
      ...updates,
      lastActiveTimestamp: Date.now(),
    };

    this.notifyListeners();
    this.persist();
  }

  /**
   * Subscribe to state changes
   */
  public subscribe(listener: (state: AppState) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * Notify all listeners of state changes
   */
  private notifyListeners(): void {
    this.listeners.forEach((listener) => listener(this.state));
  }

  /**
   * Clear crash recovery data
   */
  public clearCrashRecoveryData(): void {
    this.setState({ crashRecoveryData: undefined });
  }

  /**
   * Reset to default state
   */
  public reset(): void {
    this.state = {
      ...DEFAULT_STATE,
      sessionId: generateSessionId(),
      lastActiveTimestamp: Date.now(),
    };
    this.notifyListeners();
    this.persist();
  }

  /**
   * Cleanup on unload
   */
  public cleanup(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }
    if (this.saveTimeout) {
      clearTimeout(this.saveTimeout);
    }
    chrome.storage.onChanged.removeListener(this.handleStorageChange);
  }
}

// Singleton instance
export const appStore = new AppStore();

// Cleanup on window unload
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => {
    appStore.cleanup();
  });
}
