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
}

export interface AppState {
  activeTab: TabCategory;
  settings: AppSettings;
  toolState: ToolState;
  uiState: UIState;
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

        // Restore state
        this.state = {
          ...savedState,
          sessionId: generateSessionId(),
          lastActiveTimestamp: Date.now(),
        };
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
