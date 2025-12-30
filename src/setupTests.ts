import { vi } from 'vitest';

type StorageListener = (
  changes: { [key: string]: chrome.storage.StorageChange },
  areaName: string
) => void;

type RuntimeMessageListener = (
  message: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response?: unknown) => void
) => boolean | void;

const storageData = new Map<string, unknown>();
const storageListeners = new Set<StorageListener>();
const runtimeListeners = new Set<RuntimeMessageListener>();
const runtimeHandlers = new Map<string, (payload?: unknown) => unknown>();

const notifyStorage = (changes: { [key: string]: chrome.storage.StorageChange }) => {
  storageListeners.forEach((listener) => listener(changes, 'local'));
};

const buildChromeMocks = () => {
  const chromeMock = {
    runtime: {
      sendMessage: vi.fn((message: unknown) => {
        return new Promise((resolve) => {
          let responded = false;
          if (message && typeof message === 'object' && 'type' in message) {
            const typed = message as { type: string; payload?: unknown };
            const handler = runtimeHandlers.get(typed.type);
            if (handler) {
              responded = true;
              resolve(handler(typed.payload));
              return;
            }
          }
          runtimeListeners.forEach((listener) => {
            const result = listener(message, {}, (response?: unknown) => {
              responded = true;
              resolve(response);
            });
            if (result === true && !responded) {
              // Listener will respond asynchronously via sendResponse.
            }
          });
          if (!responded) resolve({});
        });
      }),
      onMessage: {
        addListener: vi.fn((listener: RuntimeMessageListener) => {
          runtimeListeners.add(listener);
        }),
        removeListener: vi.fn((listener: RuntimeMessageListener) => {
          runtimeListeners.delete(listener);
        })
      }
    },
    storage: {
      local: {
        get: vi.fn(async (key?: string | string[] | null) => {
          if (!key) {
            const all: Record<string, unknown> = {};
            storageData.forEach((value, mapKey) => {
              all[mapKey] = value;
            });
            return all;
          }
          if (Array.isArray(key)) {
            const result: Record<string, unknown> = {};
            key.forEach((k) => {
              result[k] = storageData.get(k);
            });
            return result;
          }
          return { [key]: storageData.get(key) };
        }),
        set: vi.fn(async (items: Record<string, unknown>) => {
          const changes: Record<string, chrome.storage.StorageChange> = {};
          Object.entries(items).forEach(([key, value]) => {
            const oldValue = storageData.get(key);
            storageData.set(key, value);
            changes[key] = { oldValue, newValue: value };
          });
          notifyStorage(changes);
        })
      },
      onChanged: {
        addListener: vi.fn((listener: StorageListener) => {
          storageListeners.add(listener);
        }),
        removeListener: vi.fn((listener: StorageListener) => {
          storageListeners.delete(listener);
        })
      }
    },
    commands: {
      onCommand: {
        addListener: vi.fn(),
        removeListener: vi.fn()
      }
    },
    tabs: {
      query: vi.fn(async () => []),
      get: vi.fn(async () => ({ id: 1, url: 'https://example.com' }))
    },
    scripting: {
      insertCSS: vi.fn(async () => undefined),
      executeScript: vi.fn(async () => undefined)
    }
  };

  return chromeMock as unknown as typeof chrome;
};

Object.defineProperty(globalThis, 'chrome', {
  value: buildChromeMocks(),
  writable: true
});

Object.defineProperty(globalThis.navigator, 'clipboard', {
  value: { writeText: vi.fn(async () => undefined) },
  writable: true
});

Object.defineProperty(globalThis, 'requestAnimationFrame', {
  value: (cb: FrameRequestCallback) => window.setTimeout(cb, 0),
  writable: true
});

Object.defineProperty(globalThis, 'performance', {
  value: {
    timing: {
      navigationStart: 0,
      requestStart: 5,
      responseStart: 15,
      domContentLoadedEventEnd: 100,
      loadEventEnd: 150
    },
    getEntriesByType: vi.fn(() => [])
  },
  writable: true
});

if (!globalThis.PointerEvent) {
  class MockPointerEvent extends MouseEvent {
    constructor(type: string, params?: MouseEventInit) {
      super(type, params);
    }
  }
  Object.defineProperty(globalThis, 'PointerEvent', {
    value: MockPointerEvent,
    writable: true
  });
}

const buildStorageMock = () => {
  const store = new Map<string, string>();
  const storage: Record<string, unknown> = {};
  Object.defineProperties(storage, {
    getItem: {
      value: (key: string) => (store.has(key) ? store.get(key)! : null),
      enumerable: false
    },
    setItem: {
      value: (key: string, value: string) => {
        store.set(key, String(value));
        Object.defineProperty(storage, key, {
          value: String(value),
          writable: true,
          enumerable: true,
          configurable: true
        });
      },
      enumerable: false
    },
    removeItem: {
      value: (key: string) => {
        store.delete(key);
        delete storage[key];
      },
      enumerable: false
    },
    clear: {
      value: () => {
        store.clear();
        Object.keys(storage).forEach((key) => {
          delete storage[key];
        });
      },
      enumerable: false
    },
    key: {
      value: (index: number) => Array.from(store.keys())[index] ?? null,
      enumerable: false
    },
    length: {
      get: () => store.size,
      enumerable: false
    }
  });
  return storage as Storage;
};

Object.defineProperty(globalThis, 'localStorage', {
  value: buildStorageMock(),
  writable: true
});

Object.defineProperty(globalThis, 'sessionStorage', {
  value: buildStorageMock(),
  writable: true
});

(globalThis as Record<string, unknown>).__resetChromeMocks = () => {
  storageData.clear();
  storageListeners.clear();
  runtimeListeners.clear();
  runtimeHandlers.clear();
};

(globalThis as Record<string, unknown>).__clearRuntimeHandlers = () => {
  runtimeHandlers.clear();
};

(globalThis as Record<string, unknown>).__setRuntimeHandler = (
  type: string,
  handler: (payload?: unknown) => unknown
) => {
  runtimeHandlers.set(type, handler);
};

(globalThis as Record<string, unknown>).__clearRuntimeHandlers = () => {
  runtimeHandlers.clear();
};
