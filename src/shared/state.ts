export type XcalibrState = {
  version: 1;
  isOpen: boolean;
  isWide: boolean;
  isVisible: boolean;
  searchQuery: string;
  tabOffsetY: number;
};

const STORAGE_KEY = 'xcalibr_state';

export const DEFAULT_STATE: XcalibrState = {
  version: 1,
  isOpen: false,
  isWide: false,
  isVisible: true,
  searchQuery: '',
  tabOffsetY: 50
};

const normalizeState = (value: unknown): XcalibrState => {
  if (!value || typeof value !== 'object') {
    return { ...DEFAULT_STATE };
  }

  const partial = value as Partial<XcalibrState>;
  const tabOffsetY =
    typeof partial.tabOffsetY === 'number'
      ? partial.tabOffsetY
      : DEFAULT_STATE.tabOffsetY;
  return {
    ...DEFAULT_STATE,
    ...partial,
    tabOffsetY,
    version: DEFAULT_STATE.version
  };
};

export const getState = async (): Promise<XcalibrState> => {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return normalizeState(stored[STORAGE_KEY]);
};

export const updateState = async (
  updater: Partial<XcalibrState> | ((current: XcalibrState) => XcalibrState)
): Promise<XcalibrState> => {
  const current = await getState();
  const next =
    typeof updater === 'function' ? updater(current) : { ...current, ...updater };
  const normalized = normalizeState(next);
  await chrome.storage.local.set({ [STORAGE_KEY]: normalized });
  return normalized;
};

export const subscribeState = (listener: (state: XcalibrState) => void) => {
  const handler = (
    changes: { [key: string]: chrome.storage.StorageChange },
    areaName: string
  ) => {
    if (areaName !== 'local' || !changes[STORAGE_KEY]) return;
    listener(normalizeState(changes[STORAGE_KEY].newValue));
  };

  chrome.storage.onChanged.addListener(handler);
  return () => chrome.storage.onChanged.removeListener(handler);
};
