import { useState, useEffect } from 'react';

/**
 * Custom hook to get the currently active browser tab
 * @returns Current active tab or null
 */
export function useActiveTab() {
  const [activeTab, setActiveTab] = useState<chrome.tabs.Tab | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Get initial active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        setActiveTab(tabs[0]);
      }
      setLoading(false);
    });

    // Listen for tab updates
    const handleTabUpdate = (_tabId: number, _changeInfo: any, tab: chrome.tabs.Tab) => {
      if (tab.active) {
        setActiveTab(tab);
      }
    };

    // Listen for tab activation
    const handleTabActivated = (activeInfo: any) => {
      chrome.tabs.get(activeInfo.tabId, (tab) => {
        setActiveTab(tab);
      });
    };

    chrome.tabs.onUpdated.addListener(handleTabUpdate);
    chrome.tabs.onActivated.addListener(handleTabActivated);

    return () => {
      chrome.tabs.onUpdated.removeListener(handleTabUpdate);
      chrome.tabs.onActivated.removeListener(handleTabActivated);
    };
  }, []);

  return { activeTab, loading };
}
