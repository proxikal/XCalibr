import { useEffect } from 'react';

export interface ChromeMessage {
  type: string;
  data?: any;
}

/**
 * Custom hook for Chrome runtime messaging
 * @param handler Message handler function
 */
export function useMessage(handler: (message: ChromeMessage, sender: chrome.runtime.MessageSender) => void) {
  useEffect(() => {
    const messageListener = (
      message: ChromeMessage,
      sender: chrome.runtime.MessageSender
    ) => {
      handler(message, sender);
      return false; // Synchronous response
    };

    chrome.runtime.onMessage.addListener(messageListener);

    return () => {
      chrome.runtime.onMessage.removeListener(messageListener);
    };
  }, [handler]);
}

/**
 * Send a message to the background script or content script
 * @param message Message object
 * @returns Promise with response
 */
export async function sendMessage(message: ChromeMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(response);
      }
    });
  });
}

/**
 * Send a message to a specific tab
 * @param tabId Tab ID
 * @param message Message object
 * @returns Promise with response
 */
export async function sendTabMessage(tabId: number, message: ChromeMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(response);
      }
    });
  });
}
