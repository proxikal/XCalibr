import { defineBackground } from 'wxt/sandbox';
import { updateState } from '../shared/state';

export default defineBackground(() => {
  chrome.commands.onCommand.addListener(async (command) => {
    if (command !== 'toggle-xcalibr-visibility') return;
    await updateState((current) => ({
      ...current,
      isVisible: !current.isVisible
    }));
  });

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type !== 'xcalibr-inject-code') return;

    const { mode, scope, code } = message.payload as {
      mode: 'css' | 'js';
      scope: 'current' | 'all';
      code: string;
    };

    const injectIntoTab = async (tabId: number) => {
      if (mode === 'css') {
        await chrome.scripting.insertCSS({
          target: { tabId },
          css: code
        });
        return;
      }

      await chrome.scripting.executeScript({
        target: { tabId },
        func: (source: string) => {
          const script = document.createElement('script');
          script.textContent = source;
          (document.head || document.documentElement).appendChild(script);
          script.remove();
        },
        args: [code]
      });
    };

    const run = async () => {
      if (scope === 'current') {
        const tabId = sender.tab?.id;
        if (typeof tabId === 'number') {
          await injectIntoTab(tabId);
        }
        sendResponse({ ok: true });
        return;
      }

      const tabs = await chrome.tabs.query({});
      await Promise.allSettled(
        tabs
          .map((tab) => tab.id)
          .filter((tabId): tabId is number => typeof tabId === 'number')
          .map((tabId) => injectIntoTab(tabId))
      );
      sendResponse({ ok: true });
    };

    run().catch(() => sendResponse({ ok: false }));
    return true;
  });
});
