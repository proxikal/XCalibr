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
    if (message?.type === 'xcalibr-fetch-robots') {
      const run = async () => {
        const tabId = sender.tab?.id;
        if (typeof tabId !== 'number') {
          sendResponse({ error: 'No active tab available.' });
          return;
        }
        const tab = await chrome.tabs.get(tabId);
        const url = tab.url;
        if (!url) {
          sendResponse({ error: 'Unable to resolve tab URL.' });
          return;
        }
        const origin = new URL(url).origin;
        const response = await fetch(`${origin}/robots.txt`, {
          redirect: 'follow'
        });
        const content = await response.text();
        sendResponse({
          url: `${origin}/robots.txt`,
          content,
          updatedAt: Date.now()
        });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Failed to fetch robots.txt.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-fetch-headers') {
      const run = async () => {
        const tabId = sender.tab?.id;
        if (typeof tabId !== 'number') {
          sendResponse({ error: 'No active tab available.' });
          return;
        }
        const tab = await chrome.tabs.get(tabId);
        const url = tab.url;
        if (!url) {
          sendResponse({ error: 'Unable to resolve tab URL.' });
          return;
        }
        const response = await fetch(url, { redirect: 'follow' });
        const headers = Array.from(response.headers.entries()).map(
          ([name, value]) => ({ name, value })
        );
        sendResponse({
          url,
          status: response.status,
          headers,
          updatedAt: Date.now()
        });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Failed to fetch headers.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-payload-replay') {
      const run = async () => {
        const payload = message.payload as {
          url: string;
          method: string;
          headers: { name: string; value: string }[];
          body: string;
        };
        const response = await fetch(payload.url, {
          method: payload.method,
          headers: Object.fromEntries(
            payload.headers.map((header) => [header.name, header.value])
          ),
          body: payload.method === 'GET' || payload.method === 'HEAD' ? undefined : payload.body
        });
        const responseBody = await response.text();
        const responseHeaders = Array.from(response.headers.entries()).map(
          ([name, value]) => ({ name, value })
        );
        sendResponse({
          responseStatus: response.status,
          responseHeaders,
          responseBody,
          error: undefined
        });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'Request failed.'
        });
      });
      return true;
    }

    if (message?.type === 'xcalibr-cors-check') {
      const run = async () => {
        const { url } = message.payload as { url: string };
        const response = await fetch(url, { method: 'GET' });
        sendResponse({
          result: {
            status: response.status,
            acao: response.headers.get('access-control-allow-origin'),
            acc: response.headers.get('access-control-allow-credentials'),
            methods: response.headers.get('access-control-allow-methods'),
            headers: response.headers.get('access-control-allow-headers')
          },
          updatedAt: Date.now()
        });
      };

      run().catch((error) => {
        sendResponse({
          error: error instanceof Error ? error.message : 'CORS check failed.'
        });
      });
      return true;
    }

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
