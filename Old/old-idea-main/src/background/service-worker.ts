/**
 * XCalibr Background Service Worker (TypeScript)
 * Handles extension lifecycle, messaging, and background tasks
 */

// Extension installation handler
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('XCalibr extension installed!');

    // Set default settings
    chrome.storage.local.set({
      activeTab: 'frontend',
      settings: {
        theme: 'dark',
        notifications: true,
      },
    });
  } else if (details.reason === 'update') {
    console.log('XCalibr extension updated!');
  }
});

// Extension startup handler
chrome.runtime.onStartup.addListener(() => {
  console.log('XCalibr extension started');
});

// Message handler for communication between popup, content scripts, and service worker
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  console.log('Message received:', message);

  switch (message.type) {
    case 'GET_ACTIVE_TAB':
      // Get the currently active tab information
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        sendResponse({ tab: tabs[0] });
      });
      return true; // Keep message channel open for async response

    case 'INJECT_CONTENT_SCRIPT':
      // Inject content script into specific tab
      if (message.tabId) {
        chrome.scripting
          .executeScript({
            target: { tabId: message.tabId },
            files: ['src/content/content-script.ts'],
          })
          .then(() => {
            sendResponse({ success: true });
          })
          .catch((error) => {
            sendResponse({ success: false, error: error.message });
          });
        return true;
      }
      break;

    case 'TOOL_ACTIVATED':
      // Handle tool activation
      console.log(`Tool activated: ${message.toolName}`);
      // TODO: Implement tool-specific logic
      sendResponse({ success: true });
      break;

    default:
      console.warn('Unknown message type:', message.type);
  }
});

// Context menu setup
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'xcalibr-inspect',
    title: 'Inspect with XCalibr',
    contexts: ['all'],
  });
});

// Context menu click handler
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'xcalibr-inspect' && tab?.id) {
    // Send message to content script to activate inspection mode
    chrome.tabs.sendMessage(tab.id, {
      type: 'ACTIVATE_INSPECTOR',
      data: {},
    });
  }
});

// Command handler for keyboard shortcuts
chrome.commands.onCommand.addListener((command) => {
  console.log('Command received:', command);

  switch (command) {
    case 'toggle-metadata-overlay':
      // Toggle metadata overlay
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'TOGGLE_METADATA_OVERLAY',
          });
        }
      });
      break;

    case 'toggle-inspector':
      // Toggle element inspector
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'TOGGLE_INSPECTOR',
          });
        }
      });
      break;

    case 'open-popup':
      // Open extension popup
      chrome.action.openPopup();
      break;

    default:
      console.warn('Unknown command:', command);
  }
});

console.log('XCalibr service worker loaded');
