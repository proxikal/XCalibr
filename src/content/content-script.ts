/**
 * XCalibr Content Script (TypeScript)
 * Injected into web pages to provide tool functionality
 * This script runs in the context of web pages
 */

(function () {
  'use strict';

  // Prevent multiple injections
  if ((window as any).xcalibrInjected) {
    console.log('XCalibr already injected');
    return;
  }
  (window as any).xcalibrInjected = true;

  console.log('XCalibr content script loaded');

  // State management
  interface State {
    inspectorActive: boolean;
    selectedElement: HTMLElement | null;
    overlay: HTMLElement | null;
  }

  const state: State = {
    inspectorActive: false,
    selectedElement: null,
    overlay: null,
  };

  /**
   * Initialize content script
   */
  function init() {
    createOverlay();
    setupMessageListener();
    console.log('XCalibr initialized on:', window.location.href);
  }

  /**
   * Create overlay element for highlighting
   */
  function createOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'xcalibr-overlay';
    overlay.style.cssText = `
      position: absolute;
      pointer-events: none;
      border: 2px solid #00e600;
      background: rgba(0, 230, 0, 0.1);
      z-index: 2147483647;
      display: none;
      box-shadow: 0 0 10px rgba(0, 230, 0, 0.5);
    `;
    document.body.appendChild(overlay);
    state.overlay = overlay;
  }

  /**
   * Setup message listener for communication with background script and popup
   */
  function setupMessageListener() {
    chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
      console.log('Content script received message:', message);

      switch (message.type) {
        case 'TOGGLE_INSPECTOR':
          toggleInspector();
          sendResponse({ success: true });
          break;

        case 'ACTIVATE_INSPECTOR':
          activateInspector(message.data);
          sendResponse({ success: true });
          break;

        case 'DEACTIVATE_INSPECTOR':
          deactivateInspector();
          sendResponse({ success: true });
          break;

        case 'GET_PAGE_INFO':
          sendResponse(getPageInfo());
          break;

        case 'INJECT_CSS':
          if (message.css) {
            injectCSS(message.css);
            sendResponse({ success: true });
          }
          break;

        default:
          console.warn('Unknown message type:', message.type);
          sendResponse({ success: false, error: 'Unknown message type' });
      }
    });
  }

  /**
   * Toggle element inspector on/off
   */
  function toggleInspector() {
    if (state.inspectorActive) {
      deactivateInspector();
    } else {
      activateInspector();
    }
  }

  /**
   * Activate element inspector
   */
  function activateInspector(_data?: any) {
    if (state.inspectorActive) return;

    state.inspectorActive = true;
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('click', handleInspectorClick, true);
    document.body.style.cursor = 'crosshair';

    console.log('Inspector activated');
  }

  /**
   * Deactivate element inspector
   */
  function deactivateInspector() {
    if (!state.inspectorActive) return;

    state.inspectorActive = false;
    document.removeEventListener('mousemove', handleMouseMove);
    document.removeEventListener('click', handleInspectorClick, true);
    document.body.style.cursor = '';
    if (state.overlay) {
      state.overlay.style.display = 'none';
    }

    console.log('Inspector deactivated');
  }

  /**
   * Handle mouse movement for element highlighting
   */
  function handleMouseMove(e: MouseEvent) {
    const element = e.target as HTMLElement;
    highlightElement(element);
  }

  /**
   * Handle inspector click to select element
   */
  function handleInspectorClick(e: MouseEvent) {
    e.preventDefault();
    e.stopPropagation();

    const element = e.target as HTMLElement;
    state.selectedElement = element;

    // Get element info
    const elementInfo = getElementInfo(element);
    console.log('Element selected:', elementInfo);

    // Send to popup or background
    chrome.runtime.sendMessage({
      type: 'ELEMENT_SELECTED',
      data: elementInfo,
    });

    deactivateInspector();
  }

  /**
   * Highlight element with overlay
   */
  function highlightElement(element: HTMLElement) {
    if (!state.overlay) return;

    const rect = element.getBoundingClientRect();
    state.overlay.style.top = `${window.scrollY + rect.top}px`;
    state.overlay.style.left = `${window.scrollX + rect.left}px`;
    state.overlay.style.width = `${rect.width}px`;
    state.overlay.style.height = `${rect.height}px`;
    state.overlay.style.display = 'block';
  }

  /**
   * Get detailed information about an element
   */
  function getElementInfo(element: HTMLElement) {
    const computed = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();

    return {
      tagName: element.tagName.toLowerCase(),
      id: element.id || null,
      classes: Array.from(element.classList),
      dimensions: {
        width: rect.width,
        height: rect.height,
        top: rect.top,
        left: rect.left,
      },
      styles: {
        color: computed.color,
        backgroundColor: computed.backgroundColor,
        fontSize: computed.fontSize,
        fontFamily: computed.fontFamily,
        padding: computed.padding,
        margin: computed.margin,
        border: computed.border,
        zIndex: computed.zIndex,
      },
      attributes: Array.from(element.attributes).map((attr) => ({
        name: attr.name,
        value: attr.value,
      })),
    };
  }

  /**
   * Get general page information
   */
  function getPageInfo() {
    return {
      url: window.location.href,
      title: document.title,
      meta: {
        description: document.querySelector('meta[name="description"]')?.getAttribute('content') || null,
        viewport: document.querySelector('meta[name="viewport"]')?.getAttribute('content') || null,
      },
      resources: {
        scripts: Array.from(document.scripts)
          .map((s) => s.src)
          .filter(Boolean),
        stylesheets: Array.from(document.styleSheets)
          .map((s) => s.href)
          .filter(Boolean),
      },
    };
  }

  /**
   * Inject CSS into the page
   */
  function injectCSS(css: string) {
    const style = document.createElement('style');
    style.textContent = css;
    style.setAttribute('data-xcalibr', 'true');
    document.head.appendChild(style);
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
