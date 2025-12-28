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
    metadataOverlayActive: boolean;
    metadataTooltip: HTMLElement | null;
  }

  const state: State = {
    inspectorActive: false,
    selectedElement: null,
    overlay: null,
    metadataOverlayActive: false,
    metadataTooltip: null,
  };

  /**
   * Initialize content script
   */
  function init() {
    createOverlay();
    createMetadataTooltip();
    setupMessageListener();
    setupKeyboardShortcuts();
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
        case 'PING':
          sendResponse({ success: true });
          break;

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

        case 'TOGGLE_METADATA_OVERLAY':
          toggleMetadataOverlay(message.data?.isActive);
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

  /**
   * Create metadata tooltip element
   */
  function createMetadataTooltip() {
    const tooltip = document.createElement('div');
    tooltip.id = 'xcalibr-metadata-tooltip';
    tooltip.style.cssText = `
      position: fixed;
      z-index: 2147483647;
      display: none;
      background: #0f172a;
      border: 1px solid #00e600;
      border-radius: 8px;
      padding: 12px;
      font-family: ui-sans-serif, system-ui, sans-serif;
      font-size: 12px;
      color: #cbd5e1;
      box-shadow: 0 0 20px rgba(0, 230, 0, 0.3);
      max-width: 350px;
      pointer-events: none;
    `;
    document.body.appendChild(tooltip);
    state.metadataTooltip = tooltip;
  }

  /**
   * Setup keyboard shortcuts
   */
  function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e: KeyboardEvent) => {
      // Cmd+Shift+. or Ctrl+Shift+.
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === '.') {
        e.preventDefault();
        toggleMetadataOverlay();
      }
    });
  }

  /**
   * Toggle metadata overlay
   */
  function toggleMetadataOverlay(forceState?: boolean) {
    state.metadataOverlayActive = forceState !== undefined ? forceState : !state.metadataOverlayActive;

    if (state.metadataOverlayActive) {
      activateMetadataOverlay();
    } else {
      deactivateMetadataOverlay();
    }

    console.log('Metadata overlay:', state.metadataOverlayActive ? 'activated' : 'deactivated');
  }

  /**
   * Activate metadata overlay
   */
  function activateMetadataOverlay() {
    document.addEventListener('mousemove', handleMetadataHover);
    document.addEventListener('mouseout', handleMetadataMouseOut);
  }

  /**
   * Deactivate metadata overlay
   */
  function deactivateMetadataOverlay() {
    document.removeEventListener('mousemove', handleMetadataHover);
    document.removeEventListener('mouseout', handleMetadataMouseOut);
    if (state.metadataTooltip) {
      state.metadataTooltip.style.display = 'none';
    }
  }

  /**
   * Handle mouse hover for metadata display
   */
  function handleMetadataHover(e: MouseEvent) {
    const element = e.target as HTMLElement;

    // Ignore our own tooltip and overlay
    if (element.id === 'xcalibr-metadata-tooltip' || element.id === 'xcalibr-overlay') {
      return;
    }

    const metadata = getElementMetadata(element);
    displayMetadataTooltip(metadata, e.clientX, e.clientY);

    // Send to popup
    chrome.runtime.sendMessage({
      type: 'ELEMENT_METADATA',
      data: metadata,
    });
  }

  /**
   * Handle mouse out
   */
  function handleMetadataMouseOut() {
    // We don't hide the tooltip on mouseout anymore, it updates on every hover
  }

  /**
   * Get element metadata
   */
  function getElementMetadata(element: HTMLElement) {
    const computed = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();

    // Calculate contrast ratio
    const contrastRatio = calculateContrastRatio(
      computed.color,
      computed.backgroundColor
    );

    return {
      tagName: element.tagName.toLowerCase(),
      id: element.id || null,
      classes: Array.from(element.classList),
      fontFamily: computed.fontFamily,
      fontSize: computed.fontSize,
      color: computed.color,
      backgroundColor: computed.backgroundColor,
      contrastRatio,
      boxModel: {
        margin: computed.margin,
        padding: computed.padding,
        border: computed.border,
        width: `${rect.width.toFixed(2)}px`,
        height: `${rect.height.toFixed(2)}px`,
      },
      zIndex: computed.zIndex,
      position: computed.position,
    };
  }

  /**
   * Calculate contrast ratio between two colors
   */
  function calculateContrastRatio(color1: string, color2: string): number | null {
    try {
      const rgb1 = parseRgbColor(color1);
      const rgb2 = parseRgbColor(color2);

      if (!rgb1 || !rgb2) return null;

      const l1 = getRelativeLuminance(rgb1);
      const l2 = getRelativeLuminance(rgb2);

      const lighter = Math.max(l1, l2);
      const darker = Math.min(l1, l2);

      return (lighter + 0.05) / (darker + 0.05);
    } catch {
      return null;
    }
  }

  /**
   * Parse RGB color string
   */
  function parseRgbColor(color: string): { r: number; g: number; b: number } | null {
    const match = color.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
    if (match) {
      return {
        r: parseInt(match[1]),
        g: parseInt(match[2]),
        b: parseInt(match[3]),
      };
    }
    return null;
  }

  /**
   * Get relative luminance
   */
  function getRelativeLuminance(rgb: { r: number; g: number; b: number }): number {
    const rsRGB = rgb.r / 255;
    const gsRGB = rgb.g / 255;
    const bsRGB = rgb.b / 255;

    const r = rsRGB <= 0.03928 ? rsRGB / 12.92 : Math.pow((rsRGB + 0.055) / 1.055, 2.4);
    const g = gsRGB <= 0.03928 ? gsRGB / 12.92 : Math.pow((gsRGB + 0.055) / 1.055, 2.4);
    const b = bsRGB <= 0.03928 ? bsRGB / 12.92 : Math.pow((bsRGB + 0.055) / 1.055, 2.4);

    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  }

  /**
   * Display metadata tooltip
   */
  function displayMetadataTooltip(metadata: any, x: number, y: number) {
    if (!state.metadataTooltip) return;

    const contrastRating = metadata.contrastRatio
      ? metadata.contrastRatio >= 7
        ? '<span style="color: #4ade80">AAA</span>'
        : metadata.contrastRatio >= 4.5
        ? '<span style="color: #facc15">AA</span>'
        : '<span style="color: #f87171">Fail</span>'
      : '<span style="color: #64748b">N/A</span>';

    const selector = metadata.id
      ? `#${metadata.id}`
      : metadata.classes.length > 0
      ? `.${metadata.classes[0]}`
      : metadata.tagName;

    state.metadataTooltip.innerHTML = `
      <div style="margin-bottom: 8px;">
        <div style="color: #00e600; font-weight: 600; font-family: monospace; margin-bottom: 4px;">
          ${selector}
        </div>
      </div>
      <div style="display: grid; gap: 6px; font-size: 11px;">
        <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #334155;">
          <span style="color: #94a3b8;">Font</span>
          <span style="font-family: monospace;">${metadata.fontFamily.split(',')[0].replace(/['"]/g, '')} ${metadata.fontSize}</span>
        </div>
        <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #334155;">
          <span style="color: #94a3b8;">Contrast</span>
          <span>${metadata.contrastRatio ? metadata.contrastRatio.toFixed(2) + ':1' : 'N/A'} ${contrastRating}</span>
        </div>
        <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #334155;">
          <span style="color: #94a3b8;">Margin</span>
          <span style="font-family: monospace; font-size: 10px;">${metadata.boxModel.margin}</span>
        </div>
        <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #334155;">
          <span style="color: #94a3b8;">Padding</span>
          <span style="font-family: monospace; font-size: 10px;">${metadata.boxModel.padding}</span>
        </div>
        <div style="display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #334155;">
          <span style="color: #94a3b8;">Z-Index</span>
          <span style="font-family: monospace;">${metadata.zIndex}</span>
        </div>
        <div style="display: flex; justify-content: space-between; padding: 4px 0;">
          <span style="color: #94a3b8;">Position</span>
          <span style="font-family: monospace;">${metadata.position}</span>
        </div>
      </div>
    `;

    // Position tooltip near cursor but keep it on screen
    const tooltipWidth = 350;
    const tooltipHeight = 300;
    const offsetX = 15;
    const offsetY = 15;

    let posX = x + offsetX;
    let posY = y + offsetY;

    // Adjust if tooltip goes off-screen
    if (posX + tooltipWidth > window.innerWidth) {
      posX = x - tooltipWidth - offsetX;
    }
    if (posY + tooltipHeight > window.innerHeight) {
      posY = y - tooltipHeight - offsetY;
    }

    state.metadataTooltip.style.left = `${posX}px`;
    state.metadataTooltip.style.top = `${posY}px`;
    state.metadataTooltip.style.display = 'block';
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
