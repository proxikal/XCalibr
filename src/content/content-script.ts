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
    linkPreviewActive: boolean;
    linkPreviewElement: HTMLElement | null;
    currentHoveredLink: HTMLAnchorElement | null;
  }

  const state: State = {
    inspectorActive: false,
    selectedElement: null,
    overlay: null,
    metadataOverlayActive: false,
    metadataTooltip: null,
    linkPreviewActive: false,
    linkPreviewElement: null,
    currentHoveredLink: null,
  };

  /**
   * Initialize content script
   */
  function init() {
    createOverlay();
    createMetadataTooltip();
    createLinkPreviewElement();
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
          if (message.data?.css) {
            injectCSS(message.data.css, message.data.id);
            sendResponse({ success: true });
          }
          break;

        case 'REMOVE_CSS':
          if (message.data?.id) {
            removeCSS(message.data.id);
            sendResponse({ success: true });
          }
          break;

        case 'TOGGLE_FEATURE':
          if (message.data?.featureId === 'link-preview') {
            toggleLinkPreview(message.data.enabled);
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
  function injectCSS(css: string, id?: string) {
    // Remove existing style with same ID if it exists
    if (id) {
      const existing = document.getElementById(id);
      if (existing) {
        existing.remove();
      }
    }

    const style = document.createElement('style');
    style.textContent = css;
    style.setAttribute('data-xcalibr', 'true');
    if (id) {
      style.id = id;
    }
    document.head.appendChild(style);
  }

  /**
   * Remove injected CSS from the page
   */
  function removeCSS(id: string) {
    const style = document.getElementById(id);
    if (style && style.getAttribute('data-xcalibr') === 'true') {
      style.remove();
    }
  }

  /**
   * Create link preview element
   */
  function createLinkPreviewElement() {
    const preview = document.createElement('div');
    preview.id = 'xcalibr-link-preview';
    preview.style.cssText = `
      position: fixed;
      z-index: 2147483646;
      display: none;
      background: #0f172a;
      border: 2px solid #00e600;
      border-radius: 12px;
      box-shadow: 0 0 30px rgba(0, 230, 0, 0.4);
      overflow: hidden;
      pointer-events: none;
      width: 400px;
      height: 300px;
    `;

    // Create loading indicator
    const loading = document.createElement('div');
    loading.className = 'xcalibr-preview-loading';
    loading.style.cssText = `
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100%;
      color: #00e600;
      font-family: ui-sans-serif, system-ui, sans-serif;
      font-size: 14px;
    `;
    loading.textContent = 'Loading preview...';
    preview.appendChild(loading);

    document.body.appendChild(preview);
    state.linkPreviewElement = preview;
  }

  /**
   * Toggle link preview feature
   */
  function toggleLinkPreview(enabled: boolean) {
    state.linkPreviewActive = enabled;

    if (enabled) {
      activateLinkPreview();
    } else {
      deactivateLinkPreview();
    }

    console.log('Link preview:', enabled ? 'activated' : 'deactivated');
  }

  /**
   * Activate link preview
   */
  function activateLinkPreview() {
    document.addEventListener('mouseover', handleLinkHover);
    document.addEventListener('mouseout', handleLinkMouseOut);
  }

  /**
   * Deactivate link preview
   */
  function deactivateLinkPreview() {
    document.removeEventListener('mouseover', handleLinkHover);
    document.removeEventListener('mouseout', handleLinkMouseOut);
    if (state.linkPreviewElement) {
      state.linkPreviewElement.style.display = 'none';
    }
    state.currentHoveredLink = null;
  }

  /**
   * Handle link hover
   */
  function handleLinkHover(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const link = target.closest('a') as HTMLAnchorElement | null;

    if (!link || !link.href) {
      return;
    }

    // Ignore same-page anchors and javascript: links
    if (
      link.href.startsWith('javascript:') ||
      link.href.startsWith('#') ||
      link.href === window.location.href
    ) {
      return;
    }

    state.currentHoveredLink = link;
    displayLinkPreview(link, e.clientX, e.clientY);
  }

  /**
   * Handle link mouse out
   */
  function handleLinkMouseOut(e: MouseEvent) {
    const target = e.target as HTMLElement;
    const link = target.closest('a') as HTMLAnchorElement | null;

    if (link === state.currentHoveredLink) {
      if (state.linkPreviewElement) {
        state.linkPreviewElement.style.display = 'none';
      }
      state.currentHoveredLink = null;
    }
  }

  /**
   * Display link preview
   */
  function displayLinkPreview(link: HTMLAnchorElement, x: number, y: number) {
    if (!state.linkPreviewElement) return;

    const preview = state.linkPreviewElement;
    const url = link.href;

    // Clear previous content
    preview.innerHTML = '';

    // Create iframe for preview
    const iframe = document.createElement('iframe');
    iframe.src = url;
    iframe.style.cssText = `
      width: 100%;
      height: 100%;
      border: none;
      background: white;
    `;
    iframe.sandbox.add('allow-same-origin');

    // Create header with URL
    const header = document.createElement('div');
    header.style.cssText = `
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      background: rgba(15, 23, 42, 0.95);
      padding: 8px 12px;
      border-bottom: 1px solid #00e600;
      font-family: ui-monospace, monospace;
      font-size: 11px;
      color: #cbd5e1;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      z-index: 1;
    `;
    header.textContent = url;

    preview.appendChild(iframe);
    preview.appendChild(header);

    // Position preview near cursor
    const previewWidth = 400;
    const previewHeight = 300;
    const offsetX = 15;
    const offsetY = 15;

    let posX = x + offsetX;
    let posY = y + offsetY;

    // Adjust if preview goes off-screen
    if (posX + previewWidth > window.innerWidth) {
      posX = x - previewWidth - offsetX;
    }
    if (posY + previewHeight > window.innerHeight) {
      posY = y - previewHeight - offsetY;
    }

    preview.style.left = `${posX}px`;
    preview.style.top = `${posY}px`;
    preview.style.display = 'block';
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
    document.addEventListener('click', handleMetadataClick, true);
  }

  /**
   * Deactivate metadata overlay
   */
  function deactivateMetadataOverlay() {
    document.removeEventListener('mousemove', handleMetadataHover);
    document.removeEventListener('mouseout', handleMetadataMouseOut);
    document.removeEventListener('click', handleMetadataClick, true);
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
  }

  /**
   * Handle mouse out
   */
  function handleMetadataMouseOut() {
    // We don't hide the tooltip on mouseout anymore, it updates on every hover
  }

  /**
   * Handle click for metadata capture
   */
  function handleMetadataClick(e: MouseEvent) {
    const element = e.target as HTMLElement;

    // Ignore our own tooltip and overlay
    if (element.id === 'xcalibr-metadata-tooltip' || element.id === 'xcalibr-overlay') {
      return;
    }

    e.preventDefault();
    e.stopPropagation();

    const metadata = getElementMetadata(element);

    // Store in chrome.storage for popup to retrieve
    chrome.storage.local.set({
      xcalibr_element_metadata_pending: metadata,
    });

    // Also send message in case popup is open
    chrome.runtime.sendMessage({
      type: 'ELEMENT_METADATA_CLICKED',
      data: metadata,
    }).catch(() => {
      // Ignore error if popup is not open
      console.log('Element metadata stored (popup not open)');
    });

    console.log('Element metadata captured:', metadata);
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

    // Generate selector for the element
    const selector = element.id
      ? `#${element.id}`
      : element.classList.length > 0
      ? `.${Array.from(element.classList).join('.')}`
      : element.tagName.toLowerCase();

    return {
      timestamp: Date.now(),
      selector,
      tagName: element.tagName.toLowerCase(),
      id: element.id || null,
      classes: Array.from(element.classList),
      fontFamily: computed.fontFamily,
      fontSize: computed.fontSize,
      color: computed.color,
      colorHex: rgbToHex(computed.color),
      backgroundColor: computed.backgroundColor,
      backgroundColorHex: rgbToHex(computed.backgroundColor),
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
   * Convert RGB color to hex format
   */
  function rgbToHex(rgbString: string): string {
    const rgb = parseRgbColor(rgbString);
    if (!rgb) return '#000000';

    const toHex = (n: number) => {
      const hex = n.toString(16);
      return hex.length === 1 ? '0' + hex : hex;
    };

    return `#${toHex(rgb.r)}${toHex(rgb.g)}${toHex(rgb.b)}`;
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
