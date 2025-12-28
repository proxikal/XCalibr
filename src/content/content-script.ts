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
    inspectorDataOverlay: HTMLElement | null;
    colorPickerActive: boolean;
    colorPickerTooltip: HTMLElement | null;
    embeddedToolPanel: HTMLElement | null;
    embeddedPickedColors: any[];
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
    inspectorDataOverlay: null,
    colorPickerActive: false,
    colorPickerTooltip: null,
    embeddedToolPanel: null,
    embeddedPickedColors: [],
  };

  /**
   * Initialize content script
   */
  function init() {
    createOverlay();
    createMetadataTooltip();
    createLinkPreviewElement();
    createInspectorDataOverlay();
    createColorPickerTooltip();
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

        case 'TOGGLE_COLOR_PICKER':
          toggleColorPicker(message.data?.isActive);
          sendResponse({ success: true });
          break;

        case 'EMBED_TOOL':
          embedTool(message.data?.toolId);
          sendResponse({ success: true });
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

    // Display in overlay instead of console
    displayInspectorData(elementInfo);

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
   * Create inspector data overlay element (fixed position)
   */
  function createInspectorDataOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'xcalibr-inspector-data-overlay';
    overlay.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 2147483646;
      display: none;
      background: #0f172a;
      border: 2px solid #00e600;
      border-radius: 12px;
      font-family: ui-sans-serif, system-ui, sans-serif;
      font-size: 12px;
      color: #cbd5e1;
      box-shadow: 0 0 30px rgba(0, 230, 0, 0.4);
      width: 450px;
      max-height: 90vh;
      overflow-y: auto;
      pointer-events: auto;
      backdrop-filter: blur(10px);
    `;

    // Custom scrollbar styles
    const style = document.createElement('style');
    style.textContent = `
      #xcalibr-inspector-data-overlay::-webkit-scrollbar {
        width: 8px;
      }
      #xcalibr-inspector-data-overlay::-webkit-scrollbar-track {
        background: #020617;
        border-radius: 4px;
      }
      #xcalibr-inspector-data-overlay::-webkit-scrollbar-thumb {
        background: #334155;
        border-radius: 4px;
      }
      #xcalibr-inspector-data-overlay::-webkit-scrollbar-thumb:hover {
        background: #00e600;
      }
    `;
    document.head.appendChild(style);

    document.body.appendChild(overlay);
    state.inspectorDataOverlay = overlay;
  }

  /**
   * Display inspector data in overlay
   */
  function displayInspectorData(elementInfo: any) {
    if (!state.inspectorDataOverlay) return;

    const selector = elementInfo.id
      ? `#${elementInfo.id}`
      : elementInfo.classes.length > 0
      ? `.${elementInfo.classes.join('.')}`
      : elementInfo.tagName;

    state.inspectorDataOverlay.innerHTML = `
      <div style="position: sticky; top: 0; background: #020617; padding: 16px; border-bottom: 2px solid #00e600; z-index: 10; border-radius: 12px 12px 0 0;">
        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
          <div style="flex: 1;">
            <div style="color: #00e600; font-weight: 700; font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">
              XCalibr Inspector
            </div>
            <div style="color: #00e600; font-weight: 600; font-family: ui-monospace, monospace; font-size: 14px; word-break: break-all;">
              ${selector}
            </div>
          </div>
          <button
            onclick="this.parentElement.parentElement.parentElement.style.display='none'"
            style="background: transparent; border: 1px solid #334155; color: #94a3b8; width: 28px; height: 28px; border-radius: 6px; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: all 0.2s; flex-shrink: 0; margin-left: 12px;"
            onmouseover="this.style.borderColor='#00e600'; this.style.color='#00e600';"
            onmouseout="this.style.borderColor='#334155'; this.style.color='#94a3b8';"
          >
            <svg style="width: 16px; height: 16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div style="color: #64748b; font-size: 11px;">
          Element information captured
        </div>
      </div>

      <div style="padding: 20px;">
        <!-- Element Info -->
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 16px;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 10px;">
            <svg style="width: 16px; height: 16px; color: #00e600;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 18" />
            </svg>
            <span style="color: #94a3b8; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">
              Element
            </span>
          </div>
          <div style="display: grid; gap: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: #64748b; font-size: 11px;">Tag Name</span>
              <span style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px;">
                ${elementInfo.tagName}
              </span>
            </div>
            ${elementInfo.id ? `
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: #64748b; font-size: 11px;">ID</span>
              <span style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px;">
                ${elementInfo.id}
              </span>
            </div>
            ` : ''}
            ${elementInfo.classes.length > 0 ? `
            <div>
              <div style="color: #64748b; font-size: 11px; margin-bottom: 4px;">Classes</div>
              <div style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px; word-break: break-all;">
                ${elementInfo.classes.join(', ')}
              </div>
            </div>
            ` : ''}
          </div>
        </div>

        <!-- Dimensions -->
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 16px;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
            <svg style="width: 16px; height: 16px; color: #00e600;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.75 3.75v4.5m0-4.5h4.5m-4.5 0L9 9M3.75 20.25v-4.5m0 4.5h4.5m-4.5 0L9 15M20.25 3.75h-4.5m4.5 0v4.5m0-4.5L15 9m5.25 11.25h-4.5m4.5 0v-4.5m0 4.5L15 15" />
            </svg>
            <span style="color: #94a3b8; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">
              Dimensions
            </span>
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
            <div>
              <div style="color: #64748b; font-size: 10px; margin-bottom: 4px;">Width</div>
              <div style="background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 6px; color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 10px;">
                ${elementInfo.dimensions.width.toFixed(2)}px
              </div>
            </div>
            <div>
              <div style="color: #64748b; font-size: 10px; margin-bottom: 4px;">Height</div>
              <div style="background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 6px; color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 10px;">
                ${elementInfo.dimensions.height.toFixed(2)}px
              </div>
            </div>
            <div>
              <div style="color: #64748b; font-size: 10px; margin-bottom: 4px;">Top</div>
              <div style="background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 6px; color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 10px;">
                ${elementInfo.dimensions.top.toFixed(2)}px
              </div>
            </div>
            <div>
              <div style="color: #64748b; font-size: 10px; margin-bottom: 4px;">Left</div>
              <div style="background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 6px; color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 10px;">
                ${elementInfo.dimensions.left.toFixed(2)}px
              </div>
            </div>
          </div>
        </div>

        <!-- Styles -->
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin-bottom: 16px;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
            <svg style="width: 16px; height: 16px; color: #00e600;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.53 16.122a3 3 0 00-5.78 1.128 2.25 2.25 0 01-2.4 2.245 4.5 4.5 0 008.4-2.245c0-.399-.078-.78-.22-1.128zm0 0a15.998 15.998 0 003.388-1.62m-5.043-.025a15.994 15.994 0 011.622-3.395m3.42 3.42a15.995 15.995 0 004.764-4.648l3.876-5.814a1.151 1.151 0 00-1.597-1.597L14.146 6.32a16.001 16.001 0 00-4.649 4.763m3.42 3.42a6.776 6.776 0 00-3.42-3.42" />
            </svg>
            <span style="color: #94a3b8; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">
              Styles
            </span>
          </div>
          <div style="display: grid; gap: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: #64748b; font-size: 11px;">Color</span>
              <span style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px;">
                ${elementInfo.styles.color}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: #64748b; font-size: 11px;">Background</span>
              <span style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px;">
                ${elementInfo.styles.backgroundColor}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: #64748b; font-size: 11px;">Font Size</span>
              <span style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px;">
                ${elementInfo.styles.fontSize}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: #64748b; font-size: 11px;">Font Family</span>
              <span style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px;">
                ${elementInfo.styles.fontFamily.split(',')[0].replace(/['"]/g, '')}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: #64748b; font-size: 11px;">Padding</span>
              <span style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px;">
                ${elementInfo.styles.padding}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: #64748b; font-size: 11px;">Margin</span>
              <span style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px;">
                ${elementInfo.styles.margin}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: #64748b; font-size: 11px;">Border</span>
              <span style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px;">
                ${elementInfo.styles.border}
              </span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center;">
              <span style="color: #64748b; font-size: 11px;">Z-Index</span>
              <span style="color: #cbd5e1; font-family: ui-monospace, monospace; font-size: 11px;">
                ${elementInfo.styles.zIndex}
              </span>
            </div>
          </div>
        </div>

        <!-- Attributes -->
        ${elementInfo.attributes.length > 0 ? `
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
            <svg style="width: 16px; height: 16px; color: #00e600;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
            </svg>
            <span style="color: #94a3b8; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;">
              Attributes
            </span>
          </div>
          <div style="display: grid; gap: 6px; max-height: 200px; overflow-y: auto;">
            ${elementInfo.attributes.map((attr: any) => `
              <div style="display: flex; justify-content: space-between; align-items: start; padding: 6px; background: #0f172a; border: 1px solid #334155; border-radius: 4px;">
                <span style="color: #94a3b8; font-size: 10px; font-family: ui-monospace, monospace; margin-right: 8px;">${attr.name}</span>
                <span style="color: #cbd5e1; font-size: 10px; font-family: ui-monospace, monospace; word-break: break-all; text-align: right;">${attr.value}</span>
              </div>
            `).join('')}
          </div>
        </div>
        ` : ''}
      </div>
    `;

    state.inspectorDataOverlay.style.display = 'block';
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

  /**
   * Create color picker tooltip
   */
  function createColorPickerTooltip() {
    const tooltip = document.createElement('div');
    tooltip.id = 'xcalibr-color-picker-tooltip';
    tooltip.style.cssText = `
      position: fixed;
      z-index: 2147483647;
      display: none;
      background: #0f172a;
      border: 2px solid #00e600;
      border-radius: 8px;
      padding: 12px;
      font-family: ui-sans-serif, system-ui, sans-serif;
      font-size: 12px;
      color: #cbd5e1;
      box-shadow: 0 0 20px rgba(0, 230, 0, 0.3);
      pointer-events: none;
      min-width: 200px;
    `;
    document.body.appendChild(tooltip);
    state.colorPickerTooltip = tooltip;
  }

  /**
   * Toggle color picker
   */
  function toggleColorPicker(forceState?: boolean) {
    state.colorPickerActive = forceState !== undefined ? forceState : !state.colorPickerActive;

    if (state.colorPickerActive) {
      activateColorPicker();
    } else {
      deactivateColorPicker();
    }

    console.log('Color picker:', state.colorPickerActive ? 'activated' : 'deactivated');
  }

  /**
   * Activate color picker
   */
  function activateColorPicker() {
    document.addEventListener('mousemove', handleColorPickerHover);
    document.addEventListener('click', handleColorPickerClick, true);
    document.body.style.cursor = 'crosshair';
  }

  /**
   * Deactivate color picker
   */
  function deactivateColorPicker() {
    document.removeEventListener('mousemove', handleColorPickerHover);
    document.removeEventListener('click', handleColorPickerClick, true);
    document.body.style.cursor = '';
    if (state.colorPickerTooltip) {
      state.colorPickerTooltip.style.display = 'none';
    }
  }

  /**
   * Handle color picker hover
   */
  function handleColorPickerHover(e: MouseEvent) {
    const element = e.target as HTMLElement;

    // Ignore our own tooltip and embedded panel
    if (element.id === 'xcalibr-color-picker-tooltip' ||
        element.closest('#xcalibr-embedded-panel')) {
      return;
    }

    const computed = window.getComputedStyle(element);
    const color = computed.color;
    const backgroundColor = computed.backgroundColor;

    // Use background color if available, otherwise text color
    const pickedColor = backgroundColor !== 'rgba(0, 0, 0, 0)' ? backgroundColor : color;

    displayColorTooltip(pickedColor, e.clientX, e.clientY);
  }

  /**
   * Handle color picker click
   */
  function handleColorPickerClick(e: MouseEvent) {
    const element = e.target as HTMLElement;

    // Ignore our own tooltip and embedded panel
    if (element.id === 'xcalibr-color-picker-tooltip' ||
        element.closest('#xcalibr-embedded-panel')) {
      return;
    }

    e.preventDefault();
    e.stopPropagation();

    const computed = window.getComputedStyle(element);
    const color = computed.color;
    const backgroundColor = computed.backgroundColor;

    // Use background color if available, otherwise text color
    const pickedColor = backgroundColor !== 'rgba(0, 0, 0, 0)' ? backgroundColor : color;

    const colorData = extractColorFormats(pickedColor);

    // Store to chrome.storage for persistence (popup might be closed)
    chrome.storage.local.get(['xcalibr_pending_colors'], (result) => {
      const pendingColors = (result.xcalibr_pending_colors as any[]) || [];
      pendingColors.push(colorData);
      chrome.storage.local.set({ xcalibr_pending_colors: pendingColors });
    });

    // Also try to send message if popup is open
    chrome.runtime.sendMessage({
      type: 'COLOR_PICKED',
      data: colorData,
    }).catch(() => {
      console.log('Color picked and stored (popup not open)');
    });

    console.log('Color picked:', colorData);

    // Add to embedded panel if active
    if (state.embeddedToolPanel) {
      state.embeddedPickedColors.push(colorData);
      updateEmbeddedUI();
    }

    // Deactivate color picker after picking
    deactivateColorPicker();
    state.colorPickerActive = false;
  }

  /**
   * Display color tooltip
   */
  function displayColorTooltip(color: string, x: number, y: number) {
    if (!state.colorPickerTooltip) return;

    const formats = extractColorFormats(color);

    state.colorPickerTooltip.innerHTML = `
      <div style="margin-bottom: 10px;">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
          <div style="width: 40px; height: 40px; border-radius: 6px; border: 2px solid #334155; background: ${formats.hex};"></div>
          <div>
            <div style="color: #00e600; font-weight: 600; font-size: 14px; font-family: monospace;">
              ${formats.hex}
            </div>
            <div style="color: #64748b; font-size: 10px;">
              Click to pick
            </div>
          </div>
        </div>
      </div>
      <div style="display: grid; gap: 6px; font-size: 11px;">
        <div style="padding: 6px; background: #1e293b; border: 1px solid #334155; border-radius: 4px;">
          <div style="color: #94a3b8; font-size: 10px; margin-bottom: 2px;">HEX</div>
          <div style="color: #cbd5e1; font-family: monospace;">${formats.hex}</div>
        </div>
        <div style="padding: 6px; background: #1e293b; border: 1px solid #334155; border-radius: 4px;">
          <div style="color: #94a3b8; font-size: 10px; margin-bottom: 2px;">RGB</div>
          <div style="color: #cbd5e1; font-family: monospace;">${formats.rgb}</div>
        </div>
        <div style="padding: 6px; background: #1e293b; border: 1px solid #334155; border-radius: 4px;">
          <div style="color: #94a3b8; font-size: 10px; margin-bottom: 2px;">RGBA</div>
          <div style="color: #cbd5e1; font-family: monospace;">${formats.rgba}</div>
        </div>
        <div style="padding: 6px; background: #1e293b; border: 1px solid #334155; border-radius: 4px;">
          <div style="color: #94a3b8; font-size: 10px; margin-bottom: 2px;">HSL</div>
          <div style="color: #cbd5e1; font-family: monospace;">${formats.hsl}</div>
        </div>
      </div>
    `;

    // Position tooltip
    const tooltipWidth = 220;
    const tooltipHeight = 280;
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

    state.colorPickerTooltip.style.left = `${posX}px`;
    state.colorPickerTooltip.style.top = `${posY}px`;
    state.colorPickerTooltip.style.display = 'block';
  }

  /**
   * Extract color in all formats
   */
  function extractColorFormats(color: string) {
    const rgb = parseRgbColor(color);
    if (!rgb) {
      return {
        color,
        hex: '#000000',
        rgb: 'rgb(0, 0, 0)',
        rgba: 'rgba(0, 0, 0, 1)',
        hsl: 'hsl(0, 0%, 0%)',
      };
    }

    // Get alpha from rgba if present
    const alphaMatch = color.match(/rgba?\([^,]+,[^,]+,[^,]+,\s*([\d.]+)\)/);
    const alpha = alphaMatch ? parseFloat(alphaMatch[1]) : 1;

    const hex = rgbToHex(color);
    const hsl = rgbToHsl(rgb);

    return {
      color,
      hex,
      rgb: `rgb(${rgb.r}, ${rgb.g}, ${rgb.b})`,
      rgba: `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${alpha})`,
      hsl,
    };
  }

  /**
   * Embed tool to site
   */
  function embedTool(toolId: string) {
    if (toolId === 'color-picker') {
      embedColorPicker();
    }
  }

  /**
   * Embed color picker tool
   */
  function embedColorPicker() {
    // Remove existing panel if any
    if (state.embeddedToolPanel) {
      state.embeddedToolPanel.remove();
      state.embeddedToolPanel = null;
    }

    // Create embedded panel
    const panel = document.createElement('div');
    panel.id = 'xcalibr-embedded-panel';
    panel.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 2147483645;
      width: 380px;
      max-height: 600px;
      background: #0f172a;
      border: 2px solid #00e600;
      border-radius: 12px;
      box-shadow: 0 0 30px rgba(0, 230, 0, 0.4);
      overflow: hidden;
      font-family: ui-sans-serif, system-ui, sans-serif;
      color: #cbd5e1;
    `;

    // Create header (draggable)
    const header = document.createElement('div');
    header.style.cssText = `
      background: #020617;
      padding: 12px 16px;
      border-bottom: 2px solid #00e600;
      cursor: move;
      display: flex;
      justify-content: space-between;
      align-items: center;
      user-select: none;
    `;

    const title = document.createElement('div');
    title.style.cssText = `
      color: #00e600;
      font-weight: 700;
      font-size: 14px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    `;
    title.textContent = 'XCalibr - Color Picker';

    const closeBtn = document.createElement('button');
    closeBtn.style.cssText = `
      background: transparent;
      border: 1px solid #334155;
      color: #94a3b8;
      width: 24px;
      height: 24px;
      border-radius: 4px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s;
    `;
    closeBtn.innerHTML = `<svg style="width: 14px; height: 14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>`;
    closeBtn.onmouseover = () => {
      closeBtn.style.borderColor = '#00e600';
      closeBtn.style.color = '#00e600';
    };
    closeBtn.onmouseout = () => {
      closeBtn.style.borderColor = '#334155';
      closeBtn.style.color = '#94a3b8';
    };
    closeBtn.onclick = () => {
      panel.remove();
      state.embeddedToolPanel = null;
      if (state.colorPickerActive) {
        deactivateColorPicker();
        state.colorPickerActive = false;
      }
    };

    header.appendChild(title);
    header.appendChild(closeBtn);

    // Create content area
    const content = document.createElement('div');
    content.style.cssText = `
      padding: 16px;
      max-height: 540px;
      overflow-y: auto;
    `;

    // Add custom scrollbar
    const scrollbarStyle = document.createElement('style');
    scrollbarStyle.textContent = `
      #xcalibr-embedded-panel > div:last-child::-webkit-scrollbar {
        width: 6px;
      }
      #xcalibr-embedded-panel > div:last-child::-webkit-scrollbar-track {
        background: #020617;
      }
      #xcalibr-embedded-panel > div:last-child::-webkit-scrollbar-thumb {
        background: #334155;
        border-radius: 3px;
      }
      #xcalibr-embedded-panel > div:last-child::-webkit-scrollbar-thumb:hover {
        background: #00e600;
      }
    `;
    document.head.appendChild(scrollbarStyle);

    // Add color picker controls
    content.innerHTML = createColorPickerUI();

    panel.appendChild(header);
    panel.appendChild(content);
    document.body.appendChild(panel);

    state.embeddedToolPanel = panel;

    // Make draggable
    makeDraggable(panel, header);

    // Setup color picker functionality for embedded panel
    setupEmbeddedColorPicker(content);

    console.log('Color Picker embedded to site');
  }

  /**
   * Create color picker UI HTML
   */
  function createColorPickerUI(): string {
    const isActive = state.colorPickerActive;
    const pickedColors = state.embeddedPickedColors;

    return `
      <div style="margin-bottom: 16px;">
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 12px;">
          <div style="display: flex; align-items: center; justify-between; margin-bottom: 12px;">
            <div style="display: flex; align-items: center; gap: 8px;">
              <div style="width: 8px; height: 8px; border-radius: 50%; background: ${isActive ? '#00e600' : '#64748b'};"></div>
              <span style="font-size: 12px; font-weight: 600;">${isActive ? 'Active' : 'Inactive'}</span>
            </div>
          </div>
          <p style="font-size: 11px; color: #64748b; margin-bottom: 12px;">
            Hover to preview, <strong style="color: #00e600;">click</strong> to pick colors
          </p>
          <button
            id="xcalibr-toggle-picker"
            style="width: 100%; background: ${isActive ? 'transparent' : '#00e600'}; border: ${isActive ? '1px solid #64748b' : 'none'}; color: ${isActive ? '#cbd5e1' : '#000'}; padding: 8px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.2s;"
          >
            ${isActive ? 'Deactivate' : 'Activate'} Color Picker
          </button>
        </div>
      </div>

      <div id="xcalibr-colors-list" style="display: ${pickedColors.length > 0 ? 'block' : 'none'};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
          <span style="font-size: 11px; font-weight: 600; color: #94a3b8; text-transform: uppercase;">Picked Colors (${pickedColors.length})</span>
          <button id="xcalibr-clear-colors" style="font-size: 10px; color: #64748b; background: none; border: none; cursor: pointer;">Clear</button>
        </div>
        <div id="xcalibr-colors-container">
          ${pickedColors.map((color, idx) => `
            <div style="background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
              <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                <div style="width: 36px; height: 36px; border-radius: 4px; border: 1px solid #334155; background: ${color.hex}; flex-shrink: 0;"></div>
                <div style="flex: 1; min-width: 0;">
                  <div style="font-size: 12px; font-weight: 600; color: #cbd5e1; font-family: monospace;">${color.hex}</div>
                </div>
                <button data-remove-idx="${idx}" style="color: #64748b; background: none; border: none; cursor: pointer; padding: 4px;">
                  <svg style="width: 14px; height: 14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
              </div>
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px; font-size: 10px;">
                <div data-copy="${color.hex}" style="background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 6px; cursor: pointer;">
                  <div style="color: #64748b; margin-bottom: 2px;">HEX</div>
                  <div style="color: #cbd5e1; font-family: monospace;">${color.hex}</div>
                </div>
                <div data-copy="${color.rgb}" style="background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 6px; cursor: pointer;">
                  <div style="color: #64748b; margin-bottom: 2px;">RGB</div>
                  <div style="color: #cbd5e1; font-family: monospace; font-size: 9px;">${color.rgb}</div>
                </div>
                <div data-copy="${color.rgba}" style="background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 6px; cursor: pointer;">
                  <div style="color: #64748b; margin-bottom: 2px;">RGBA</div>
                  <div style="color: #cbd5e1; font-family: monospace; font-size: 9px;">${color.rgba}</div>
                </div>
                <div data-copy="${color.hsl}" style="background: #0f172a; border: 1px solid #334155; border-radius: 4px; padding: 6px; cursor: pointer;">
                  <div style="color: #64748b; margin-bottom: 2px;">HSL</div>
                  <div style="color: #cbd5e1; font-family: monospace; font-size: 9px;">${color.hsl}</div>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>

      ${pickedColors.length === 0 ? `
        <div style="background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; text-align: center;">
          <div style="width: 40px; height: 40px; margin: 0 auto 8px; border-radius: 50%; background: rgba(0, 230, 0, 0.1); border: 1px solid rgba(0, 230, 0, 0.2); display: flex; align-items: center; justify-content: center;">
            <svg style="width: 20px; height: 20px; color: #00e600;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.53 16.122a3 3 0 00-5.78 1.128 2.25 2.25 0 01-2.4 2.245 4.5 4.5 0 008.4-2.245c0-.399-.078-.78-.22-1.128zm0 0a15.998 15.998 0 003.388-1.62m-5.043-.025a15.994 15.994 0 011.622-3.395m3.42 3.42a15.995 15.995 0 004.764-4.648l3.876-5.814a1.151 1.151 0 00-1.597-1.597L14.146 6.32a16.001 16.001 0 00-4.649 4.763m3.42 3.42a6.776 6.776 0 00-3.42-3.42" />
            </svg>
          </div>
          <p style="font-size: 12px; color: #94a3b8; margin-bottom: 4px;"><strong style="color: #00e600;">Click</strong> on colors to pick</p>
          <p style="font-size: 10px; color: #64748b;">Picked colors will appear here</p>
        </div>
      ` : ''}
    `;
  }

  /**
   * Setup embedded color picker functionality
   */
  function setupEmbeddedColorPicker(content: HTMLElement) {
    const toggleBtn = content.querySelector('#xcalibr-toggle-picker') as HTMLButtonElement;
    const clearBtn = content.querySelector('#xcalibr-clear-colors') as HTMLButtonElement;

    if (toggleBtn) {
      toggleBtn.onclick = () => {
        if (state.colorPickerActive) {
          deactivateColorPicker();
          state.colorPickerActive = false;
        } else {
          activateColorPicker();
          state.colorPickerActive = true;
        }
        updateEmbeddedUI();
      };
    }

    if (clearBtn) {
      clearBtn.onclick = () => {
        state.embeddedPickedColors = [];
        updateEmbeddedUI();
      };
    }

    // Setup copy buttons
    content.querySelectorAll('[data-copy]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const value = btn.getAttribute('data-copy');
        if (value) {
          navigator.clipboard.writeText(value);
          const originalText = btn.innerHTML;
          (btn as HTMLElement).innerHTML = '<div style="color: #00e600; font-weight: 600;">✓ Copied!</div>';
          setTimeout(() => {
            (btn as HTMLElement).innerHTML = originalText;
          }, 1500);
        }
      });
    });

    // Setup remove buttons
    content.querySelectorAll('[data-remove-idx]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-remove-idx') || '0');
        state.embeddedPickedColors.splice(idx, 1);
        updateEmbeddedUI();
      });
    });
  }

  /**
   * Update embedded UI
   */
  function updateEmbeddedUI() {
    if (!state.embeddedToolPanel) return;
    const content = state.embeddedToolPanel.querySelector('div:last-child');
    if (content) {
      content.innerHTML = createColorPickerUI();
      setupEmbeddedColorPicker(content as HTMLElement);
    }
  }

  /**
   * Make element draggable
   */
  function makeDraggable(element: HTMLElement, handle: HTMLElement) {
    let pos1 = 0, pos2 = 0, pos3 = 0, pos4 = 0;

    handle.onmousedown = dragMouseDown;

    function dragMouseDown(e: MouseEvent) {
      e.preventDefault();
      pos3 = e.clientX;
      pos4 = e.clientY;
      document.onmouseup = closeDragElement;
      document.onmousemove = elementDrag;
    }

    function elementDrag(e: MouseEvent) {
      e.preventDefault();
      pos1 = pos3 - e.clientX;
      pos2 = pos4 - e.clientY;
      pos3 = e.clientX;
      pos4 = e.clientY;
      element.style.top = (element.offsetTop - pos2) + 'px';
      element.style.left = (element.offsetLeft - pos1) + 'px';
      element.style.right = 'auto';
    }

    function closeDragElement() {
      document.onmouseup = null;
      document.onmousemove = null;
    }
  }

  /**
   * Convert RGB to HSL
   */
  function rgbToHsl(rgb: { r: number; g: number; b: number }): string {
    const r = rgb.r / 255;
    const g = rgb.g / 255;
    const b = rgb.b / 255;

    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    let h = 0;
    let s = 0;
    const l = (max + min) / 2;

    if (max !== min) {
      const d = max - min;
      s = l > 0.5 ? d / (2 - max - min) : d / (max + min);

      switch (max) {
        case r:
          h = ((g - b) / d + (g < b ? 6 : 0)) / 6;
          break;
        case g:
          h = ((b - r) / d + 2) / 6;
          break;
        case b:
          h = ((r - g) / d + 4) / 6;
          break;
      }
    }

    return `hsl(${Math.round(h * 360)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`;
  }

  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
