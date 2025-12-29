/**
 * Element Metadata Overlay Tool
 * Toggle overlay to inspect element styles on hover
 * Keyboard shortcut: Cmd+Shift+.
 */

import React, { useEffect, useState } from 'react';
import { useElementMetadata } from '@/hooks/useAppStore';

export const ElementMetadata: React.FC = () => {
  const {
    elementMetadataState,
    setActive,
    addInspection,
    loadInspection,
    clearHistory,
  } = useElementMetadata();

  const [isConnected, setIsConnected] = useState(false);

  // Check if content script is available
  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(
          tabs[0].id,
          { type: 'PING' },
          () => {
            if (chrome.runtime.lastError) {
              setIsConnected(false);
            } else {
              setIsConnected(true);
            }
          }
        );
      }
    });
  }, []);

  // Check for pending metadata on mount
  useEffect(() => {
    chrome.storage.local.get(['xcalibr_element_metadata_pending'], (result) => {
      const pendingData = result.xcalibr_element_metadata_pending;
      if (pendingData && typeof pendingData === 'object') {
        console.log('Loading pending metadata:', pendingData);
        addInspection(pendingData as any);
        // Clear the pending data
        chrome.storage.local.remove('xcalibr_element_metadata_pending');
      }
    });
  }, [addInspection]);

  // Listen for element inspection data from content script
  useEffect(() => {
    const handleMessage = (
      message: any,
      _sender: chrome.runtime.MessageSender
    ) => {
      if (message.type === 'ELEMENT_METADATA_CLICKED') {
        console.log('Received metadata message:', message.data);
        addInspection(message.data);
        // Clear pending data since we got it via message
        chrome.storage.local.remove('xcalibr_element_metadata_pending');
      }
    };

    chrome.runtime.onMessage.addListener(handleMessage);

    return () => {
      chrome.runtime.onMessage.removeListener(handleMessage);
    };
  }, [addInspection]);

  // Sync state with content script when toggling
  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'TOGGLE_METADATA_OVERLAY',
          data: { isActive: elementMetadataState.isActive },
        });
      }
    });
  }, [elementMetadataState.isActive]);

  const handleActivate = () => {
    if (!isConnected) {
      alert('Please reload the page to enable Element Metadata Overlay');
      return;
    }
    setActive(true);
  };

  const handleDeactivate = () => {
    setActive(false);
  };

  const getContrastRating = (ratio: number | null) => {
    if (!ratio) return { text: 'Unknown', color: 'text-slate-500' };
    if (ratio >= 7) return { text: 'AAA', color: 'text-green-400' };
    if (ratio >= 4.5) return { text: 'AA', color: 'text-yellow-400' };
    return { text: 'Fail', color: 'text-red-400' };
  };

  const elem = elementMetadataState.lastInspectedElement;
  const contrastRating = elem ? getContrastRating(elem.contrastRatio) : null;

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <main className="flex-1 overflow-y-auto p-5 space-y-6 custom-scrollbar relative">
        {/* Background Gradient */}
        <div className="fixed top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-dev-green/5 blur-3xl rounded-full pointer-events-none"></div>

        {/* Status Section */}
        <section className="space-y-3 relative z-0">
          <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-2">
            Overlay Status
          </h2>

          <div className="bg-dev-card/50 border border-slate-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div
                  className={`w-2 h-2 rounded-full ${
                    elementMetadataState.isActive ? 'bg-dev-green' : 'bg-slate-600'
                  }`}
                ></div>
                <span className="text-sm font-medium text-slate-200">
                  {elementMetadataState.isActive ? 'Active' : 'Inactive'}
                </span>
              </div>
              <kbd className="px-2 py-1 text-xs font-mono bg-slate-800 border border-slate-700 rounded text-slate-400">
                Cmd+Shift+.
              </kbd>
            </div>
            <p className="text-xs text-slate-500 mb-4">
              Hover to preview, <strong className="text-dev-green">click to capture</strong> element metadata. Captured elements appear in Recent Inspections below.
            </p>
            <div className="flex gap-2">
              {!elementMetadataState.isActive ? (
                <button
                  onClick={handleActivate}
                  className="flex-1 bg-dev-green text-black hover:bg-[#00ff00] py-2 rounded-md text-sm font-bold shadow-[0_0_15px_rgba(0,230,0,0.3)] hover:shadow-[0_0_20px_rgba(0,230,0,0.5)] transition-all"
                >
                  Activate Overlay
                </button>
              ) : (
                <button
                  onClick={handleDeactivate}
                  className="flex-1 bg-transparent border border-slate-600 text-slate-300 hover:text-white hover:border-slate-400 py-2 rounded-md text-sm font-medium transition-colors"
                >
                  Deactivate Overlay
                </button>
              )}
            </div>

            {!isConnected && (
              <div className="mt-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
                <p className="text-xs text-yellow-400">
                  ⚠️ Page needs to be reloaded to activate this feature
                </p>
              </div>
            )}
          </div>
        </section>

        {/* Last Inspected Element */}
        {elem ? (
          <>
            <div className="h-px bg-slate-800"></div>

            <section className="space-y-3 relative z-0">
              <div className="flex items-center justify-between">
                <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold">
                  Last Inspected Element
                </h2>
              </div>

              <div className="space-y-3">
                {/* Element Selector */}
                <div className="bg-dev-card/30 border border-slate-700 rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-2">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      strokeWidth="1.5"
                      stroke="currentColor"
                      className="w-4 h-4 text-dev-green"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 18"
                      />
                    </svg>
                    <span className="text-xs font-semibold text-slate-400 uppercase">
                      Selector
                    </span>
                  </div>
                  <code className="text-sm text-dev-green font-mono">
                    {elem.tagName}
                    {elem.id && `#${elem.id}`}
                    {elem.classes.length > 0 && `.${elem.classes.join('.')}`}
                  </code>
                </div>

                {/* Typography */}
                <div className="bg-dev-card/30 border border-slate-700 rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-3">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      strokeWidth="1.5"
                      stroke="currentColor"
                      className="w-4 h-4 text-dev-green"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25H12"
                      />
                    </svg>
                    <span className="text-xs font-semibold text-slate-400 uppercase">
                      Typography
                    </span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-slate-500">Font Family</span>
                      <span className="text-xs text-slate-300 font-mono">
                        {elem.fontFamily.split(',')[0].replace(/['"]/g, '')}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-slate-500">Font Size</span>
                      <span className="text-xs text-slate-300 font-mono">
                        {elem.fontSize}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Colors & Contrast */}
                <div className="bg-dev-card/30 border border-slate-700 rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-3">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      strokeWidth="1.5"
                      stroke="currentColor"
                      className="w-4 h-4 text-dev-green"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M9.53 16.122a3 3 0 00-5.78 1.128 2.25 2.25 0 01-2.4 2.245 4.5 4.5 0 008.4-2.245c0-.399-.078-.78-.22-1.128zm0 0a15.998 15.998 0 003.388-1.62m-5.043-.025a15.994 15.994 0 011.622-3.395m3.42 3.42a15.995 15.995 0 004.764-4.648l3.876-5.814a1.151 1.151 0 00-1.597-1.597L14.146 6.32a16.001 16.001 0 00-4.649 4.763m3.42 3.42a6.776 6.776 0 00-3.42-3.42"
                      />
                    </svg>
                    <span className="text-xs font-semibold text-slate-400 uppercase">
                      Colors
                    </span>
                  </div>
                  <div className="space-y-2">
                    <div>
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-xs text-slate-500">Text Color</span>
                        <div className="flex items-center gap-2">
                          <div
                            className="w-4 h-4 rounded border border-slate-600"
                            style={{ backgroundColor: elem.color }}
                          ></div>
                          <span className="text-xs text-slate-300 font-mono">
                            {elem.color}
                          </span>
                        </div>
                      </div>
                      {elem.colorHex && (
                        <div className="flex justify-end">
                          <span className="text-[10px] text-slate-600 font-mono">
                            {elem.colorHex}
                          </span>
                        </div>
                      )}
                    </div>
                    <div>
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-xs text-slate-500">Background</span>
                        <div className="flex items-center gap-2">
                          <div
                            className="w-4 h-4 rounded border border-slate-600"
                            style={{ backgroundColor: elem.backgroundColor }}
                          ></div>
                          <span className="text-xs text-slate-300 font-mono">
                            {elem.backgroundColor}
                          </span>
                        </div>
                      </div>
                      {elem.backgroundColorHex && (
                        <div className="flex justify-end">
                          <span className="text-[10px] text-slate-600 font-mono">
                            {elem.backgroundColorHex}
                          </span>
                        </div>
                      )}
                    </div>
                    {elem.contrastRatio !== null && contrastRating && (
                      <div className="flex justify-between items-center pt-2 border-t border-slate-700/50">
                        <span className="text-xs text-slate-500">
                          Contrast Ratio
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-slate-300 font-mono">
                            {elem.contrastRatio.toFixed(2)}:1
                          </span>
                          <span
                            className={`text-xs font-bold ${contrastRating.color}`}
                          >
                            {contrastRating.text}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Box Model */}
                <div className="bg-dev-card/30 border border-slate-700 rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-3">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      strokeWidth="1.5"
                      stroke="currentColor"
                      className="w-4 h-4 text-dev-green"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z"
                      />
                    </svg>
                    <span className="text-xs font-semibold text-slate-400 uppercase">
                      Box Model
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="space-y-1">
                      <span className="text-xs text-slate-500">Margin</span>
                      <div className="text-xs text-slate-300 font-mono bg-slate-800/50 px-2 py-1 rounded">
                        {elem.boxModel.margin}
                      </div>
                    </div>
                    <div className="space-y-1">
                      <span className="text-xs text-slate-500">Padding</span>
                      <div className="text-xs text-slate-300 font-mono bg-slate-800/50 px-2 py-1 rounded">
                        {elem.boxModel.padding}
                      </div>
                    </div>
                    <div className="space-y-1">
                      <span className="text-xs text-slate-500">Width</span>
                      <div className="text-xs text-slate-300 font-mono bg-slate-800/50 px-2 py-1 rounded">
                        {elem.boxModel.width}
                      </div>
                    </div>
                    <div className="space-y-1">
                      <span className="text-xs text-slate-500">Height</span>
                      <div className="text-xs text-slate-300 font-mono bg-slate-800/50 px-2 py-1 rounded">
                        {elem.boxModel.height}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Z-Index & Position */}
                <div className="bg-dev-card/30 border border-slate-700 rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-3">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      fill="none"
                      viewBox="0 0 24 24"
                      strokeWidth="1.5"
                      stroke="currentColor"
                      className="w-4 h-4 text-dev-green"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M6.429 9.75L2.25 12l4.179 2.25m0-4.5l5.571 3 5.571-3m-11.142 0L2.25 7.5 12 2.25l9.75 5.25-4.179 2.25m0 0L21.75 12l-4.179 2.25m0 0l4.179 2.25L12 21.75 2.25 16.5l4.179-2.25m11.142 0l-5.571 3-5.571-3"
                      />
                    </svg>
                    <span className="text-xs font-semibold text-slate-400 uppercase">
                      Position & Stacking
                    </span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-slate-500">Z-Index</span>
                      <span className="text-xs text-slate-300 font-mono">
                        {elem.zIndex}
                      </span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-slate-500">Position</span>
                      <span className="text-xs text-slate-300 font-mono">
                        {elem.position}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </section>

            {/* Inspection History */}
            {elementMetadataState.inspectionHistory.length > 0 && (
              <>
                <div className="h-px bg-slate-800"></div>

                <section className="space-y-2 relative z-0">
                  <div className="flex items-center justify-between">
                    <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold">
                      Recent Inspections
                    </h2>
                    <button
                      onClick={clearHistory}
                      className="text-xs text-slate-500 hover:text-dev-green transition-colors"
                    >
                      Clear
                    </button>
                  </div>
                  <div className="bg-dev-card/30 border border-slate-700 rounded-lg overflow-hidden max-h-48 overflow-y-auto custom-scrollbar">
                    {elementMetadataState.inspectionHistory.map((item, idx) => (
                      <div
                        key={idx}
                        onClick={() => loadInspection(item)}
                        className="flex items-center justify-between p-2 border-b border-slate-700/50 last:border-b-0 hover:bg-slate-800/50 hover:border-dev-green/40 transition-colors cursor-pointer group"
                      >
                        <div className="flex items-center gap-2">
                          <div className="w-1.5 h-1.5 rounded-full bg-dev-green group-hover:shadow-[0_0_6px_rgba(0,230,0,0.6)] transition-shadow"></div>
                          <code className="text-xs text-slate-300 group-hover:text-dev-green font-mono transition-colors">
                            {item.selector}
                          </code>
                        </div>
                        <span className="text-xs text-slate-600 group-hover:text-slate-500 transition-colors">
                          {new Date(item.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    ))}
                  </div>
                </section>
              </>
            )}
          </>
        ) : (
          elementMetadataState.isActive && (
            <>
              <div className="h-px bg-slate-800"></div>
              <div className="bg-dev-card/30 border border-slate-700 rounded-lg p-6 text-center">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-dev-green/10 border border-dev-green/20 mb-3">
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    fill="none"
                    viewBox="0 0 24 24"
                    strokeWidth="1.5"
                    stroke="currentColor"
                    className="w-6 h-6 text-dev-green"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      d="M15.042 21.672L13.684 16.6m0 0l-2.51 2.225.569-9.47 5.227 7.917-3.286-.672zM12 2.25V4.5m5.834.166l-1.591 1.591M20.25 10.5H18M7.757 14.743l-1.59 1.59M6 10.5H3.75m4.007-4.243l-1.59-1.59"
                    />
                  </svg>
                </div>
                <p className="text-sm text-slate-400 mb-1">
                  <strong className="text-dev-green">Click</strong> on any element to inspect it
                </p>
                <p className="text-xs text-slate-600">
                  Typography, Colors, Box Model & Position data will appear here
                </p>
              </div>
            </>
          )
        )}
      </main>
    </div>
  );
};
