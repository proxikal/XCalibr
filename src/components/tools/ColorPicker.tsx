/**
 * Color Picker Tool
 * Extract colors from page elements with hover preview
 */

import React, { useEffect, useState } from 'react';
import { useColorPicker } from '@/hooks/useAppStore';

export const ColorPicker: React.FC = () => {
  const {
    colorPickerState,
    setActive,
    addColor,
    removeColor,
    clearColors,
  } = useColorPicker();

  const [isConnected, setIsConnected] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Check for pending colors on mount
  useEffect(() => {
    chrome.storage.local.get(['xcalibr_pending_colors'], (result) => {
      const pendingColors = result.xcalibr_pending_colors;
      if (pendingColors && Array.isArray(pendingColors) && pendingColors.length > 0) {
        console.log('Loading pending colors:', pendingColors);
        // Add all pending colors to state
        pendingColors.forEach((colorData) => {
          addColor(colorData);
        });
        // Clear pending colors from storage
        chrome.storage.local.remove('xcalibr_pending_colors');
      }
    });
  }, [addColor]);

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

  // Listen for color picked messages from content script
  useEffect(() => {
    const handleMessage = (
      message: any,
      _sender: chrome.runtime.MessageSender
    ) => {
      if (message.type === 'COLOR_PICKED') {
        console.log('Received color picked:', message.data);
        addColor(message.data);
      }
    };

    chrome.runtime.onMessage.addListener(handleMessage);

    return () => {
      chrome.runtime.onMessage.removeListener(handleMessage);
    };
  }, [addColor]);

  // Sync state with content script when toggling
  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'TOGGLE_COLOR_PICKER',
          data: { isActive: colorPickerState.isActive },
        });
      }
    });
  }, [colorPickerState.isActive]);

  const handleActivate = () => {
    if (!isConnected) {
      alert('Please reload the page to enable Color Picker');
      return;
    }
    setActive(true);
  };

  const handleDeactivate = () => {
    setActive(false);
  };

  const handleEmbedToSite = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'EMBED_TOOL',
          data: { toolId: 'color-picker' },
        });
      }
    });
  };

  const handleCopyColor = (_format: string, value: string, id: string) => {
    navigator.clipboard.writeText(value);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <main className="flex-1 overflow-y-auto p-5 space-y-6 custom-scrollbar relative">
        {/* Background Gradient */}
        <div className="fixed top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-dev-green/5 blur-3xl rounded-full pointer-events-none"></div>

        {/* Status Section */}
        <section className="space-y-3 relative z-0">
          <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-2">
            Color Picker Status
          </h2>

          <div className="bg-dev-card/50 border border-slate-700 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div
                  className={`w-2 h-2 rounded-full ${
                    colorPickerState.isActive ? 'bg-dev-green' : 'bg-slate-600'
                  }`}
                ></div>
                <span className="text-sm font-medium text-slate-200">
                  {colorPickerState.isActive ? 'Active' : 'Inactive'}
                </span>
              </div>
            </div>
            <p className="text-xs text-slate-500 mb-4">
              Hover over any element to preview its color. <strong className="text-dev-green">Click</strong> to pick and save the color to your palette.
            </p>
            <div className="flex gap-2 mb-3">
              {!colorPickerState.isActive ? (
                <button
                  onClick={handleActivate}
                  className="flex-1 bg-dev-green text-black hover:bg-[#00ff00] py-2 rounded-md text-sm font-bold shadow-[0_0_15px_rgba(0,230,0,0.3)] hover:shadow-[0_0_20px_rgba(0,230,0,0.5)] transition-all"
                >
                  Activate Color Picker
                </button>
              ) : (
                <button
                  onClick={handleDeactivate}
                  className="flex-1 bg-transparent border border-slate-600 text-slate-300 hover:text-white hover:border-slate-400 py-2 rounded-md text-sm font-medium transition-colors"
                >
                  Deactivate Color Picker
                </button>
              )}
            </div>
            <button
              onClick={handleEmbedToSite}
              className="w-full bg-slate-800 border border-dev-green/50 text-dev-green hover:bg-slate-700 hover:border-dev-green py-2 rounded-md text-sm font-medium transition-all flex items-center justify-center gap-2"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                strokeWidth="2"
                stroke="currentColor"
                className="w-4 h-4"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M9 8.25H7.5a2.25 2.25 0 00-2.25 2.25v9a2.25 2.25 0 002.25 2.25h9a2.25 2.25 0 002.25-2.25v-9a2.25 2.25 0 00-2.25-2.25H15m0-3l-3-3m0 0l-3 3m3-3V15"
                />
              </svg>
              Embed Tool to Site
            </button>

            {!isConnected && (
              <div className="mt-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
                <p className="text-xs text-yellow-400">
                  ⚠️ Page needs to be reloaded to activate this feature
                </p>
              </div>
            )}
          </div>
        </section>

        {/* Picked Colors */}
        {colorPickerState.pickedColors.length > 0 && (
          <>
            <div className="h-px bg-slate-800"></div>

            <section className="space-y-3 relative z-0">
              <div className="flex items-center justify-between">
                <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold">
                  Saved Colors ({colorPickerState.pickedColors.length})
                </h2>
                <button
                  onClick={clearColors}
                  className="text-xs text-slate-500 hover:text-dev-green transition-colors"
                >
                  Clear All
                </button>
              </div>

              <div className="space-y-2">
                {colorPickerState.pickedColors.map((color) => (
                  <div
                    key={color.id}
                    className="bg-dev-card/30 border border-slate-700 rounded-lg p-3 hover:border-dev-green/40 transition-colors"
                  >
                    <div className="flex items-center gap-3 mb-3">
                      <div
                        className="w-12 h-12 rounded-md border border-slate-600 flex-shrink-0"
                        style={{ backgroundColor: color.hex }}
                      ></div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium text-slate-200">
                            {color.hex.toUpperCase()}
                          </span>
                          <button
                            onClick={() => removeColor(color.id)}
                            className="text-slate-500 hover:text-red-400 transition-colors"
                          >
                            <svg
                              xmlns="http://www.w3.org/2000/svg"
                              fill="none"
                              viewBox="0 0 24 24"
                              strokeWidth="1.5"
                              stroke="currentColor"
                              className="w-4 h-4"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                d="M6 18L18 6M6 6l12 12"
                              />
                            </svg>
                          </button>
                        </div>
                        <p className="text-xs text-slate-600">
                          {new Date(color.timestamp).toLocaleString()}
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      {/* HEX */}
                      <button
                        onClick={() => handleCopyColor('HEX', color.hex, color.id)}
                        className="bg-slate-800/50 border border-slate-700 rounded px-2 py-1.5 hover:border-dev-green transition-colors group"
                      >
                        <div className="text-[10px] text-slate-500 mb-0.5">HEX</div>
                        <div className="text-xs text-slate-300 font-mono group-hover:text-dev-green transition-colors">
                          {copiedId === color.id ? '✓ Copied!' : color.hex}
                        </div>
                      </button>

                      {/* RGB */}
                      <button
                        onClick={() => handleCopyColor('RGB', color.rgb, color.id)}
                        className="bg-slate-800/50 border border-slate-700 rounded px-2 py-1.5 hover:border-dev-green transition-colors group"
                      >
                        <div className="text-[10px] text-slate-500 mb-0.5">RGB</div>
                        <div className="text-xs text-slate-300 font-mono group-hover:text-dev-green transition-colors truncate">
                          {copiedId === color.id ? '✓ Copied!' : color.rgb}
                        </div>
                      </button>

                      {/* RGBA */}
                      <button
                        onClick={() => handleCopyColor('RGBA', color.rgba, color.id)}
                        className="bg-slate-800/50 border border-slate-700 rounded px-2 py-1.5 hover:border-dev-green transition-colors group"
                      >
                        <div className="text-[10px] text-slate-500 mb-0.5">RGBA</div>
                        <div className="text-xs text-slate-300 font-mono group-hover:text-dev-green transition-colors truncate">
                          {copiedId === color.id ? '✓ Copied!' : color.rgba}
                        </div>
                      </button>

                      {/* HSL */}
                      <button
                        onClick={() => handleCopyColor('HSL', color.hsl, color.id)}
                        className="bg-slate-800/50 border border-slate-700 rounded px-2 py-1.5 hover:border-dev-green transition-colors group"
                      >
                        <div className="text-[10px] text-slate-500 mb-0.5">HSL</div>
                        <div className="text-xs text-slate-300 font-mono group-hover:text-dev-green transition-colors truncate">
                          {copiedId === color.id ? '✓ Copied!' : color.hsl}
                        </div>
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </>
        )}

        {/* Empty State */}
        {colorPickerState.pickedColors.length === 0 && colorPickerState.isActive && (
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
                    d="M9.53 16.122a3 3 0 00-5.78 1.128 2.25 2.25 0 01-2.4 2.245 4.5 4.5 0 008.4-2.245c0-.399-.078-.78-.22-1.128zm0 0a15.998 15.998 0 003.388-1.62m-5.043-.025a15.994 15.994 0 011.622-3.395m3.42 3.42a15.995 15.995 0 004.764-4.648l3.876-5.814a1.151 1.151 0 00-1.597-1.597L14.146 6.32a16.001 16.001 0 00-4.649 4.763m3.42 3.42a6.776 6.776 0 00-3.42-3.42"
                  />
                </svg>
              </div>
              <p className="text-sm text-slate-400 mb-1">
                <strong className="text-dev-green">Click</strong> on any color to pick it
              </p>
              <p className="text-xs text-slate-600">
                Picked colors will appear here with all formats
              </p>
            </div>
          </>
        )}
      </main>
    </div>
  );
};
