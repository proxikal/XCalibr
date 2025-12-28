/**
 * Live CSS Scratchpad Tool
 * Inject temporary CSS into pages for testing
 * Persists per domain with toggle functionality
 */

import React, { useEffect, useState } from 'react';
import { useCSSScratchpad } from '@/hooks/useFeatures';

export const LiveCSSScratchpad: React.FC = () => {
  const { cssScratchpadState, updateDomainCSS, toggleDomainCSS } = useCSSScratchpad();
  const [currentDomain, setCurrentDomain] = useState<string | null>(null);
  const [cssInput, setCssInput] = useState('');
  const [isConnected, setIsConnected] = useState(false);

  // Get current domain
  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.url) {
        try {
          const url = new URL(tabs[0].url);
          const domain = url.hostname;
          setCurrentDomain(domain);

          // Load existing CSS for this domain
          const domainData = cssScratchpadState.domains[domain];
          if (domainData) {
            setCssInput(domainData.css);
          } else {
            setCssInput('');
          }
        } catch (error) {
          console.error('Failed to parse URL:', error);
          setCurrentDomain(null);
        }
      }
    });
  }, [cssScratchpadState.domains]);

  // Check if content script is available
  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, { type: 'PING' }, () => {
          if (chrome.runtime.lastError) {
            setIsConnected(false);
          } else {
            setIsConnected(true);
          }
        });
      }
    });
  }, []);

  const handleInject = () => {
    if (!currentDomain) {
      alert('Cannot determine current domain');
      return;
    }

    if (!isConnected) {
      alert('Please reload the page to enable CSS injection');
      return;
    }

    // Save CSS to state
    updateDomainCSS(currentDomain, cssInput);

    // Inject CSS into page
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'INJECT_CSS',
          data: {
            css: cssInput,
            domain: currentDomain,
            id: `xcalibr-css-${currentDomain}`,
          },
        });
      }
    });
  };

  const handleRemove = () => {
    if (!currentDomain) return;

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.sendMessage(tabs[0].id, {
          type: 'REMOVE_CSS',
          data: {
            domain: currentDomain,
            id: `xcalibr-css-${currentDomain}`,
          },
        });
      }
    });

    // Clear from state
    updateDomainCSS(currentDomain, '');
    setCssInput('');
  };

  const handleToggle = () => {
    if (!currentDomain) return;

    const domainData = cssScratchpadState.domains[currentDomain];
    const willBeEnabled = !domainData?.enabled;

    toggleDomainCSS(currentDomain);

    if (willBeEnabled && domainData?.css) {
      // Re-inject CSS
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'INJECT_CSS',
            data: {
              css: domainData.css,
              domain: currentDomain,
              id: `xcalibr-css-${currentDomain}`,
            },
          });
        }
      });
    } else {
      // Remove CSS
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) {
          chrome.tabs.sendMessage(tabs[0].id, {
            type: 'REMOVE_CSS',
            data: {
              domain: currentDomain,
              id: `xcalibr-css-${currentDomain}`,
            },
          });
        }
      });
    }
  };

  const domainData = currentDomain ? cssScratchpadState.domains[currentDomain] : null;
  const isEnabled = domainData?.enabled ?? false;

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <main className="flex-1 overflow-y-auto p-5 space-y-6 custom-scrollbar relative">
        {/* Background Gradient */}
        <div className="fixed top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-dev-green/5 blur-3xl rounded-full pointer-events-none"></div>

        {/* Current Domain */}
        <section className="space-y-3 relative z-0">
          <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold">
            Current Domain
          </h2>
          <div className="bg-dev-card/50 border border-slate-700 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${isEnabled ? 'bg-dev-green' : 'bg-slate-600'}`}></div>
                <code className="text-sm text-dev-green font-mono">
                  {currentDomain || 'No domain detected'}
                </code>
              </div>
              {domainData && (
                <button
                  onClick={handleToggle}
                  className={`px-3 py-1 text-xs font-medium rounded transition-all ${
                    isEnabled
                      ? 'bg-dev-green/20 text-dev-green border border-dev-green/40'
                      : 'bg-slate-800 text-slate-400 border border-slate-600 hover:border-slate-500'
                  }`}
                >
                  {isEnabled ? 'Enabled' : 'Disabled'}
                </button>
              )}
            </div>
            {domainData?.lastModified && (
              <p className="text-xs text-slate-600 mt-2">
                Last modified: {new Date(domainData.lastModified).toLocaleString()}
              </p>
            )}
          </div>

          {!isConnected && (
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
              <p className="text-xs text-yellow-400">
                ⚠️ Page needs to be reloaded to enable CSS injection
              </p>
            </div>
          )}
        </section>

        {/* CSS Editor */}
        <section className="space-y-3 relative z-0">
          <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold">
            CSS Editor
          </h2>
          <div className="bg-dev-card/30 border border-slate-700 rounded-lg overflow-hidden">
            <textarea
              value={cssInput}
              onChange={(e) => setCssInput(e.target.value)}
              placeholder={`/* Enter CSS to inject into ${currentDomain || 'this domain'} */\n\nbody {\n  background: #000;\n}\n\n.my-class {\n  color: #00e600;\n}`}
              className="w-full h-64 p-4 bg-slate-900 text-slate-300 font-mono text-xs resize-none focus:outline-none focus:ring-2 focus:ring-dev-green/50"
              spellCheck={false}
            />
          </div>
        </section>

        {/* Actions */}
        <section className="space-y-2 relative z-0">
          <div className="flex gap-2">
            <button
              onClick={handleInject}
              disabled={!currentDomain || !cssInput.trim()}
              className="flex-1 bg-dev-green text-black hover:bg-[#00ff00] py-2.5 rounded-md text-sm font-bold shadow-[0_0_15px_rgba(0,230,0,0.3)] hover:shadow-[0_0_20px_rgba(0,230,0,0.5)] transition-all disabled:opacity-50 disabled:cursor-not-allowed disabled:shadow-none"
            >
              Inject CSS
            </button>
            <button
              onClick={handleRemove}
              disabled={!currentDomain || !domainData?.css}
              className="flex-1 bg-transparent border border-red-500/50 text-red-400 hover:bg-red-500/10 hover:border-red-500 py-2.5 rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Remove CSS
            </button>
          </div>
          <p className="text-xs text-slate-600 text-center">
            CSS persists per domain and survives page reloads
          </p>
        </section>

        {/* Domain List */}
        {Object.keys(cssScratchpadState.domains).length > 0 && (
          <>
            <div className="h-px bg-slate-800"></div>
            <section className="space-y-3 relative z-0">
              <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold">
                Saved Domains
              </h2>
              <div className="bg-dev-card/30 border border-slate-700 rounded-lg overflow-hidden max-h-48 overflow-y-auto custom-scrollbar">
                {Object.entries(cssScratchpadState.domains).map(([domain, data]) => (
                  <div
                    key={domain}
                    className="flex items-center justify-between p-3 border-b border-slate-700/50 last:border-b-0 hover:bg-slate-800/50 transition-colors"
                  >
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      <div
                        className={`w-1.5 h-1.5 rounded-full ${data.enabled ? 'bg-dev-green' : 'bg-slate-600'}`}
                      ></div>
                      <code className="text-xs text-slate-300 font-mono truncate">{domain}</code>
                    </div>
                    <span className="text-xs text-slate-600">
                      {data.css.split('\n').length} lines
                    </span>
                  </div>
                ))}
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  );
};
