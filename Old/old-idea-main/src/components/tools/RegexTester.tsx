/**
 * Regex Tester Tool
 * Test and debug regular expressions with persistent state
 */

import React, { useState, useEffect } from 'react';
import { useRegexTester } from '@/hooks/useAppStore';

export const RegexTester: React.FC = () => {
  const {
    regexTesterState,
    setPattern,
    setTestString,
    setFlag,
    setMatches,
    setError,
    setReplacePattern,
    setReplaceResult,
    clearAll,
  } = useRegexTester();

  const [copied, setCopied] = useState(false);

  // Test regex and find matches
  useEffect(() => {
    if (!regexTesterState.pattern || !regexTesterState.testString) {
      setMatches([]);
      setError(null);
      return;
    }

    try {
      // Build flags string
      let flagsString = '';
      if (regexTesterState.flags.global) flagsString += 'g';
      if (regexTesterState.flags.multiline) flagsString += 'm';
      if (regexTesterState.flags.caseInsensitive) flagsString += 'i';
      if (regexTesterState.flags.dotAll) flagsString += 's';
      if (regexTesterState.flags.unicode) flagsString += 'u';
      if (regexTesterState.flags.sticky) flagsString += 'y';

      const regex = new RegExp(regexTesterState.pattern, flagsString);
      const matches: Array<{
        fullMatch: string;
        groups: string[];
        index: number;
      }> = [];

      if (regexTesterState.flags.global) {
        // Use matchAll for global flag
        const matchIterator = regexTesterState.testString.matchAll(regex);
        for (const match of matchIterator) {
          matches.push({
            fullMatch: match[0],
            groups: match.slice(1),
            index: match.index || 0,
          });
        }
      } else {
        // Use exec for non-global
        const match = regex.exec(regexTesterState.testString);
        if (match) {
          matches.push({
            fullMatch: match[0],
            groups: match.slice(1),
            index: match.index,
          });
        }
      }

      setMatches(matches);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid regular expression');
      setMatches([]);
    }
  }, [
    regexTesterState.pattern,
    regexTesterState.testString,
    regexTesterState.flags,
    setMatches,
    setError,
  ]);

  // Handle replace functionality
  const handleReplace = () => {
    if (!regexTesterState.pattern || !regexTesterState.testString) {
      return;
    }

    try {
      let flagsString = '';
      if (regexTesterState.flags.global) flagsString += 'g';
      if (regexTesterState.flags.multiline) flagsString += 'm';
      if (regexTesterState.flags.caseInsensitive) flagsString += 'i';
      if (regexTesterState.flags.dotAll) flagsString += 's';
      if (regexTesterState.flags.unicode) flagsString += 'u';
      if (regexTesterState.flags.sticky) flagsString += 'y';

      const regex = new RegExp(regexTesterState.pattern, flagsString);
      const result = regexTesterState.testString.replace(
        regex,
        regexTesterState.replacePattern
      );
      setReplaceResult(result);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Replace failed');
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const getFlagsString = () => {
    let flags = '';
    if (regexTesterState.flags.global) flags += 'g';
    if (regexTesterState.flags.multiline) flags += 'm';
    if (regexTesterState.flags.caseInsensitive) flags += 'i';
    if (regexTesterState.flags.dotAll) flags += 's';
    if (regexTesterState.flags.unicode) flags += 'u';
    if (regexTesterState.flags.sticky) flags += 'y';
    return flags || 'none';
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <main className="flex-1 overflow-y-auto p-5 space-y-6 custom-scrollbar relative">
        {/* Background Gradient */}
        <div className="fixed top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-dev-green/5 blur-3xl rounded-full pointer-events-none"></div>

        {/* Pattern Input Section */}
        <section className="space-y-3 relative z-0">
          <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-2">
            Regular Expression
          </h2>

          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-slate-400 text-lg font-mono">/</span>
              <input
                type="text"
                value={regexTesterState.pattern}
                onChange={(e) => setPattern(e.target.value)}
                placeholder="[A-Za-z0-9]+"
                className="flex-1 bg-dev-card border border-slate-700 rounded-md px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-dev-green/50 focus:ring-1 focus:ring-dev-green/50 transition-all font-mono"
              />
              <span className="text-slate-400 text-lg font-mono">/{getFlagsString()}</span>
            </div>

            {/* Flags */}
            <div className="grid grid-cols-3 gap-2">
              {[
                { key: 'global' as const, label: 'Global (g)', desc: 'Find all matches' },
                { key: 'multiline' as const, label: 'Multiline (m)', desc: '^$ match line breaks' },
                { key: 'caseInsensitive' as const, label: 'Case Insensitive (i)', desc: 'Ignore case' },
                { key: 'dotAll' as const, label: 'Dot All (s)', desc: '. matches newline' },
                { key: 'unicode' as const, label: 'Unicode (u)', desc: 'Unicode support' },
                { key: 'sticky' as const, label: 'Sticky (y)', desc: 'Match from lastIndex' },
              ].map((flag) => (
                <label
                  key={flag.key}
                  className="checkbox-wrapper flex items-center gap-2 cursor-pointer group"
                  title={flag.desc}
                >
                  <input
                    type="checkbox"
                    checked={regexTesterState.flags[flag.key]}
                    onChange={(e) => setFlag(flag.key, e.target.checked)}
                    className="hidden"
                  />
                  <div
                    className={`w-4 h-4 rounded border flex items-center justify-center transition-colors group-hover:border-slate-500 ${
                      regexTesterState.flags[flag.key]
                        ? 'bg-dev-green border-dev-green'
                        : 'border-slate-600 bg-slate-800'
                    }`}
                  >
                    <svg
                      className={`w-3 h-3 text-black transition-opacity ${
                        regexTesterState.flags[flag.key] ? 'opacity-100' : 'opacity-0'
                      }`}
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth="3"
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  </div>
                  <span className="text-xs text-slate-300 group-hover:text-white transition-colors">
                    {flag.label}
                  </span>
                </label>
              ))}
            </div>
          </div>
        </section>

        <div className="h-px bg-slate-800"></div>

        {/* Test String Section */}
        <section className="space-y-2 relative z-0">
          <div className="flex items-center justify-between">
            <label className="block text-sm font-medium text-slate-300">
              Test String
            </label>
            {regexTesterState.testString && (
              <button
                onClick={() => setTestString('')}
                className="text-xs text-slate-500 hover:text-dev-green transition-colors"
              >
                Clear
              </button>
            )}
          </div>
          <textarea
            value={regexTesterState.testString}
            onChange={(e) => setTestString(e.target.value)}
            placeholder="Enter text to test against your regex pattern..."
            className="w-full h-32 bg-dev-card border border-slate-700 rounded-md px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-dev-green/50 focus:ring-1 focus:ring-dev-green/50 transition-all font-mono resize-none"
          />
        </section>

        {/* Error Display */}
        {regexTesterState.error && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
            <div className="flex items-start gap-2">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
                strokeWidth="2"
                stroke="currentColor"
                className="w-5 h-5 text-red-500 shrink-0 mt-0.5"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
                />
              </svg>
              <div>
                <p className="text-sm font-medium text-red-400">Error</p>
                <p className="text-xs text-red-300/80 mt-1">
                  {regexTesterState.error}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Matches Display */}
        {regexTesterState.matches.length > 0 && (
          <section className="space-y-3 relative z-0">
            <div className="flex items-center justify-between">
              <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold">
                Matches ({regexTesterState.matches.length})
              </h2>
            </div>

            <div className="bg-dev-card/30 border border-slate-700 rounded-lg overflow-hidden">
              {regexTesterState.matches.map((match, idx) => (
                <div
                  key={idx}
                  className="border-b border-slate-700/50 last:border-b-0 p-3 hover:bg-slate-800/50 transition-colors"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 space-y-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-dev-green">
                          Match {idx + 1}
                        </span>
                        <span className="text-xs text-slate-500">
                          @ index {match.index}
                        </span>
                      </div>
                      <div className="bg-dev-darker border border-slate-700 rounded px-2 py-1.5">
                        <code className="text-sm text-dev-green font-mono break-all">
                          {match.fullMatch}
                        </code>
                      </div>
                      {match.groups.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-xs text-slate-500">Capture Groups:</span>
                          {match.groups.map((group, groupIdx) => (
                            <div
                              key={groupIdx}
                              className="flex items-center gap-2 ml-3"
                            >
                              <span className="text-xs text-slate-600">
                                ${groupIdx + 1}:
                              </span>
                              <code className="text-xs text-slate-300 font-mono">
                                {group || '(empty)'}
                              </code>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => copyToClipboard(match.fullMatch)}
                      className="text-slate-500 hover:text-dev-green transition-colors shrink-0"
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
                          d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"
                        />
                      </svg>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* No matches message */}
        {regexTesterState.pattern &&
          regexTesterState.testString &&
          !regexTesterState.error &&
          regexTesterState.matches.length === 0 && (
            <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-4 text-center">
              <p className="text-sm text-slate-400">No matches found</p>
            </div>
          )}

        <div className="h-px bg-slate-800"></div>

        {/* Replace Section */}
        <section className="space-y-3 relative z-0">
          <h2 className="text-xs uppercase tracking-wider text-slate-500 font-semibold mb-2">
            Replace
          </h2>

          <div className="space-y-2">
            <input
              type="text"
              value={regexTesterState.replacePattern}
              onChange={(e) => setReplacePattern(e.target.value)}
              placeholder="Replacement pattern (use $1, $2 for groups)"
              className="w-full bg-dev-card border border-slate-700 rounded-md px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-dev-green/50 focus:ring-1 focus:ring-dev-green/50 transition-all font-mono"
            />

            {regexTesterState.replaceResult && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="block text-sm font-medium text-slate-300">
                    Result
                  </label>
                  <button
                    onClick={() => copyToClipboard(regexTesterState.replaceResult)}
                    className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-dev-green transition-colors"
                  >
                    {copied ? (
                      <>
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          viewBox="0 0 24 24"
                          fill="currentColor"
                          className="w-3.5 h-3.5 text-dev-green"
                        >
                          <path
                            fillRule="evenodd"
                            d="M19.916 4.626a.75.75 0 01.208 1.04l-9 13.5a.75.75 0 01-1.154.114l-6-6a.75.75 0 011.06-1.06l5.353 5.353 8.493-12.739a.75.75 0 011.04-.208z"
                            clipRule="evenodd"
                          />
                        </svg>
                        Copied!
                      </>
                    ) : (
                      <>
                        <svg
                          xmlns="http://www.w3.org/2000/svg"
                          fill="none"
                          viewBox="0 0 24 24"
                          strokeWidth="2"
                          stroke="currentColor"
                          className="w-3.5 h-3.5"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"
                          />
                        </svg>
                        Copy
                      </>
                    )}
                  </button>
                </div>
                <pre className="w-full max-h-48 bg-dev-darker border border-slate-700 rounded-md px-3 py-2 text-sm text-dev-green overflow-auto font-mono custom-scrollbar">
                  {regexTesterState.replaceResult}
                </pre>
              </div>
            )}
          </div>
        </section>

        {/* Action Buttons */}
        <section className="pt-2 flex gap-3 relative z-0">
          <button
            onClick={clearAll}
            className="flex-1 bg-transparent border border-slate-600 text-slate-300 hover:text-white hover:border-slate-400 py-2 rounded-md text-sm font-medium transition-colors"
          >
            Clear All
          </button>
          <button
            onClick={handleReplace}
            disabled={
              !regexTesterState.pattern ||
              !regexTesterState.testString ||
              !regexTesterState.replacePattern
            }
            className="flex-1 bg-dev-green text-black hover:bg-[#00ff00] disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed py-2 rounded-md text-sm font-bold shadow-[0_0_15px_rgba(0,230,0,0.3)] hover:shadow-[0_0_20px_rgba(0,230,0,0.5)] transition-all"
          >
            Replace
          </button>
        </section>
      </main>
    </div>
  );
};
