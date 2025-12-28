/**
 * SearchBar Component
 * Provides search input and favorites filter toggle
 */

import React from 'react';
import { useUIState } from '@/hooks/useAppStore';

export const SearchBar: React.FC = () => {
  const { uiState, setSearchQuery, setShowFavoritesOnly } = useUIState();

  return (
    <div className="px-4 pt-3 pb-2 bg-dev-dark space-y-3">
      {/* Search Input */}
      <div className="relative">
        <input
          type="text"
          placeholder="Search tools..."
          value={uiState.searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full bg-dev-card border border-slate-700 rounded-md pl-9 pr-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-dev-green/50 focus:ring-1 focus:ring-dev-green/50 transition-all"
        />
        {/* Search Icon */}
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
          strokeWidth="2"
          stroke="currentColor"
          className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"
          />
        </svg>
        {/* Clear Button */}
        {uiState.searchQuery && (
          <button
            onClick={() => setSearchQuery('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
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
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        )}
      </div>

      {/* Favorites Toggle */}
      <label className="checkbox-wrapper flex items-center gap-3 cursor-pointer group">
        <input
          type="checkbox"
          checked={uiState.showFavoritesOnly}
          onChange={(e) => setShowFavoritesOnly(e.target.checked)}
          className="hidden"
        />
        <div className={`w-5 h-5 rounded border flex items-center justify-center transition-colors group-hover:border-slate-500 ${
          uiState.showFavoritesOnly
            ? 'bg-dev-green border-dev-green'
            : 'border-slate-600 bg-slate-800'
        }`}>
          <svg
            className={`w-3.5 h-3.5 text-black transition-opacity ${
              uiState.showFavoritesOnly ? 'opacity-100' : 'opacity-0'
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
        <div className="flex items-center gap-1.5">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="currentColor"
            className={`w-4 h-4 transition-colors ${
              uiState.showFavoritesOnly ? 'text-dev-green' : 'text-slate-500'
            }`}
          >
            <path
              fillRule="evenodd"
              d="M10.788 3.21c.448-1.077 1.976-1.077 2.424 0l2.082 5.007 5.404.433c1.164.093 1.636 1.545.749 2.305l-4.117 3.527 1.257 5.273c.271 1.136-.964 2.033-1.96 1.425L12 18.354 7.373 21.18c-.996.608-2.231-.29-1.96-1.425l1.257-5.273-4.117-3.527c-.887-.76-.415-2.212.749-2.305l5.404-.433 2.082-5.006z"
              clipRule="evenodd"
            />
          </svg>
          <span className={`text-sm transition-colors group-hover:text-white ${
            uiState.showFavoritesOnly ? 'text-dev-green font-medium' : 'text-slate-300'
          }`}>
            Show favorites only
          </span>
        </div>
      </label>
    </div>
  );
};
