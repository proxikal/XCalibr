/**
 * Features Tab Component
 * Displays toggleable features with checkboxes
 */

import React, { useMemo } from 'react';
import { useFeatures } from '@/hooks/useFeatures';
import { Pagination } from './ui/Pagination';

export const FeaturesTab: React.FC = () => {
  const { featuresState, toggleFeature, setCurrentPage } = useFeatures();

  const itemsPerPage = 10;
  const totalPages = Math.ceil(featuresState.features.length / itemsPerPage);

  // Get paginated features
  const paginatedFeatures = useMemo(() => {
    const startIndex = (featuresState.currentPage - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    return featuresState.features.slice(startIndex, endIndex);
  }, [featuresState.features, featuresState.currentPage]);

  return (
    <main className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar relative">
      {/* Background Gradient */}
      <div className="fixed top-0 right-0 -mr-20 -mt-20 w-64 h-64 bg-dev-green/5 blur-3xl rounded-full pointer-events-none"></div>

      {/* Features List */}
      <div className="space-y-2 relative z-0">
        {paginatedFeatures.map((feature) => (
          <div
            key={feature.id}
            className="group flex items-center justify-between p-3 bg-dev-card/50 hover:bg-slate-800/80 border border-slate-700/40 hover:border-dev-green/40 rounded-lg cursor-pointer transition-all duration-200 shadow-sm hover:shadow-[0_0_15px_-5px_rgba(0,230,0,0.1)] h-[40px]"
            onClick={() => toggleFeature(feature.id)}
          >
            <div className="flex items-center gap-3">
              {/* Icon */}
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all duration-300 ${
                  feature.enabled
                    ? 'bg-dev-green/10 border border-dev-green/20 text-dev-green'
                    : 'bg-purple-500/10 border border-purple-500/20 text-purple-400 group-hover:text-dev-green group-hover:bg-dev-green/10 group-hover:border-dev-green/20'
                }`}
                dangerouslySetInnerHTML={{ __html: feature.icon }}
              />

              {/* Feature Info */}
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-slate-200 group-hover:text-white">
                  {feature.name}
                </h3>
                <span className="text-xs text-slate-500">—</span>
                <p className="text-xs text-slate-500 group-hover:text-slate-400">
                  {feature.description}
                </p>
              </div>
            </div>

            {/* Checkbox */}
            <label className="checkbox-wrapper flex items-center cursor-pointer" onClick={(e) => e.stopPropagation()}>
              <input
                type="checkbox"
                checked={feature.enabled}
                onChange={() => toggleFeature(feature.id)}
                className="hidden"
              />
              <div
                className={`w-5 h-5 rounded border flex items-center justify-center transition-colors ${
                  feature.enabled
                    ? 'bg-dev-green border-dev-green'
                    : 'border-slate-600 bg-slate-800 hover:border-slate-500'
                }`}
              >
                <svg
                  className={`w-3.5 h-3.5 text-black transition-opacity ${
                    feature.enabled ? 'opacity-100' : 'opacity-0'
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
            </label>
          </div>
        ))}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <Pagination
          currentPage={featuresState.currentPage}
          totalPages={totalPages}
          onPageChange={setCurrentPage}
          totalItems={featuresState.features.length}
          itemsPerPage={itemsPerPage}
        />
      )}
    </main>
  );
};
