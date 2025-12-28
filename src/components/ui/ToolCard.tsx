import React from 'react';
import type { Tool } from '@/types';

interface ToolCardProps {
  tool: Tool;
  isFavorite: boolean;
  onClick?: () => void;
  onToggleFavorite?: (e: React.MouseEvent) => void;
}

export const ToolCard: React.FC<ToolCardProps> = ({
  tool,
  isFavorite,
  onClick,
  onToggleFavorite,
}) => {
  return (
    <div
      className="group relative flex items-center justify-between p-3.5 bg-dev-card/50 hover:bg-slate-800/80 border border-slate-700/40 hover:border-dev-green/40 rounded-xl cursor-pointer transition-all duration-200 shadow-sm hover:shadow-[0_0_15px_-5px_rgba(0,230,0,0.1)]"
      onClick={onClick}
    >
      <div className="flex items-center gap-3.5">
        <div className="w-10 h-10 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 group-hover:text-dev-green group-hover:bg-dev-green/10 group-hover:border-dev-green/20 flex items-center justify-center transition-all duration-300">
          <div dangerouslySetInnerHTML={{ __html: tool.icon }} />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-slate-200 group-hover:text-white mb-0.5">
            {tool.name}
          </h3>
          <p className="text-[11px] leading-tight text-slate-500 group-hover:text-slate-400">
            {tool.description}
          </p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        {/* Favorite Button */}
        <button
          onClick={onToggleFavorite}
          className="p-1.5 rounded hover:bg-slate-700 transition-colors z-10"
          title={isFavorite ? 'Remove from favorites' : 'Add to favorites'}
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill={isFavorite ? 'currentColor' : 'none'}
            stroke="currentColor"
            strokeWidth={isFavorite ? '0' : '2'}
            className={`w-4 h-4 transition-colors ${
              isFavorite ? 'text-dev-green' : 'text-slate-600 hover:text-dev-green'
            }`}
          >
            <path
              fillRule="evenodd"
              d="M10.788 3.21c.448-1.077 1.976-1.077 2.424 0l2.082 5.007 5.404.433c1.164.093 1.636 1.545.749 2.305l-4.117 3.527 1.257 5.273c.271 1.136-.964 2.033-1.96 1.425L12 18.354 7.373 21.18c-.996.608-2.231-.29-1.96-1.425l1.257-5.273-4.117-3.527c-.887-.76-.415-2.212.749-2.305l5.404-.433 2.082-5.006z"
              clipRule="evenodd"
            />
          </svg>
        </button>

        {/* Arrow Icon */}
        <div className="text-slate-600 group-hover:text-dev-green group-hover:translate-x-0.5 transition-all duration-200">
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
              d="M8.25 4.5l7.5 7.5-7.5 7.5"
            />
          </svg>
        </div>
      </div>
    </div>
  );
};
