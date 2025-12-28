import React from 'react';
import type { Tool } from '@/types';

interface ToolCardProps {
  tool: Tool;
  onClick?: () => void;
}

export const ToolCard: React.FC<ToolCardProps> = ({ tool, onClick }) => {
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
  );
};
