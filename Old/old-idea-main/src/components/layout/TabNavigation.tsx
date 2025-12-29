import React from 'react';
import type { TabCategory } from '@/types';

interface TabNavigationProps {
  activeTab: TabCategory;
  onTabChange: (tab: TabCategory) => void;
}

export const TabNavigation: React.FC<TabNavigationProps> = ({ activeTab, onTabChange }) => {
  const tabs: Array<{ id: TabCategory; label: string }> = [
    { id: 'frontend', label: 'Front End' },
    { id: 'backend', label: 'Back End' },
    { id: 'other', label: 'Other' },
    { id: 'features', label: 'Features' },
  ];

  return (
    <nav className="flex px-5 pt-4 pb-0 gap-6 text-sm font-medium border-b border-slate-800/50 shrink-0 bg-dev-dark z-10">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onTabChange(tab.id)}
          className={`relative pb-3 transition-colors ${
            activeTab === tab.id
              ? 'text-white'
              : 'text-slate-500 hover:text-slate-300'
          }`}
        >
          {tab.label}
          <span
            className={`absolute bottom-0 left-0 h-0.5 rounded-t-full transition-all ${
              activeTab === tab.id
                ? 'w-full bg-dev-green shadow-[0_0_10px_0_rgba(0,230,0,0.6)]'
                : 'w-0 bg-slate-600 group-hover:w-full'
            }`}
          />
        </button>
      ))}
    </nav>
  );
};
