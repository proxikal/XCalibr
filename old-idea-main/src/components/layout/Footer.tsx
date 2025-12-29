import React from 'react';

export const Footer: React.FC = () => {
  const handleClick = (action: string) => {
    console.log(`Footer action: ${action}`);
    if (action === 'feedback') {
      chrome.tabs.create({
        url: 'https://github.com/proxikal/XCalibr/issues',
      });
    }
    // TODO: Implement other actions
  };

  return (
    <footer className="px-5 py-3 border-t border-slate-800 bg-dev-darker text-[10px] uppercase tracking-wider font-semibold text-slate-600 flex justify-between items-center shrink-0">
      <span className="flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-dev-green"></span>
        XCalibr v1.0.2
      </span>
      <div className="flex gap-4">
        <a
          href="#"
          onClick={() => handleClick('settings')}
          className="hover:text-slate-300 transition-colors"
        >
          Settings
        </a>
        <a
          href="#"
          onClick={() => handleClick('feedback')}
          className="hover:text-slate-300 transition-colors"
        >
          Feedback
        </a>
      </div>
    </footer>
  );
};
