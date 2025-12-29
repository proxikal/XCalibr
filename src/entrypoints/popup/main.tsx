import React from 'react';
import ReactDOM from 'react-dom/client';
import '../../styles/index.css';

const Popup = () => {
  return (
    <div className="min-w-[280px] bg-slate-900 text-slate-200 p-4 font-sans">
      <div className="flex items-center gap-2 mb-3">
        <div className="w-6 h-6 rounded bg-blue-600 flex items-center justify-center">
          <span className="text-xs font-bold text-white">X</span>
        </div>
        <h1 className="text-sm font-semibold">XCalibr</h1>
      </div>
      <p className="text-xs text-slate-400 leading-relaxed">
        XCalibr lives directly on the page you are browsing. Look for the slim
        tab on the right edge of the website to open the full tool menu.
      </p>
      <p className="text-[11px] text-slate-500 mt-3">
        Tip: Press <span className="text-slate-200">Cmd+Shift+V</span> to hide
        or show the tab.
      </p>
    </div>
  );
};

const root = ReactDOM.createRoot(document.getElementById('root')!);
root.render(<Popup />);
