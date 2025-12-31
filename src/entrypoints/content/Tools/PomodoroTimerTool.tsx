import React, { useRef, useEffect } from 'react';

export type PomodoroTimerData = {
  phase?: 'work' | 'break' | 'longBreak';
  remainingMs?: number;
  isRunning?: boolean;
  sessionsCompleted?: number;
  workDuration?: number; // minutes
  breakDuration?: number; // minutes
  longBreakDuration?: number; // minutes
  sessionsUntilLongBreak?: number;
};

type Props = {
  data: PomodoroTimerData | undefined;
  onChange: (data: PomodoroTimerData) => void;
};

const formatTime = (ms: number): string => {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
};

const PomodoroTimer: React.FC<Props> = ({ data, onChange }) => {
  const phase = data?.phase ?? 'work';
  const workDuration = data?.workDuration ?? 25;
  const breakDuration = data?.breakDuration ?? 5;
  const longBreakDuration = data?.longBreakDuration ?? 15;
  const sessionsUntilLongBreak = data?.sessionsUntilLongBreak ?? 4;
  const sessionsCompleted = data?.sessionsCompleted ?? 0;
  const isRunning = data?.isRunning ?? false;

  const getDefaultRemaining = () => {
    switch (phase) {
      case 'work': return workDuration * 60 * 1000;
      case 'break': return breakDuration * 60 * 1000;
      case 'longBreak': return longBreakDuration * 60 * 1000;
    }
  };

  const remainingMs = data?.remainingMs ?? getDefaultRemaining();
  const intervalRef = useRef<number | null>(null);
  const lastTickRef = useRef<number>(0);

  useEffect(() => {
    if (isRunning && remainingMs > 0) {
      lastTickRef.current = Date.now();
      intervalRef.current = window.setInterval(() => {
        const now = Date.now();
        const delta = now - lastTickRef.current;
        lastTickRef.current = now;
        const newRemaining = Math.max(0, remainingMs - delta);
        onChange({ ...data, remainingMs: newRemaining });
      }, 100);
    } else {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [isRunning, remainingMs > 0]);

  useEffect(() => {
    if (remainingMs <= 0 && isRunning) {
      // Phase complete
      if (phase === 'work') {
        const newSessions = sessionsCompleted + 1;
        const isLongBreak = newSessions % sessionsUntilLongBreak === 0;
        onChange({
          ...data,
          isRunning: false,
          sessionsCompleted: newSessions,
          phase: isLongBreak ? 'longBreak' : 'break',
          remainingMs: isLongBreak ? longBreakDuration * 60 * 1000 : breakDuration * 60 * 1000
        });
      } else {
        onChange({
          ...data,
          isRunning: false,
          phase: 'work',
          remainingMs: workDuration * 60 * 1000
        });
      }
    }
  }, [remainingMs, isRunning]);

  const handleStartPause = () => {
    onChange({ ...data, isRunning: !isRunning });
  };

  const handleReset = () => {
    onChange({
      ...data,
      isRunning: false,
      remainingMs: getDefaultRemaining()
    });
  };

  const handleSkip = () => {
    if (phase === 'work') {
      const isLongBreak = (sessionsCompleted + 1) % sessionsUntilLongBreak === 0;
      onChange({
        ...data,
        isRunning: false,
        sessionsCompleted: sessionsCompleted + 1,
        phase: isLongBreak ? 'longBreak' : 'break',
        remainingMs: isLongBreak ? longBreakDuration * 60 * 1000 : breakDuration * 60 * 1000
      });
    } else {
      onChange({
        ...data,
        isRunning: false,
        phase: 'work',
        remainingMs: workDuration * 60 * 1000
      });
    }
  };

  const phaseColors = {
    work: 'text-red-400',
    break: 'text-green-400',
    longBreak: 'text-blue-400'
  };

  const phaseLabels = {
    work: 'Focus Time',
    break: 'Short Break',
    longBreak: 'Long Break'
  };

  return (
    <div className="space-y-4">
      <div className={`text-center ${phaseColors[phase]}`}>
        <div className="text-sm font-medium">{phaseLabels[phase]}</div>
        <div className="text-5xl font-mono mt-2">{formatTime(remainingMs)}</div>
      </div>

      <div className="flex justify-center gap-1">
        {Array.from({ length: sessionsUntilLongBreak }).map((_, i) => (
          <div
            key={i}
            className={`w-3 h-3 rounded-full ${
              i < (sessionsCompleted % sessionsUntilLongBreak)
                ? 'bg-red-500'
                : 'bg-gray-600'
            }`}
          />
        ))}
      </div>

      <div className="text-center text-xs text-gray-400">
        Sessions completed: {sessionsCompleted}
      </div>

      <div className="flex gap-2">
        <button
          onClick={handleStartPause}
          className={`flex-1 py-2 rounded text-sm ${
            isRunning
              ? 'bg-yellow-600 hover:bg-yellow-500 text-white'
              : 'bg-green-600 hover:bg-green-500 text-white'
          }`}
        >
          {isRunning ? 'Pause' : 'Start'}
        </button>
        <button
          onClick={handleReset}
          className="flex-1 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded text-sm"
        >
          Reset
        </button>
        <button
          onClick={handleSkip}
          className="flex-1 py-2 bg-purple-600 hover:bg-purple-500 text-white rounded text-sm"
        >
          Skip
        </button>
      </div>

      {!isRunning && (
        <div className="space-y-2 pt-2 border-t border-gray-700">
          <div className="text-xs text-gray-400">Settings (minutes)</div>
          <div className="grid grid-cols-3 gap-2">
            <div>
              <label className="block text-xs text-gray-500">Work</label>
              <input
                type="number"
                value={workDuration}
                onChange={(e) => onChange({ ...data, workDuration: parseInt(e.target.value) || 25 })}
                min={1}
                max={60}
                className="w-full px-2 py-1 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-500">Break</label>
              <input
                type="number"
                value={breakDuration}
                onChange={(e) => onChange({ ...data, breakDuration: parseInt(e.target.value) || 5 })}
                min={1}
                max={30}
                className="w-full px-2 py-1 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-500">Long</label>
              <input
                type="number"
                value={longBreakDuration}
                onChange={(e) => onChange({ ...data, longBreakDuration: parseInt(e.target.value) || 15 })}
                min={1}
                max={60}
                className="w-full px-2 py-1 bg-[#1a1a2e] border border-gray-700 rounded text-white text-sm"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export class PomodoroTimerTool {
  static Component = PomodoroTimer;
}
