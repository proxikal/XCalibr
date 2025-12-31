import React, { useState, useEffect } from 'react';

export type MathEvaluatorData = {
  expression?: string;
  result?: string;
  history?: { expr: string; result: string }[];
  error?: string;
};

type Props = {
  data: MathEvaluatorData | undefined;
  onChange: (data: MathEvaluatorData) => void;
};

// Safe math evaluation using Function constructor
const evaluateExpression = (expr: string): { result: string; error?: string } => {
  try {
    // Remove whitespace and validate characters
    const cleaned = expr.replace(/\s+/g, '');
    if (!cleaned) return { result: '' };

    // Only allow safe characters: numbers, operators, parentheses, decimal points
    if (!/^[\d+\-*/().%^]+$/.test(cleaned)) {
      return { result: '', error: 'Invalid characters in expression' };
    }

    // Replace ^ with ** for exponentiation
    const normalized = cleaned.replace(/\^/g, '**');

    // Use Function constructor for safe evaluation
    const fn = new Function(`return (${normalized})`);
    const result = fn();

    if (typeof result !== 'number' || !isFinite(result)) {
      if (result === Infinity) return { result: 'Infinity', error: 'Division by zero' };
      if (result === -Infinity) return { result: '-Infinity', error: 'Division by zero' };
      if (isNaN(result)) return { result: 'NaN', error: 'Invalid calculation' };
    }

    // Format result - handle floating point precision
    const formatted = Number.isInteger(result)
      ? result.toString()
      : parseFloat(result.toPrecision(10)).toString();

    return { result: formatted };
  } catch {
    return { result: '', error: 'Invalid expression' };
  }
};

const MathEvaluator: React.FC<Props> = ({ data, onChange }) => {
  const expression = data?.expression ?? '';
  const result = data?.result ?? '';
  const history = data?.history ?? [];
  const error = data?.error ?? '';
  const [liveResult, setLiveResult] = useState<{ result: string; error?: string }>({ result: '' });

  useEffect(() => {
    if (expression) {
      setLiveResult(evaluateExpression(expression));
    } else {
      setLiveResult({ result: '' });
    }
  }, [expression]);

  const handleEvaluate = () => {
    if (!expression.trim()) return;

    const evalResult = evaluateExpression(expression);
    if (evalResult.result && !evalResult.error) {
      const newHistory = [
        { expr: expression, result: evalResult.result },
        ...history.slice(0, 9) // Keep last 10
      ];
      onChange({
        ...data,
        result: evalResult.result,
        history: newHistory,
        error: ''
      });
    } else {
      onChange({ ...data, error: evalResult.error || 'Invalid expression' });
    }
  };

  const handleClear = () => {
    onChange({ ...data, expression: '', result: '', error: '' });
  };

  const handleClearHistory = () => {
    onChange({ ...data, history: [] });
  };

  const handleHistoryClick = (expr: string) => {
    onChange({ ...data, expression: expr });
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-gray-400 mb-1">Math Expression</label>
        <input
          type="text"
          value={expression}
          onChange={(e) => onChange({ ...data, expression: e.target.value, error: '' })}
          onKeyDown={(e) => e.key === 'Enter' && handleEvaluate()}
          placeholder="e.g., 5 * (10 + 2) or 2^8"
          className="w-full px-3 py-2 bg-[#1a1a2e] border border-gray-700 rounded text-white font-mono text-sm"
        />
      </div>

      {liveResult.result && !liveResult.error && (
        <div className="text-center py-4 bg-[#1a1a2e] rounded">
          <div className="text-3xl font-mono text-green-400">{liveResult.result}</div>
          <div className="text-xs text-gray-500 mt-1">Live result</div>
        </div>
      )}

      {liveResult.error && (
        <div className="text-red-400 text-xs bg-red-900/20 p-2 rounded">
          {liveResult.error}
        </div>
      )}

      <div className="flex gap-2">
        <button
          onClick={handleEvaluate}
          disabled={!expression.trim()}
          className="flex-1 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded text-sm"
        >
          = Calculate
        </button>
        <button
          onClick={handleClear}
          className="py-2 px-4 bg-gray-600 hover:bg-gray-500 text-white rounded text-sm"
        >
          Clear
        </button>
      </div>

      <div className="text-xs text-gray-500">
        Supported: + - * / % ^ ( ) | Examples: 2^8, 100%7, (5+3)*2
      </div>

      {history.length > 0 && (
        <div className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-xs text-gray-400">History</span>
            <button
              onClick={handleClearHistory}
              className="text-xs text-red-400 hover:text-red-300"
            >
              Clear
            </button>
          </div>
          <div className="max-h-24 overflow-y-auto space-y-1">
            {history.map((item, i) => (
              <button
                key={i}
                onClick={() => handleHistoryClick(item.expr)}
                className="w-full flex justify-between text-xs bg-[#1a1a2e] px-2 py-1 rounded hover:bg-gray-700"
              >
                <span className="text-gray-400 font-mono truncate">{item.expr}</span>
                <span className="text-green-400 font-mono ml-2">= {item.result}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export class MathEvaluatorTool {
  static Component = MathEvaluator;
}
