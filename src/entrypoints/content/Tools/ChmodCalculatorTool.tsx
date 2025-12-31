import React, { useMemo } from 'react';
import type { ChmodCalculatorData } from './tool-types';

type Props = {
  data: ChmodCalculatorData | undefined;
  onChange: (next: ChmodCalculatorData) => void;
};

const ChmodCalculatorToolComponent = ({ data, onChange }: Props) => {
  const perms = {
    ownerRead: data?.ownerRead ?? true,
    ownerWrite: data?.ownerWrite ?? true,
    ownerExecute: data?.ownerExecute ?? true,
    groupRead: data?.groupRead ?? true,
    groupWrite: data?.groupWrite ?? false,
    groupExecute: data?.groupExecute ?? true,
    publicRead: data?.publicRead ?? true,
    publicWrite: data?.publicWrite ?? false,
    publicExecute: data?.publicExecute ?? true,
  };

  const { octal, symbolic } = useMemo(() => {
    const owner = (perms.ownerRead ? 4 : 0) + (perms.ownerWrite ? 2 : 0) + (perms.ownerExecute ? 1 : 0);
    const group = (perms.groupRead ? 4 : 0) + (perms.groupWrite ? 2 : 0) + (perms.groupExecute ? 1 : 0);
    const pub = (perms.publicRead ? 4 : 0) + (perms.publicWrite ? 2 : 0) + (perms.publicExecute ? 1 : 0);

    const sym = [
      perms.ownerRead ? 'r' : '-', perms.ownerWrite ? 'w' : '-', perms.ownerExecute ? 'x' : '-',
      perms.groupRead ? 'r' : '-', perms.groupWrite ? 'w' : '-', perms.groupExecute ? 'x' : '-',
      perms.publicRead ? 'r' : '-', perms.publicWrite ? 'w' : '-', perms.publicExecute ? 'x' : '-',
    ].join('');

    return { octal: `${owner}${group}${pub}`, symbolic: sym };
  }, [perms]);

  const handleToggle = (key: keyof typeof perms) => {
    onChange({ ...data, [key]: !perms[key] });
  };

  const renderCheckbox = (label: string, key: keyof typeof perms) => (
    <label className="flex items-center gap-1 cursor-pointer">
      <input
        type="checkbox"
        checked={perms[key]}
        onChange={() => handleToggle(key)}
        className="w-3.5 h-3.5 rounded border-slate-600"
      />
      <span className="text-[10px] text-slate-300">{label}</span>
    </label>
  );

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Chmod Calculator</div>

      <div className="grid grid-cols-3 gap-3 bg-slate-800 rounded p-3">
        <div className="space-y-1">
          <div className="text-[10px] text-emerald-400 font-medium">Owner</div>
          {renderCheckbox('Read', 'ownerRead')}
          {renderCheckbox('Write', 'ownerWrite')}
          {renderCheckbox('Execute', 'ownerExecute')}
        </div>
        <div className="space-y-1">
          <div className="text-[10px] text-cyan-400 font-medium">Group</div>
          {renderCheckbox('Read', 'groupRead')}
          {renderCheckbox('Write', 'groupWrite')}
          {renderCheckbox('Execute', 'groupExecute')}
        </div>
        <div className="space-y-1">
          <div className="text-[10px] text-yellow-400 font-medium">Public</div>
          {renderCheckbox('Read', 'publicRead')}
          {renderCheckbox('Write', 'publicWrite')}
          {renderCheckbox('Execute', 'publicExecute')}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="bg-slate-800 rounded p-3 text-center">
          <div className="text-[10px] text-slate-400">Octal</div>
          <div className="text-emerald-400 font-mono text-xl">{octal}</div>
        </div>
        <div className="bg-slate-800 rounded p-3 text-center">
          <div className="text-[10px] text-slate-400">Symbolic</div>
          <div className="text-cyan-400 font-mono text-lg">{symbolic}</div>
        </div>
      </div>

      <div className="text-[10px] text-slate-500">
        chmod {octal} file.txt or chmod u=rwx,g=rx,o=rx file.txt
      </div>
    </div>
  );
};

export class ChmodCalculatorTool {
  static Component = ChmodCalculatorToolComponent;
}
