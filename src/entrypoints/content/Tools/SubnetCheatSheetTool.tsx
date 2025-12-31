import React from 'react';
import type { SubnetCheatSheetData } from './tool-types';

const SUBNETS = [
  { prefix: 32, mask: '255.255.255.255', hosts: 1, hex: 'FFFFFFFF' },
  { prefix: 31, mask: '255.255.255.254', hosts: 2, hex: 'FFFFFFFE' },
  { prefix: 30, mask: '255.255.255.252', hosts: 2, hex: 'FFFFFFFC' },
  { prefix: 29, mask: '255.255.255.248', hosts: 6, hex: 'FFFFFFF8' },
  { prefix: 28, mask: '255.255.255.240', hosts: 14, hex: 'FFFFFFF0' },
  { prefix: 27, mask: '255.255.255.224', hosts: 30, hex: 'FFFFFFE0' },
  { prefix: 26, mask: '255.255.255.192', hosts: 62, hex: 'FFFFFFC0' },
  { prefix: 25, mask: '255.255.255.128', hosts: 126, hex: 'FFFFFF80' },
  { prefix: 24, mask: '255.255.255.0', hosts: 254, hex: 'FFFFFF00' },
  { prefix: 23, mask: '255.255.254.0', hosts: 510, hex: 'FFFFFE00' },
  { prefix: 22, mask: '255.255.252.0', hosts: 1022, hex: 'FFFFFC00' },
  { prefix: 21, mask: '255.255.248.0', hosts: 2046, hex: 'FFFFF800' },
  { prefix: 20, mask: '255.255.240.0', hosts: 4094, hex: 'FFFFF000' },
  { prefix: 19, mask: '255.255.224.0', hosts: 8190, hex: 'FFFFE000' },
  { prefix: 18, mask: '255.255.192.0', hosts: 16382, hex: 'FFFFC000' },
  { prefix: 17, mask: '255.255.128.0', hosts: 32766, hex: 'FFFF8000' },
  { prefix: 16, mask: '255.255.0.0', hosts: 65534, hex: 'FFFF0000' },
  { prefix: 8, mask: '255.0.0.0', hosts: 16777214, hex: 'FF000000' },
];

type Props = {
  data: SubnetCheatSheetData | undefined;
  onChange: (next: SubnetCheatSheetData) => void;
};

const SubnetCheatSheetToolComponent = ({ data, onChange }: Props) => {
  const selectedPrefix = data?.selectedPrefix;

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Subnet Mask Cheat Sheet</div>

      <div className="overflow-y-auto max-h-64">
        <table className="w-full text-[10px]">
          <thead className="bg-slate-800 sticky top-0">
            <tr>
              <th className="px-2 py-1 text-left text-slate-400">CIDR</th>
              <th className="px-2 py-1 text-left text-slate-400">Decimal</th>
              <th className="px-2 py-1 text-left text-slate-400">Hex</th>
              <th className="px-2 py-1 text-right text-slate-400">Hosts</th>
            </tr>
          </thead>
          <tbody>
            {SUBNETS.map((s) => (
              <tr
                key={s.prefix}
                onClick={() => onChange({ selectedPrefix: s.prefix })}
                className={`cursor-pointer hover:bg-slate-700 ${selectedPrefix === s.prefix ? 'bg-emerald-900/30' : ''}`}
              >
                <td className="px-2 py-1 text-emerald-400 font-mono">/{s.prefix}</td>
                <td className="px-2 py-1 text-slate-300 font-mono">{s.mask}</td>
                <td className="px-2 py-1 text-cyan-400 font-mono">{s.hex}</td>
                <td className="px-2 py-1 text-right text-slate-300">{s.hosts.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="text-[10px] text-slate-500">
        Click a row to select. Common subnet masks with CIDR notation, decimal, and hexadecimal formats.
      </div>
    </div>
  );
};

export class SubnetCheatSheetTool {
  static Component = SubnetCheatSheetToolComponent;
}
