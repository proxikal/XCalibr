import React, { useCallback } from 'react';
import type { CidrCalculatorData } from './tool-types';

const ipToInt = (ip: string): number => {
  const parts = ip.split('.').map(Number);
  return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
};

const intToIp = (num: number): string => {
  return [
    (num >>> 24) & 255,
    (num >>> 16) & 255,
    (num >>> 8) & 255,
    num & 255
  ].join('.');
};

const calculateCidr = (cidr: string): CidrCalculatorData => {
  const match = cidr.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if (!match) return { error: 'Invalid CIDR format (e.g., 192.168.1.0/24)' };

  const [, ip, prefixStr] = match;
  const prefix = parseInt(prefixStr, 10);
  if (prefix < 0 || prefix > 32) return { error: 'Prefix must be 0-32' };

  const parts = ip.split('.').map(Number);
  if (parts.some(p => p < 0 || p > 255)) return { error: 'Invalid IP address' };

  const ipInt = ipToInt(ip);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const wildcardInt = ~mask >>> 0;

  const networkInt = (ipInt & mask) >>> 0;
  const broadcastInt = (networkInt | wildcardInt) >>> 0;

  const networkAddress = intToIp(networkInt);
  const broadcastAddress = intToIp(broadcastInt);
  const netmask = intToIp(mask);
  const wildcardMask = intToIp(wildcardInt);

  const totalHosts = Math.pow(2, 32 - prefix);
  const usableHosts = prefix <= 30 ? totalHosts - 2 : prefix === 31 ? 2 : 1;

  const firstHost = prefix < 31 ? intToIp(networkInt + 1) : networkAddress;
  const lastHost = prefix < 31 ? intToIp(broadcastInt - 1) : broadcastAddress;

  return {
    cidr,
    networkAddress,
    broadcastAddress,
    netmask,
    wildcardMask,
    firstHost,
    lastHost,
    hosts: usableHosts,
    error: ''
  };
};

type Props = {
  data: CidrCalculatorData | undefined;
  onChange: (next: CidrCalculatorData) => void;
};

const CidrCalculatorToolComponent = ({ data, onChange }: Props) => {
  const cidr = data?.cidr ?? '';
  const error = data?.error ?? '';

  const handleCalculate = useCallback(() => {
    const result = calculateCidr(cidr.trim());
    onChange({ ...data, ...result });
  }, [cidr, data, onChange]);

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">CIDR Calculator</div>

      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">CIDR Notation</div>
        <input
          type="text"
          value={cidr}
          onChange={(e) => onChange({ ...data, cidr: e.target.value, error: '' })}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
          placeholder="192.168.1.0/24"
        />
      </div>

      <button
        type="button"
        onClick={handleCalculate}
        className="w-full rounded bg-emerald-600 text-white text-xs py-2 hover:bg-emerald-500"
      >
        Calculate
      </button>

      {data?.networkAddress && (
        <div className="space-y-2 bg-slate-800 rounded p-3">
          <div className="grid grid-cols-2 gap-2 text-[10px]">
            <div><span className="text-slate-500">Network:</span> <span className="text-emerald-400 font-mono">{data.networkAddress}</span></div>
            <div><span className="text-slate-500">Broadcast:</span> <span className="text-emerald-400 font-mono">{data.broadcastAddress}</span></div>
            <div><span className="text-slate-500">Netmask:</span> <span className="text-cyan-400 font-mono">{data.netmask}</span></div>
            <div><span className="text-slate-500">Wildcard:</span> <span className="text-cyan-400 font-mono">{data.wildcardMask}</span></div>
            <div><span className="text-slate-500">First Host:</span> <span className="text-slate-300 font-mono">{data.firstHost}</span></div>
            <div><span className="text-slate-500">Last Host:</span> <span className="text-slate-300 font-mono">{data.lastHost}</span></div>
          </div>
          <div className="text-[11px] text-center border-t border-slate-700 pt-2">
            <span className="text-slate-400">Usable Hosts:</span>{' '}
            <span className="text-emerald-400 font-bold">{data.hosts?.toLocaleString()}</span>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded p-2 text-[10px] text-red-300">{error}</div>
      )}

      <div className="text-[10px] text-slate-500">
        Calculate network details from CIDR notation. Enter an IP with prefix (e.g., 10.0.0.0/8).
      </div>
    </div>
  );
};

export class CidrCalculatorTool {
  static Component = CidrCalculatorToolComponent;
}
