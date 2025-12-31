import React, { useCallback, useState } from 'react';
import type { MacVendorLookupData } from './tool-types';

// Common MAC vendor prefixes (OUI)
const VENDORS: Record<string, string> = {
  '00:00:0C': 'Cisco Systems',
  '00:1A:2B': 'Cisco Systems',
  '00:50:56': 'VMware',
  '00:0C:29': 'VMware',
  '00:15:5D': 'Microsoft (Hyper-V)',
  '08:00:27': 'Oracle VirtualBox',
  '00:1C:42': 'Parallels',
  'AC:DE:48': 'Apple',
  '00:03:93': 'Apple',
  '00:1F:F3': 'Apple',
  '00:25:00': 'Apple',
  '7C:D1:C3': 'Apple',
  'D4:61:9D': 'Apple',
  '00:24:D7': 'Intel',
  '00:1E:67': 'Intel',
  '3C:97:0E': 'Intel',
  '00:1A:6B': 'Samsung',
  '00:26:37': 'Samsung',
  '78:47:1D': 'Samsung',
  '00:1E:58': 'Dell',
  'F0:4D:A2': 'Dell',
  '00:21:9B': 'Dell',
  '00:1D:09': 'HP',
  '00:25:B3': 'HP',
  '3C:D9:2B': 'HP',
  '00:1C:C0': 'Lenovo',
  '00:26:6C': 'Lenovo',
  'D0:BF:9C': 'Lenovo',
  '00:1B:21': 'Netgear',
  '00:1E:2A': 'Netgear',
  '00:14:6C': 'Netgear',
  '00:1D:7E': 'Cisco-Linksys',
  '00:1A:70': 'Cisco-Linksys',
  'B4:75:0E': 'TP-Link',
  '14:CF:92': 'TP-Link',
  '00:23:CD': 'TP-Link',
  '00:1F:33': 'TP-Link',
  'EC:08:6B': 'TP-Link',
  '00:0D:B9': 'Google',
  '00:1A:11': 'Google',
  '94:EB:2C': 'Google',
  'F4:F5:D8': 'Google',
  '18:B4:30': 'Nest Labs',
  '64:16:66': 'Nest Labs',
};

const formatMac = (mac: string): string => {
  const clean = mac.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
  if (clean.length < 6) return mac;
  return clean.match(/.{2}/g)?.join(':') || mac;
};

const lookupVendor = (mac: string): string | null => {
  const formatted = formatMac(mac);
  const prefix = formatted.substring(0, 8);
  return VENDORS[prefix] || null;
};

type Props = {
  data: MacVendorLookupData | undefined;
  onChange: (next: MacVendorLookupData) => void;
};

const MacVendorLookupToolComponent = ({ data, onChange }: Props) => {
  const mac = data?.mac ?? '';
  const vendor = data?.vendor ?? '';
  const error = data?.error ?? '';

  const handleLookup = useCallback(() => {
    const formatted = formatMac(mac);
    if (formatted.length < 8) {
      onChange({ ...data, error: 'Enter at least 6 hex characters', vendor: '' });
      return;
    }

    const result = lookupVendor(formatted);
    if (result) {
      onChange({ ...data, mac: formatted, vendor: result, error: '' });
    } else {
      onChange({ ...data, mac: formatted, vendor: '', error: 'Vendor not found in local database' });
    }
  }, [mac, data, onChange]);

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">MAC Address Vendor Lookup</div>

      <div className="space-y-1">
        <div className="text-[11px] text-slate-400">MAC Address</div>
        <input
          type="text"
          value={mac}
          onChange={(e) => onChange({ ...data, mac: e.target.value, vendor: '', error: '' })}
          className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500 font-mono"
          placeholder="00:1A:2B:3C:4D:5E or 001A2B3C4D5E"
        />
      </div>

      <button
        type="button"
        onClick={handleLookup}
        className="w-full rounded bg-emerald-600 text-white text-xs py-2 hover:bg-emerald-500"
      >
        Lookup Vendor
      </button>

      {vendor && (
        <div className="bg-emerald-900/30 border border-emerald-700 rounded p-3 text-center">
          <div className="text-[10px] text-slate-400">Manufacturer</div>
          <div className="text-emerald-400 text-sm font-medium">{vendor}</div>
        </div>
      )}

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded p-2 text-[10px] text-red-300">{error}</div>
      )}

      <div className="text-[10px] text-slate-500">
        Identifies the manufacturer from the OUI (first 6 hex digits) of a MAC address.
      </div>
    </div>
  );
};

export class MacVendorLookupTool {
  static Component = MacVendorLookupToolComponent;
}
