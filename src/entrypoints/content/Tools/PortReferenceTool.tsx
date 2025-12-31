import React, { useMemo } from 'react';
import type { PortReferenceData } from './tool-types';

const COMMON_PORTS = [
  { port: 20, protocol: 'TCP', service: 'FTP Data', desc: 'File Transfer Protocol data transfer' },
  { port: 21, protocol: 'TCP', service: 'FTP', desc: 'File Transfer Protocol control' },
  { port: 22, protocol: 'TCP', service: 'SSH', desc: 'Secure Shell' },
  { port: 23, protocol: 'TCP', service: 'Telnet', desc: 'Unencrypted text communications' },
  { port: 25, protocol: 'TCP', service: 'SMTP', desc: 'Simple Mail Transfer Protocol' },
  { port: 53, protocol: 'TCP/UDP', service: 'DNS', desc: 'Domain Name System' },
  { port: 67, protocol: 'UDP', service: 'DHCP', desc: 'Dynamic Host Configuration (Server)' },
  { port: 68, protocol: 'UDP', service: 'DHCP', desc: 'Dynamic Host Configuration (Client)' },
  { port: 80, protocol: 'TCP', service: 'HTTP', desc: 'Hypertext Transfer Protocol' },
  { port: 110, protocol: 'TCP', service: 'POP3', desc: 'Post Office Protocol v3' },
  { port: 123, protocol: 'UDP', service: 'NTP', desc: 'Network Time Protocol' },
  { port: 143, protocol: 'TCP', service: 'IMAP', desc: 'Internet Message Access Protocol' },
  { port: 161, protocol: 'UDP', service: 'SNMP', desc: 'Simple Network Management Protocol' },
  { port: 443, protocol: 'TCP', service: 'HTTPS', desc: 'HTTP Secure' },
  { port: 445, protocol: 'TCP', service: 'SMB', desc: 'Server Message Block' },
  { port: 465, protocol: 'TCP', service: 'SMTPS', desc: 'SMTP over SSL' },
  { port: 587, protocol: 'TCP', service: 'SMTP', desc: 'SMTP submission' },
  { port: 993, protocol: 'TCP', service: 'IMAPS', desc: 'IMAP over SSL' },
  { port: 995, protocol: 'TCP', service: 'POP3S', desc: 'POP3 over SSL' },
  { port: 1433, protocol: 'TCP', service: 'MSSQL', desc: 'Microsoft SQL Server' },
  { port: 1521, protocol: 'TCP', service: 'Oracle', desc: 'Oracle Database' },
  { port: 3306, protocol: 'TCP', service: 'MySQL', desc: 'MySQL Database' },
  { port: 3389, protocol: 'TCP', service: 'RDP', desc: 'Remote Desktop Protocol' },
  { port: 5432, protocol: 'TCP', service: 'PostgreSQL', desc: 'PostgreSQL Database' },
  { port: 5900, protocol: 'TCP', service: 'VNC', desc: 'Virtual Network Computing' },
  { port: 6379, protocol: 'TCP', service: 'Redis', desc: 'Redis Database' },
  { port: 8080, protocol: 'TCP', service: 'HTTP-Alt', desc: 'HTTP Alternate/Proxy' },
  { port: 8443, protocol: 'TCP', service: 'HTTPS-Alt', desc: 'HTTPS Alternate' },
  { port: 27017, protocol: 'TCP', service: 'MongoDB', desc: 'MongoDB Database' },
];

type Props = {
  data: PortReferenceData | undefined;
  onChange: (next: PortReferenceData) => void;
};

const PortReferenceToolComponent = ({ data, onChange }: Props) => {
  const search = data?.search ?? '';

  const filtered = useMemo(() => {
    if (!search.trim()) return COMMON_PORTS;
    const q = search.toLowerCase();
    return COMMON_PORTS.filter(p =>
      p.port.toString().includes(q) ||
      p.service.toLowerCase().includes(q) ||
      p.desc.toLowerCase().includes(q)
    );
  }, [search]);

  return (
    <div className="space-y-3">
      <div className="text-xs text-slate-200">Port Number Reference</div>

      <input
        type="text"
        value={search}
        onChange={(e) => onChange({ ...data, search: e.target.value })}
        className="w-full rounded bg-slate-800 text-slate-200 text-xs px-2 py-2 border border-slate-700 focus:outline-none focus:border-emerald-500"
        placeholder="Search ports, services..."
      />

      <div className="overflow-y-auto max-h-56">
        <table className="w-full text-[10px]">
          <thead className="bg-slate-800 sticky top-0">
            <tr>
              <th className="px-2 py-1 text-left text-slate-400">Port</th>
              <th className="px-2 py-1 text-left text-slate-400">Proto</th>
              <th className="px-2 py-1 text-left text-slate-400">Service</th>
              <th className="px-2 py-1 text-left text-slate-400">Description</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((p) => (
              <tr key={p.port} className="hover:bg-slate-700">
                <td className="px-2 py-1 text-emerald-400 font-mono">{p.port}</td>
                <td className="px-2 py-1 text-cyan-400">{p.protocol}</td>
                <td className="px-2 py-1 text-slate-200">{p.service}</td>
                <td className="px-2 py-1 text-slate-400 truncate max-w-[120px]">{p.desc}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="text-[10px] text-slate-500">
        Common TCP/UDP port numbers and their associated services.
      </div>
    </div>
  );
};

export class PortReferenceTool {
  static Component = PortReferenceToolComponent;
}
