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

export const defaultPayloads = [
  `"' OR '1'='1`,
  '<script>alert(1)</script>',
  '../../etc/passwd',
  '{{7*7}}',
  '${7*7}'
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

export const applyPayloadToForm = (formIndex: number, payload: string) => {
  const form = document.querySelectorAll('form')[formIndex];
  if (!form) return false;
  const fields = Array.from(
    form.querySelectorAll('input, textarea, select')
  ) as Array<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>;
  fields.forEach((field) => {
    if (field instanceof HTMLInputElement) {
      const type = field.type.toLowerCase();
      if (['checkbox', 'radio', 'submit', 'button', 'file'].includes(type)) {
        return;
      }
    }
    if (field instanceof HTMLSelectElement) {
      field.value = field.options[0]?.value ?? '';
    } else {
      field.value = payload;
    }
    field.dispatchEvent(new Event('input', { bubbles: true }));
    field.dispatchEvent(new Event('change', { bubbles: true }));
  });
  return true;
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
