export type ScraperFieldSource = 'text' | 'html' | 'attr' | 'regex';
export type ScraperFieldMode = 'single' | 'list';

export type ScraperField = {
  id: string;
  name: string;
  selector: string;
  xpath: string;
  mode: ScraperFieldMode;
  source: ScraperFieldSource;
  attrName?: string;
  regex?: string;
  regexFlags?: string;
};

export type ScraperDefinition = {
  id: string;
  name: string;
  fields: ScraperField[];
  createdAt: number;
  updatedAt: number;
};

export type ScraperDraft = {
  name: string;
  fields: ScraperField[];
  isPicking: boolean;
};

export type ScraperRunResult = Record<string, string | string[]>;

const safeCssEscape = (value: string) => {
  if (typeof CSS !== 'undefined' && typeof CSS.escape === 'function') {
    return CSS.escape(value);
  }
  return value.replace(/[^a-zA-Z0-9_-]/g, '\\$&');
};

export const generateCssSelector = (element: Element): string => {
  if (element.id) {
    return `#${safeCssEscape(element.id)}`;
  }

  const segments: string[] = [];
  let current: Element | null = element;
  while (current && current.nodeType === 1 && current.tagName.toLowerCase() !== 'html') {
    const tag = current.tagName.toLowerCase();
    const classList = Array.from(current.classList).filter(Boolean).slice(0, 2);
    let segment = tag;
    if (classList.length) {
      segment += `.${classList.map(safeCssEscape).join('.')}`;
    }
    const parent = current.parentElement;
    if (parent) {
      const siblings = Array.from(parent.children).filter(
        (child) => child.tagName === current!.tagName
      );
      if (siblings.length > 1) {
        const index = siblings.indexOf(current) + 1;
        segment += `:nth-of-type(${index})`;
      }
    }
    segments.unshift(segment);
    current = current.parentElement;
  }
  return segments.join(' > ');
};

export const generateXPath = (element: Element): string => {
  if (element.id) {
    return `//*[@id="${element.id}"]`;
  }
  const segments: string[] = [];
  let current: Element | null = element;
  while (current && current.nodeType === 1) {
    const tag = current.tagName.toLowerCase();
    const parent = current.parentElement;
    if (!parent) break;
    const siblings = Array.from(parent.children).filter(
      (child) => child.tagName.toLowerCase() === tag
    );
    const index = siblings.indexOf(current) + 1;
    segments.unshift(`${tag}[${index}]`);
    current = parent;
    if (current.tagName.toLowerCase() === 'html') {
      segments.unshift('html[1]');
      break;
    }
  }
  return `/${segments.join('/')}`;
};

export const buildScraperId = () =>
  typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `scraper_${Date.now()}_${Math.random().toString(16).slice(2)}`;

export const normalizeScrapers = (value: unknown): ScraperDefinition[] => {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => {
      if (!entry || typeof entry !== 'object') return null;
      const candidate = entry as Partial<ScraperDefinition>;
      if (!candidate.id || !candidate.name || !Array.isArray(candidate.fields)) {
        return null;
      }
      const fields = candidate.fields
        .map((field) => {
          if (!field || typeof field !== 'object') return null;
          const candidateField = field as Partial<ScraperField>;
          if (
            !candidateField.id ||
            !candidateField.name ||
            !candidateField.selector ||
            !candidateField.xpath ||
            !candidateField.mode ||
            !candidateField.source
          ) {
            return null;
          }
          return {
            id: candidateField.id,
            name: candidateField.name,
            selector: candidateField.selector,
            xpath: candidateField.xpath,
            mode: candidateField.mode,
            source: candidateField.source,
            attrName: candidateField.attrName ?? undefined,
            regex: typeof candidateField.regex === 'string' ? candidateField.regex : undefined,
            regexFlags:
              typeof candidateField.regexFlags === 'string'
                ? candidateField.regexFlags
                : undefined
          };
        })
        .filter((field): field is ScraperField => Boolean(field));
      return {
        id: candidate.id,
        name: candidate.name,
        fields,
        createdAt: candidate.createdAt ?? Date.now(),
        updatedAt: candidate.updatedAt ?? Date.now()
      };
    })
    .filter((entry): entry is ScraperDefinition => Boolean(entry));
};

export const normalizeScraperDraft = (value: unknown): ScraperDraft => {
  if (!value || typeof value !== 'object') {
    return { name: '', fields: [], isPicking: false };
  }
  const candidate = value as Partial<ScraperDraft>;
  return {
    name: typeof candidate.name === 'string' ? candidate.name : '',
    fields: normalizeScrapers([{ id: 'draft', name: 'draft', fields: candidate.fields ?? [] }])[0]
      ?.fields ?? [],
    isPicking: Boolean(candidate.isPicking)
  };
};

export const extractScraperResults = (
  documentRef: Document,
  scraper: ScraperDefinition
): ScraperRunResult => {
  const result: ScraperRunResult = {};
  scraper.fields.forEach((field) => {
    if (field.source === 'regex') {
      const text = documentRef.body?.innerText ?? '';
      if (!field.regex) {
        result[field.name] = field.mode === 'list' ? [] : '';
        return;
      }
      let regex: RegExp | null = null;
      try {
        regex = new RegExp(field.regex, field.regexFlags ?? '');
      } catch {
        result[field.name] = field.mode === 'list' ? [] : '';
        return;
      }
      if (field.mode === 'list') {
        const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
        const globalRegex = new RegExp(regex.source, flags);
        const matches: string[] = [];
        let match = globalRegex.exec(text);
        while (match) {
          matches.push(match[1] ?? match[0]);
          match = globalRegex.exec(text);
        }
        result[field.name] = matches;
      } else {
        const match = regex.exec(text);
        result[field.name] = match ? match[1] ?? match[0] : '';
      }
      return;
    }

    const nodes = Array.from(documentRef.querySelectorAll(field.selector));
    const extractValue = (el: Element) => {
      if (field.source === 'html') return el.innerHTML;
      if (field.source === 'attr') {
        return field.attrName ? el.getAttribute(field.attrName) ?? '' : '';
      }
      return el.textContent?.trim() ?? '';
    };
    if (field.mode === 'list') {
      result[field.name] = nodes.map(extractValue).filter(Boolean);
    } else {
      result[field.name] = nodes[0] ? extractValue(nodes[0]) : '';
    }
  });
  return result;
};

export const buildCsvFromResults = (results: ScraperRunResult) => {
  const headers = Object.keys(results);
  const values = headers.map((header) => {
    const value = results[header];
    if (Array.isArray(value)) return value.join(' | ');
    return value ?? '';
  });
  const escape = (value: string) => `"${value.replace(/"/g, '""')}"`;
  return `${headers.map(escape).join(',')}\n${values.map(escape).join(',')}`;
};

export const getRegexMatchCount = (
  text: string,
  pattern: string,
  flags: string
) => {
  if (!pattern.trim()) return { count: 0, error: null, capped: false };
  let regex: RegExp;
  try {
    regex = new RegExp(pattern, flags);
  } catch (error) {
    return {
      count: 0,
      error: error instanceof Error ? error.message : 'Invalid regex',
      capped: false
    };
  }
  const hasGlobal = regex.flags.includes('g');
  const globalRegex = hasGlobal ? regex : new RegExp(regex.source, `${regex.flags}g`);
  let count = 0;
  const limit = 5000;
  let match = globalRegex.exec(text);
  while (match) {
    count += 1;
    if (count >= limit) {
      return { count, error: null, capped: true };
    }
    match = globalRegex.exec(text);
  }
  return { count, error: null, capped: false };
};
