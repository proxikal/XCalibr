export const decodeJwt = (token: string) => {
  const parts = token.split('.');
  if (parts.length < 2) {
    return { header: null, payload: null, signature: parts[2] ?? null, error: 'Invalid JWT' };
  }
  const decodePart = (value: string) => {
    try {
      const padded = value.padEnd(Math.ceil(value.length / 4) * 4, '=');
      const decoded = atob(padded.replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(decoded);
    } catch {
      return null;
    }
  };
  const header = decodePart(parts[0]);
  const payload = decodePart(parts[1]);
  return { header, payload, signature: parts[2] ?? null, error: null };
};

export const parseCookieString = (value: string) =>
  value
    .split(';')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const index = entry.indexOf('=');
      if (index === -1) return { name: entry, value: '' };
      return { name: entry.slice(0, index), value: entry.slice(index + 1) };
    });

const clamp = (value: number, min: number, max: number) =>
  Math.min(Math.max(value, min), max);

export const hexToRgbValues = (hex: string) => {
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

const relativeLuminance = (value: number) => {
  const channel = value / 255;
  return channel <= 0.03928
    ? channel / 12.92
    : Math.pow((channel + 0.055) / 1.055, 2.4);
};

export const contrastRatio = (foreground: string, background: string) => {
  const fg = hexToRgbValues(foreground);
  const bg = hexToRgbValues(background);
  if (!fg || !bg) return null;
  const l1 =
    0.2126 * relativeLuminance(fg.r) +
    0.7152 * relativeLuminance(fg.g) +
    0.0722 * relativeLuminance(fg.b);
  const l2 =
    0.2126 * relativeLuminance(bg.r) +
    0.7152 * relativeLuminance(bg.g) +
    0.0722 * relativeLuminance(bg.b);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
};

export const optimizeSvg = (input: string) =>
  input
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/\s{2,}/g, ' ')
    .replace(/>\s+</g, '><')
    .trim();

export const auditAccessibility = (documentRef: Document) => {
  const issues: string[] = [];
  documentRef.querySelectorAll('img:not([alt])').forEach((img, index) => {
    issues.push(`Image missing alt text (#${index + 1}).`);
  });
  documentRef.querySelectorAll('button').forEach((button, index) => {
    if (!button.textContent?.trim()) {
      issues.push(`Button has no text (#${index + 1}).`);
    }
  });
  documentRef.querySelectorAll('input').forEach((input, index) => {
    if (!input.getAttribute('aria-label') && !input.getAttribute('aria-labelledby')) {
      issues.push(`Input missing label (#${index + 1}).`);
    }
  });
  return issues.length ? issues : ['No obvious issues found.'];
};

export const runRegexTest = (pattern: string, flags: string, text: string) => {
  try {
    const regex = new RegExp(pattern, flags);
    const matches = Array.from(text.matchAll(regex)).map((match) => match[0]);
    return { matches, error: null };
  } catch (error) {
    return {
      matches: [],
      error: error instanceof Error ? error.message : 'Invalid regex'
    };
  }
};

export const safeParseJson = (value: string) => {
  try {
    return { value: JSON.parse(value), error: null };
  } catch (error) {
    return {
      value: null,
      error: error instanceof Error ? error.message : 'Invalid JSON'
    };
  }
};
