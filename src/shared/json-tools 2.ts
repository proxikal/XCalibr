export type JsonSchemaValidationIssue = {
  path: string;
  message: string;
};

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

const matchesType = (value: unknown, type: string) => {
  switch (type) {
    case 'string':
      return typeof value === 'string';
    case 'number':
      return typeof value === 'number' && !Number.isNaN(value);
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'object':
      return isObject(value);
    case 'array':
      return Array.isArray(value);
    case 'null':
      return value === null;
    default:
      return true;
  }
};

export const validateJsonSchema = (
  schema: unknown,
  data: unknown,
  path = '$'
): JsonSchemaValidationIssue[] => {
  if (!isObject(schema)) {
    return [{ path, message: 'Schema must be an object.' }];
  }

  const issues: JsonSchemaValidationIssue[] = [];
  const schemaType = typeof schema.type === 'string' ? schema.type : null;
  if (schemaType && !matchesType(data, schemaType)) {
    issues.push({
      path,
      message: `Expected ${schemaType} but found ${Array.isArray(data) ? 'array' : typeof data}.`
    });
    return issues;
  }

  if (schema.enum && Array.isArray(schema.enum)) {
    const matches = schema.enum.some((entry) => entry === data);
    if (!matches) {
      issues.push({ path, message: `Value must be one of: ${schema.enum.join(', ')}` });
    }
  }

  if (schemaType === 'string' && typeof data === 'string') {
    if (typeof schema.minLength === 'number' && data.length < schema.minLength) {
      issues.push({ path, message: `Minimum length is ${schema.minLength}.` });
    }
    if (typeof schema.maxLength === 'number' && data.length > schema.maxLength) {
      issues.push({ path, message: `Maximum length is ${schema.maxLength}.` });
    }
  }

  if (schemaType === 'object' && isObject(data)) {
    const required = Array.isArray(schema.required) ? schema.required : [];
    required.forEach((key) => {
      if (!(key in data)) {
        issues.push({ path: `${path}.${key}`, message: 'Field is required.' });
      }
    });

    if (schema.properties && isObject(schema.properties)) {
      Object.entries(schema.properties).forEach(([key, value]) => {
        if (key in data) {
          issues.push(...validateJsonSchema(value, data[key], `${path}.${key}`));
        }
      });
    }
  }

  if (schemaType === 'array' && Array.isArray(data)) {
    if (schema.items) {
      data.forEach((entry, index) => {
        issues.push(...validateJsonSchema(schema.items, entry, `${path}[${index}]`));
      });
    }
  }

  return issues;
};

export const parseJsonPath = (path: string): Array<string | number> => {
  const trimmed = path.trim();
  if (!trimmed.startsWith('$')) return [];
  const tokens: Array<string | number> = [];
  let buffer = '';
  for (let i = 1; i < trimmed.length; i += 1) {
    const char = trimmed[i];
    if (char === '.') {
      if (buffer) {
        tokens.push(buffer);
        buffer = '';
      }
      continue;
    }
    if (char === '[') {
      if (buffer) {
        tokens.push(buffer);
        buffer = '';
      }
      const end = trimmed.indexOf(']', i);
      if (end === -1) break;
      const content = trimmed.slice(i + 1, end).trim();
      if (content.startsWith("'") || content.startsWith('"')) {
        tokens.push(content.slice(1, -1));
      } else if (content.length) {
        const index = Number(content);
        tokens.push(Number.isNaN(index) ? content : index);
      }
      i = end;
      continue;
    }
    buffer += char;
  }
  if (buffer) tokens.push(buffer);
  return tokens;
};

export const resolveJsonPath = (data: unknown, path: string) => {
  const tokens = parseJsonPath(path);
  return tokens.reduce<unknown>((acc, token) => {
    if (acc === null || acc === undefined) return undefined;
    if (typeof token === 'number' && Array.isArray(acc)) {
      return acc[token];
    }
    if (typeof token === 'string' && typeof acc === 'object') {
      return (acc as Record<string, unknown>)[token];
    }
    return undefined;
  }, data);
};

export const diffJson = (
  left: unknown,
  right: unknown,
  path = '$'
): string[] => {
  if (Object.is(left, right)) return [];
  if (Array.isArray(left) && Array.isArray(right)) {
    const max = Math.max(left.length, right.length);
    const diffs: string[] = [];
    for (let i = 0; i < max; i += 1) {
      diffs.push(...diffJson(left[i], right[i], `${path}[${i}]`));
    }
    return diffs;
  }
  if (isObject(left) && isObject(right)) {
    const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
    const diffs: string[] = [];
    keys.forEach((key) => {
      diffs.push(...diffJson(left[key], right[key], `${path}.${key}`));
    });
    return diffs;
  }
  return [`${path}: ${JSON.stringify(left)} → ${JSON.stringify(right)}`];
};
