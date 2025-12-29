const sqlKeywords = [
  'select',
  'from',
  'where',
  'and',
  'or',
  'group by',
  'order by',
  'limit',
  'offset',
  'join',
  'left join',
  'right join',
  'inner join',
  'outer join',
  'on',
  'values',
  'insert',
  'update',
  'delete'
];

export const formatSql = (input: string) => {
  let sql = input.trim().replace(/\s+/g, ' ');
  sqlKeywords.forEach((keyword) => {
    const regex = new RegExp(`\\b${keyword}\\b`, 'gi');
    sql = sql.replace(regex, keyword.toUpperCase());
  });
  sql = sql.replace(/\b(FROM|WHERE|GROUP BY|ORDER BY|LIMIT|OFFSET|JOIN|LEFT JOIN|RIGHT JOIN|INNER JOIN|OUTER JOIN)\b/g, '\n$1');
  return sql.trim();
};

export type SqlQueryConfig = {
  table: string;
  columns: string[];
  where: string;
  orderBy: string;
  limit: string;
};

export const buildSqlQuery = (config: SqlQueryConfig) => {
  const columns = config.columns.length ? config.columns.join(', ') : '*';
  let query = `SELECT ${columns} FROM ${config.table || 'table_name'}`;
  if (config.where.trim()) {
    query += ` WHERE ${config.where}`;
  }
  if (config.orderBy.trim()) {
    query += ` ORDER BY ${config.orderBy}`;
  }
  if (config.limit.trim()) {
    query += ` LIMIT ${config.limit}`;
  }
  return query;
};

export const jsonArrayToCsv = (value: unknown) => {
  if (!Array.isArray(value)) return '';
  const rows = value.filter((entry) => entry && typeof entry === 'object') as Record<
    string,
    unknown
  >[];
  const headers = Array.from(
    rows.reduce((set, row) => {
      Object.keys(row).forEach((key) => set.add(key));
      return set;
    }, new Set<string>())
  );
  const escape = (input: string) => `"${input.replace(/"/g, '""')}"`;
  const lines = [
    headers.map(escape).join(','),
    ...rows.map((row) =>
      headers.map((header) => escape(String(row[header] ?? ''))).join(',')
    )
  ];
  return lines.join('\n');
};

export const suggestIndex = (table: string, columns: string[], unique: boolean) => {
  if (!table.trim() || columns.length === 0) return '';
  const indexName = `${table}_${columns.join('_')}_${unique ? 'uniq' : 'idx'}`;
  return `CREATE ${unique ? 'UNIQUE ' : ''}INDEX ${indexName} ON ${table} (${columns.join(
    ', '
  )});`;
};

export const normalizeBsonValue = (value: unknown): unknown => {
  if (!value || typeof value !== 'object') return value;
  if ('$numberInt' in (value as Record<string, unknown>)) {
    return Number((value as Record<string, string>).$numberInt);
  }
  if ('$numberLong' in (value as Record<string, unknown>)) {
    return Number((value as Record<string, string>).$numberLong);
  }
  if ('$date' in (value as Record<string, unknown>)) {
    return (value as Record<string, string>).$date;
  }
  if (Array.isArray(value)) {
    return value.map(normalizeBsonValue);
  }
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, val]) => [
      key,
      normalizeBsonValue(val)
    ])
  );
};

export const toDynamo = (value: unknown): unknown => {
  if (value === null || value === undefined) return { NULL: true };
  if (Array.isArray(value)) return { L: value.map(toDynamo) };
  switch (typeof value) {
    case 'string':
      return { S: value };
    case 'number':
      return { N: value.toString() };
    case 'boolean':
      return { BOOL: value };
    case 'object':
      return {
        M: Object.fromEntries(
          Object.entries(value as Record<string, unknown>).map(([key, val]) => [
            key,
            toDynamo(val)
          ])
        )
      };
    default:
      return { S: String(value) };
  }
};

export const fromDynamo = (value: unknown): unknown => {
  if (!value || typeof value !== 'object') return value;
  const record = value as Record<string, unknown>;
  if ('S' in record) return record.S;
  if ('N' in record) return Number(record.N);
  if ('BOOL' in record) return Boolean(record.BOOL);
  if ('NULL' in record) return null;
  if ('L' in record && Array.isArray(record.L)) return record.L.map(fromDynamo);
  if ('M' in record && typeof record.M === 'object') {
    return Object.fromEntries(
      Object.entries(record.M as Record<string, unknown>).map(([key, val]) => [
        key,
        fromDynamo(val)
      ])
    );
  }
  return value;
};

export const lintFirebaseRules = (raw: unknown) => {
  const warnings: string[] = [];
  if (!raw || typeof raw !== 'object') {
    return ['Rules must be a JSON object.'];
  }
  if (!('rules' in (raw as Record<string, unknown>))) {
    warnings.push('Root "rules" property is missing.');
  }
  const scan = (node: unknown, path: string) => {
    if (!node || typeof node !== 'object') return;
    Object.entries(node as Record<string, unknown>).forEach(([key, value]) => {
      const nextPath = `${path}/${key}`;
      if (key === '.read' || key === '.write') {
        if (value === true) {
          warnings.push(`${nextPath} is set to true (public).`);
        }
      }
      scan(value, nextPath);
    });
  };
  scan(raw, '$');
  return warnings.length ? warnings : ['No obvious issues found.'];
};
