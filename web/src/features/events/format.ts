export function utcTime(value: string, includeZone = true): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, includeZone ? ' UTC' : '');
}
