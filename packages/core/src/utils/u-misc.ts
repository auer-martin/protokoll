export const uriEncodeObject = (obj: Record<string, unknown>) => {
  return Object.entries(obj)
    .map(
      ([key, val]) =>
        `${key}=${encodeURIComponent(typeof val === 'string' || typeof val === 'boolean' || typeof val === 'number' ? val : encodeURIComponent(JSON.stringify(val as Record<string, unknown>)))}`
    )
    .join('&');
};

export function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && !Array.isArray(value) && typeof value === 'object';
}
