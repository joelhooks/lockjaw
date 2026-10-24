export const patternCovers = (parent: string, child: string): boolean =>
  parent.endsWith("*")
    ? child.startsWith(parent.slice(0, -1))
    : parent === child;

export const nameMatches = (pattern: string, name: string): boolean =>
  patternCovers(pattern, name);
