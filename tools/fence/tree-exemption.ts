// oxlint-disable no-comments/no-comments -- .brain/projects/briefs/public-split.svx requires this temporary infra-only tree exclusion until ops moves private. Never exempt history.
export const treeExempt = (name: string): boolean => name.startsWith("infra/");
