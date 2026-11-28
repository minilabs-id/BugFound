export function formatCount(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatBudget(value: number): string {
  if (value === 0) return "unlimited";
  return formatCount(value);
}
