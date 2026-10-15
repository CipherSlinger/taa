interface Point {
  x: number;
  y: number;
}

export function mean(values: number[]): number {
  if (values.length === 0) {
    return 0;
  }
  let total = 0;
  for (const v of values) {
    total += v;
  }
  return total / values.length;
}

export function describe(point: Point): string {
  return `(${point.x.toFixed(2)}, ${point.y.toFixed(2)})`;
}

export function normalize(values: number[]): number[] {
  const m = mean(values);
  return values.map((v) => (m === 0 ? 0 : v / m));
}
