interface Point { x: number; y: number }

// Clip along the true Bezier endpoint tangents. This only moves the visible
// ink outside node halos; semantic source/target and anchors stay unchanged.
export function visibleQuadraticPath(a: Point, b: Point, control: Point, sourceRadius = 43, targetRadius = 43): string {
  const sourceLength = Math.max(1, Math.hypot(control.x - a.x, control.y - a.y))
  const targetLength = Math.max(1, Math.hypot(b.x - control.x, b.y - control.y))
  const startX = a.x + (control.x - a.x) / sourceLength * sourceRadius
  const startY = a.y + (control.y - a.y) / sourceLength * sourceRadius
  const endX = b.x - (b.x - control.x) / targetLength * targetRadius
  const endY = b.y - (b.y - control.y) / targetLength * targetRadius
  return `M${startX} ${startY} Q${control.x} ${control.y} ${endX} ${endY}`
}
