import type { AttackSpec, TopologyLink, TopologyNode } from '@/api'
import type { PrimaryBusinessFlow } from './topologySemantics'

export type TopologyMode = 'overview' | 'spoofing' | 'fdi' | 'dos' | 'eavesdropping' | 'replay'

export interface SemanticNode extends TopologyNode {
  x: number
  y: number
  emphasis: 'primary' | 'context'
}

export interface SemanticLayout {
  nodes: SemanticNode[]
  sourceId: number | null
  targetId: number | null
  primaryFlow: PrimaryBusinessFlow | null
  attackerId: number | null
  airGroundDividerY: number | null
}

interface Point { x: number; y: number }

const role = (node: TopologyNode): string => String(node.role || '').toUpperCase()
const isExternal = (node: TopologyNode): boolean => role(node) === 'EXTERNAL'
const isGcs = (node: TopologyNode): boolean => role(node) === 'GCS'
const isLeader = (node: TopologyNode): boolean => role(node) === 'LEADER'
const isFollower = (node: TopologyNode): boolean => role(node) === 'FOLLOWER'
const sortById = <T extends TopologyNode>(nodes: T[]): T[] => [...nodes].sort((a, b) => a.id - b.id)

function spread(count: number, start: number, end: number): number[] {
  if (count <= 0) return []
  if (count === 1) return [(start + end) / 2]
  return Array.from({ length: count }, (_, index) => start + (end - start) * index / (count - 1))
}

/**
 * Nodes are real scenario entities.  A missing EXTERNAL node may be
 * materialised only when the attack plan explicitly names that participant.
 * No decorative UAV/server entity is created by the visual layer.
 */
export function materializeSceneNodes(
  topologyNodes: TopologyNode[],
  attackPlan: AttackSpec | null,
  showTruth: boolean,
): TopologyNode[] {
  const nodes = topologyNodes.map((node) => ({ ...node }))
  const attackerId = attackPlan?.attacker_node_id
  if (
    showTruth
    && typeof attackerId === 'number'
    && !nodes.some((node) => node.id === attackerId)
  ) {
    nodes.push({ id: attackerId, role: 'EXTERNAL', pos: null, position_available: false })
  }
  return showTruth ? nodes : nodes.filter((node) => !isExternal(node))
}

function findTarget(nodes: TopologyNode[], attackPlan: AttackSpec | null): TopologyNode | null {
  const configured = attackPlan?.target_node_ids?.[0]
  if (typeof configured === 'number') {
    const target = nodes.find((node) => node.id === configured)
    if (target) return target
  }
  return nodes.find(isLeader) ?? nodes.find((node) => !isExternal(node) && !isGcs(node)) ?? nodes[0] ?? null
}

function targetLinkSource(
  nodes: TopologyNode[],
  links: TopologyLink[],
  attackPlan: AttackSpec | null,
  targetId: number | null,
): TopologyNode | null {
  if (targetId === null) return null
  const configuredLinkIds = new Set(attackPlan?.target_link_ids ?? [])
  const linksByPriority = [
    ...links.filter((link) => configuredLinkIds.has(link.id)),
    ...links.filter((link) => !configuredLinkIds.has(link.id)),
  ]
  for (const link of linksByPriority) {
    const opposite = link.src === targetId ? link.dst : link.dst === targetId ? link.src : null
    if (opposite === null) continue
    const node = nodes.find((candidate) => candidate.id === opposite)
    if (node && !isExternal(node) && !isGcs(node)) return node
  }
  return null
}

function findSource(
  mode: TopologyMode,
  nodes: TopologyNode[],
  links: TopologyLink[],
  attackPlan: AttackSpec | null,
  targetId: number | null,
): TopologyNode | null {
  if (mode === 'fdi') {
    const configured = attackPlan?.attacker_node_id
    const source = nodes.find((node) => node.id === configured && !isExternal(node))
    if (source) return source
  }
  return targetLinkSource(nodes, links, attackPlan, targetId)
    ?? nodes.find((node) => node.id !== targetId && isFollower(node))
    ?? nodes.find((node) => node.id !== targetId && isLeader(node))
    ?? nodes.find((node) => node.id !== targetId && !isExternal(node))
    ?? null
}

function placeOverview(nodes: TopologyNode[], targetId: number | null): SemanticNode[] {
  const externals = sortById(nodes.filter(isExternal))
  const leaders = sortById(nodes.filter(isLeader))
  const followers = sortById(nodes.filter(isFollower))
  const ground = sortById(nodes.filter((node) => isGcs(node) || (!isExternal(node) && !isLeader(node) && !isFollower(node))))
  const result: SemanticNode[] = []
  const addRow = (row: TopologyNode[], xs: number[], y: number, emphasis: SemanticNode['emphasis'] = 'primary') => {
    row.forEach((node, index) => result.push({ ...node, x: xs[index] ?? 380, y, emphasis }))
  }

  addRow(leaders, spread(leaders.length, 310, 450), 75)
  const followerEnd = externals.length ? 570 : 660
  addRow(followers, spread(followers.length, 120, followerEnd), 185)
  addRow(ground, spread(ground.length, 250, 510), 306)
  externals.forEach((node, index) => result.push({ ...node, x: 670, y: 78 + index * 104, emphasis: 'primary' }))

  // Preserve unusual but real roles without inventing a replacement entity.
  const placed = new Set(result.map((node) => node.id))
  const remaining = nodes.filter((node) => !placed.has(node.id))
  addRow(remaining, spread(remaining.length, 130, 620), 225, 'context')
  return result.map((node) => ({ ...node, emphasis: node.id === targetId ? 'primary' : node.emphasis }))
}

const scenePoints: Record<Exclude<TopologyMode, 'overview'>, {
  source: Point
  target: Point
  attacker: Point
  context: Point[]
}> = {
  spoofing: {
    source: { x: 145, y: 88 }, target: { x: 380, y: 235 }, attacker: { x: 615, y: 88 },
    context: [{ x: 105, y: 292 }, { x: 655, y: 292 }, { x: 380, y: 75 }],
  },
  fdi: {
    source: { x: 140, y: 168 }, target: { x: 600, y: 168 }, attacker: { x: 140, y: 168 },
    context: [{ x: 370, y: 72 }, { x: 370, y: 294 }, { x: 675, y: 292 }, { x: 75, y: 292 }],
  },
  dos: {
    source: { x: 140, y: 82 }, target: { x: 575, y: 175 }, attacker: { x: 140, y: 270 },
    context: [{ x: 675, y: 82 }, { x: 675, y: 290 }, { x: 365, y: 302 }],
  },
  eavesdropping: {
    source: { x: 145, y: 105 }, target: { x: 585, y: 105 }, attacker: { x: 410, y: 276 },
    context: [{ x: 105, y: 292 }, { x: 665, y: 292 }, { x: 335, y: 298 }],
  },
  replay: {
    source: { x: 145, y: 95 }, target: { x: 585, y: 95 }, attacker: { x: 365, y: 280 },
    context: [{ x: 95, y: 292 }, { x: 660, y: 292 }, { x: 365, y: 190 }],
  },
}

function placeScenario(
  mode: Exclude<TopologyMode, 'overview'>,
  nodes: TopologyNode[],
  sourceId: number | null,
  targetId: number | null,
  attackerId: number | null,
): SemanticNode[] {
  const anchors = mode === 'fdi' && attackerId !== sourceId ? scenePoints.spoofing : scenePoints[mode]
  const occupied = new Set<number>()
  const result: SemanticNode[] = []
  const place = (id: number | null, point: Point, emphasis: SemanticNode['emphasis'] = 'primary') => {
    if (id === null || occupied.has(id)) return
    const node = nodes.find((candidate) => candidate.id === id)
    if (!node) return
    occupied.add(id)
    result.push({ ...node, ...point, emphasis })
  }

  place(sourceId, anchors.source)
  place(targetId, anchors.target)
  if (mode !== 'fdi' || attackerId !== sourceId) place(attackerId, anchors.attacker)

  const remaining = sortById(nodes.filter((node) => !occupied.has(node.id)))
  const ordered = [
    ...remaining.filter(isGcs),
    ...remaining.filter(isLeader),
    ...remaining.filter(isFollower),
    ...remaining.filter((node) => !isGcs(node) && !isLeader(node) && !isFollower(node)),
  ]
  ordered.forEach((node, index) => {
    const point = anchors.context[index] ?? {
      x: 90 + (index % 4) * 185,
      y: 300 - Math.floor(index / 4) * 58,
    }
    result.push({ ...node, ...point, emphasis: 'context' })
  })
  return result
}

export function buildSemanticLayout(
  mode: TopologyMode,
  nodes: TopologyNode[],
  links: TopologyLink[],
  attackPlan: AttackSpec | null,
  configuredPrimaryFlow: PrimaryBusinessFlow | null = null,
): SemanticLayout {
  const configuredSource = configuredPrimaryFlow
    ? nodes.find((node) => node.id === configuredPrimaryFlow.sourceId) ?? null
    : null
  const configuredTarget = configuredPrimaryFlow
    ? nodes.find((node) => node.id === configuredPrimaryFlow.targetId) ?? null
    : null
  const attackTarget = findTarget(nodes, attackPlan) ?? configuredTarget
  const targetId = attackTarget?.id ?? null
  const source = mode === 'overview'
    ? null
    : configuredSource ?? findSource(mode, nodes, links, attackPlan, targetId)
  const primaryTarget = mode === 'overview' ? null : configuredTarget ?? attackTarget
  const primaryFlow = source && primaryTarget
    ? { sourceId: source.id, targetId: primaryTarget.id }
    : null
  const attackerId = typeof attackPlan?.attacker_node_id === 'number'
    ? attackPlan.attacker_node_id
    : nodes.find(isExternal)?.id ?? null
  const positioned = mode === 'overview'
    ? placeOverview(nodes, targetId)
    : placeScenario(mode, nodes, source?.id ?? null, targetId, attackerId)
  return {
    nodes: positioned,
    sourceId: source?.id ?? null,
    targetId,
    primaryFlow,
    attackerId,
    airGroundDividerY: mode === 'overview' ? 250 : null,
  }
}

export function humanNodeName(node: TopologyNode): string {
  if (isGcs(node)) return node.id === 0 ? 'GCS' : `GCS ${node.id}`
  if (isLeader(node)) return `Leader ${node.id}`
  if (isExternal(node)) return node.id < 0 ? 'External' : `External ${node.id}`
  if (isFollower(node)) return `Follower ${node.id}`
  return `${node.role || 'Node'} ${node.id}`
}

export function humanRoleName(node: TopologyNode): string {
  if (isGcs(node)) return '地面站'
  if (isLeader(node)) return '领航机'
  if (isExternal(node)) return '攻击节点'
  if (isFollower(node)) return '跟随机'
  return String(node.role || '网络节点')
}
