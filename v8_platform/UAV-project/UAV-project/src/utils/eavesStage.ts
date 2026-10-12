import type { PacketAccounting } from '@/api'

/** Progress from actual transmissions, never elapsed time or provider names. */
export function eavesStageFromEvidence(state: string | undefined, accounting: PacketAccounting | null, evaluated: boolean): number {
  if (!state || state === 'INITIALIZED') return 0
  if (state === 'COMPLETED' && evaluated) return 4
  const transmissions = accounting?.causal_evidence?.transmissions ?? []
  if (transmissions.some(frame => frame.sensitive && frame.encrypted && frame.hop_index === 0)) return 3
  if (transmissions.some(frame => frame.packet_type === 'SKG_CONTROL')) return 2
  return ['RUNNING', 'PAUSED', 'STOPPED', 'COMPLETED'].includes(state) ? 1 : 0
}
