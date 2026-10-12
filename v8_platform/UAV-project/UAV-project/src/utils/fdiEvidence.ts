import type { PacketAccounting, SecurityReport } from '@/api'
import { messageReport } from './messageEvidence'

/** Join simulator modifications to online reports only through their real source event IDs. */
export function fdiEvidence(accounting: PacketAccounting | null, reports: SecurityReport[]) {
  const causal = accounting?.causal_evidence
  return [...(causal?.mutations ?? [])].sort((a, b) => a.modified_time_s - b.modified_time_s || a.message_id.localeCompare(b.message_id)).map((mutation) => {
    const report = messageReport(accounting, reports, mutation.message_id)
    const interception = causal?.interceptions?.find(item => item.message_id === mutation.message_id) ?? null
    const derivation = causal?.derivations?.find(item => item.copy.message_id === mutation.message_id) ?? null
    const transmission = causal?.transmissions?.find(item => item.message_id === mutation.message_id) ?? null
    return { ...mutation, report, interception, derivation, transmission }
  })
}
