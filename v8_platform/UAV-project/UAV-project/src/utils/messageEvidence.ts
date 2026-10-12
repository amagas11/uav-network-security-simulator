import type { PacketAccounting, SecurityReport } from '@/api'

export function messageReport(accounting: PacketAccounting | null, reports: SecurityReport[], messageId: string) {
  const ids = new Set((accounting?.causal_evidence?.security_observations ?? [])
    .filter(event => event.message_id === messageId).map(event => event.event_id))
  return reports.find(report => report.category === 'AUTH_FAILURE'
    && report.source_event_ids?.some(id => ids.has(id))) ?? null
}

export function spoofingEvidence(accounting: PacketAccounting | null, reports: SecurityReport[]) {
  const causal = accounting?.causal_evidence
  return [...(causal?.derivations ?? [])]
    .sort((a,b) => a.modified_time_s-b.modified_time_s || a.copy.message_id.localeCompare(b.copy.message_id))
    .map(item => ({ ...item,
      transmission: causal?.transmissions?.find(tx => tx.message_id === item.copy.message_id) ?? null,
      report: messageReport(accounting,reports,item.copy.message_id),
    }))
}

export function eavesBusinessSets(accounting: PacketAccounting | null) {
  const c = accounting?.causal_evidence
  if (!c?.generations || !c.transmissions || !c.captures) return null
  const generated = new Set(c.generations.map(m => m.message_id))
  const sent = new Set(c.transmissions.filter(t => t.hop_index === 0 && generated.has(t.message_id)).map(t => t.message_id))
  const captured = new Set(c.captures.filter(t => t.family === 'EAVESDROPPING' && t.sensitive && t.encrypted).map(t => t.message_id))
  const withheld = [...generated].filter(id => !sent.has(id)).map(id => ({ id,
    reason: c.security_observations?.find(o => o.extensions?.crypto_send_failure?.withheld_message_ref === id)?.extensions?.crypto_send_failure?.error_code ?? '未核实',
  }))
  return { generated, sent, captured, withheld, sentNotCaptured: [...sent].filter(id => !captured.has(id)),
    controlFrames: c.captures.filter(f => f.family === 'EAVESDROPPING' && !f.sensitive && !f.encrypted && f.packet_type === 'SKG_CONTROL'),
  }
}
