import type { OnlineEvent } from '@/api'

export interface RuntimeCumulativeCounters {
  acceptedTotal: number
  gcsLocalHmacRejectedTotal: number
  gcsLocalReplayRejectedTotal: number
}

export function createRuntimeCumulativeCounters(): RuntimeCumulativeCounters {
  return {
    acceptedTotal: 0,
    gcsLocalHmacRejectedTotal: 0,
    gcsLocalReplayRejectedTotal: 0,
  }
}

/**
 * Accumulate run-since-start totals from the newly returned cursor delta.
 * The retained event list is deliberately not involved: it may be capped for
 * presentation without changing these totals.
 */
export function accumulateRuntimeEvents(
  current: RuntimeCumulativeCounters,
  incoming: OnlineEvent[],
  processedEventIds: Set<string>,
): RuntimeCumulativeCounters {
  const next = { ...current }

  for (const event of incoming) {
    if (!event.event_id || processedEventIds.has(event.event_id)) continue
    processedEventIds.add(event.event_id)
    if (event.event_type !== 'AUTH_RESULT') continue

    const state = event.online_features.security_state
    const hmacResult = state?.application_hmac_result
    const replayResult = state?.replay_check_result

    if (hmacResult === 'PASS' && replayResult === 'PASS') next.acceptedTotal += 1
    if (hmacResult && !['PASS', 'NOT_APPLICABLE', 'UNAVAILABLE'].includes(hmacResult)) {
      next.gcsLocalHmacRejectedTotal += 1
    }
    if (replayResult && !['PASS', 'UNAVAILABLE'].includes(replayResult)) {
      next.gcsLocalReplayRejectedTotal += 1
    }
  }

  return next
}
