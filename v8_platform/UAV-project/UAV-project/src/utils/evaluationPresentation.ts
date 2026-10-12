// Lifecycle presentation only; never a detector or cryptographic proof.
export function eavesProtectionPresentation(
  matches: boolean, lifecycle: string | null | undefined,
  evaluationState: string, effective: boolean | null | undefined,
) {
  if (!matches) return { label: '等待场景', tone: 'neutral' as const }
  if (lifecycle === 'COMPLETED' && typeof effective === 'boolean') {
    return effective
      ? { label: '保密保护有效', tone: 'success' as const }
      : { label: '保密保护未达到', tone: 'danger' as const }
  }
  if (lifecycle === 'COMPLETED') return {
    label: evaluationState === 'ERROR' ? '离线评价暂不可用' : evaluationState === 'READY' ? '保密保护结果 —' : '等待离线评价',
    tone: 'neutral' as const,
  }
  if (lifecycle === 'RUNNING') return { label: '保密流程运行中', tone: 'info' as const }
  if (lifecycle === 'PAUSED') return { label: '保密流程已暂停', tone: 'neutral' as const }
  if (lifecycle === 'STOPPED') return { label: '保密流程已停止', tone: 'neutral' as const }
  return { label: '等待启动', tone: 'neutral' as const }
}
