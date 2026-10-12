export class ApiError extends Error {
  constructor(status, message = 'controlled business error') { super(message); this.status = status }
}
const call = (name, ...args) => globalThis.__presentationApi[name](...args)
export const getRuntime = (...args) => call('getRuntime', ...args)
export const getCurrentRun = () => call('getCurrentRun')
export const getEvaluation = () => call('getEvaluation')
export const getHealth = () => call('getHealth')
export const createRun = (...args) => call('createRun', ...args)
export const startRun = () => call('startRun')
export const pauseRun = () => call('pauseRun')
export const resetRun = () => call('resetRun')
export const resumeRun = () => call('resumeRun')
export const stopRun = () => call('stopRun')
