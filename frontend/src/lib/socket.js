import { io } from 'socket.io-client'
import { getToken } from './api.js'

let socket = null

/** Lazy singleton Socket.IO client. Rebuilds the socket when the JWT changes. */
export function getSocket() {
  const token = getToken()
  if (socket && socket.auth?.token !== token) {
    try { socket.close() } catch { /* ignore */ }
    socket = null
  }
  if (!socket) {
    socket = io('/', { auth: { token }, transports: ['websocket', 'polling'] })
    socket.auth = { token }
  }
  return socket
}

export function subscribeScan(scanId, handlers = {}) {
  const s = getSocket()
  // (Re)join the room on every (re)connect so updates resume after a drop.
  const join = () => s.emit('scan:subscribe', scanId)
  if (s.connected) join()
  s.on('connect', join)
  const onLog = (d) => d.scanId === scanId && handlers.onLog?.(d)
  const onFinding = (d) => d.scanId === scanId && handlers.onFinding?.(d)
  const onUpdate = (d) => d.scanId === scanId && handlers.onUpdate?.(d)
  const onDone = (d) => d.scanId === scanId && handlers.onDone?.(d)
  s.on('scan:log', onLog)
  s.on('scan:finding', onFinding)
  s.on('scan:update', onUpdate)
  s.on('scan:done', onDone)
  return () => {
    s.off('connect', join)
    s.emit('scan:unsubscribe', scanId)
    s.off('scan:log', onLog)
    s.off('scan:finding', onFinding)
    s.off('scan:update', onUpdate)
    s.off('scan:done', onDone)
  }
}

/** Subscribe to live exploit campaign events for a campaign. */
export function subscribeExploit(campaignId, handlers = {}) {
  const s = getSocket()
  const join = () => s.emit('exploit:subscribe', campaignId)
  if (s.connected) join()
  s.on('connect', join)
  const onCampaign = (d) => d.campaignId === campaignId && handlers.onCampaign?.(d)
  const onStep = (d) => d.campaignId === campaignId && handlers.onStep?.(d)
  const onLog = (d) => d.campaignId === campaignId && handlers.onLog?.(d)
  const onApproval = (d) => d.campaignId === campaignId && handlers.onApproval?.(d)
  const onSession = (d) => d.campaignId === campaignId && handlers.onSession?.(d)
  const onLoot = (d) => d.campaignId === campaignId && handlers.onLoot?.(d)
  const onPost = (d) => d.campaignId === campaignId && handlers.onPost?.(d)
  s.on('exploit:campaign', onCampaign)
  s.on('exploit:step', onStep)
  s.on('exploit:log', onLog)
  s.on('exploit:approval', onApproval)
  s.on('exploit:session', onSession)
  s.on('exploit:loot', onLoot)
  s.on('exploit:post', onPost)
  return () => {
    s.off('connect', join)
    s.emit('exploit:unsubscribe', campaignId)
    s.off('exploit:campaign', onCampaign)
    s.off('exploit:step', onStep)
    s.off('exploit:log', onLog)
    s.off('exploit:approval', onApproval)
    s.off('exploit:session', onSession)
    s.off('exploit:loot', onLoot)
    s.off('exploit:post', onPost)
  }
}

export default { getSocket, subscribeScan, subscribeExploit }
