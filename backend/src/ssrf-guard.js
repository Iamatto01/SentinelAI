import dns from 'node:dns/promises'
import net from 'node:net'

function isPrivateAddress(address) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split('.').map(Number)
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
  }
  if (net.isIPv6(address)) {
    const value = address.toLowerCase()
    return value === '::1' || value === '::' || value.startsWith('fc') ||
      value.startsWith('fd') || value.startsWith('fe80:')
  }
  return true
}

export async function assertPublicHttpUrl(rawUrl) {
  const url = new URL(String(rawUrl || ''))
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('only http(s) verification targets are allowed')
  if (url.username || url.password) throw new Error('verification target cannot contain credentials')
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (!hostname || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.internal')) {
    throw new Error('private verification host is not allowed')
  }
  const addresses = net.isIP(hostname) ? [hostname] : (await dns.lookup(hostname, { all: true, verbatim: true })).map(item => item.address)
  if (!addresses.length || addresses.some(isPrivateAddress)) throw new Error('verification target resolves to a private or local address')
  return { url, addresses }
}

export default { assertPublicHttpUrl }
