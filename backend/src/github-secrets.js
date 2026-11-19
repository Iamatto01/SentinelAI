import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { config } from './config.js'

const KEY = createHash('sha256').update(config.jwt.secret).digest()
const PREFIX = 'v1:'

export function encryptGitHubToken(token) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', KEY, iv)
  const ciphertext = Buffer.concat([cipher.update(String(token), 'utf8'), cipher.final()])
  return `${PREFIX}${iv.toString('base64url')}:${ciphertext.toString('base64url')}:${cipher.getAuthTag().toString('base64url')}`
}

export function decryptGitHubToken(value) {
  const raw = String(value || '')
  if (!raw) return ''
  if (!raw.startsWith(PREFIX)) return raw
  const [, ivText, ciphertextText, tagText] = raw.split(':')
  if (!ivText || !ciphertextText || !tagText) throw new Error('invalid encrypted GitHub token')
  const decipher = createDecipheriv('aes-256-gcm', KEY, Buffer.from(ivText, 'base64url'))
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'))
  return Buffer.concat([decipher.update(Buffer.from(ciphertextText, 'base64url')), decipher.final()]).toString('utf8')
}

export default { encryptGitHubToken, decryptGitHubToken }
