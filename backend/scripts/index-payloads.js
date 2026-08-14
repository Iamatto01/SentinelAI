#!/usr/bin/env node
/**
 * CLI: build / rebuild the PayloadsAllTheThings FTS5 RAG index.
 * Usage: node backend/scripts/index-payloads.js
 */
import { payloadsRag } from '../src/integrations/index.js'

console.log('[index] Building PayloadsAllTheThings RAG index...')
const status = payloadsRag.payloadsIndexStatus()
if (!status.installed) {
  console.error(`[index] corpus not found at ${status.path}`)
  process.exit(1)
}
const r = payloadsRag.buildPayloadIndex((lvl, msg) => console.log(`[index] ${msg}`))
console.log(`[index] done — ${r.indexed} documents indexed`)
