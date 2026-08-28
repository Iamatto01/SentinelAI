import { nativeToolsStatus, NATIVE_TOOLS } from '../src/integrations/native-tools.js'
import { spawn } from 'node:child_process'

async function checkBin(bin) {
  return new Promise((resolve) => {
    const proc = spawn('which', [bin])
    proc.on('close', (code) => resolve(code === 0))
    proc.on('error', () => resolve(false))
  })
}

async function main() {
  console.log('=== CHECKING KALI LINUX SECURITY TOOLS ===')
  const status = await nativeToolsStatus()
  console.log('Native Tools mapped in SentinelAI Pipeline:')
  for (const [tool, present] of Object.entries(status)) {
    console.log(` - ${tool.padEnd(15)} : ${present ? '✅ INSTALLED & READY' : '❌ NOT FOUND'}`)
  }

  const otherFamousTools = [
    'msfconsole', 'hydra', 'hashcat', 'john', 'wpscan', 'amass', 'subfinder',
    'nuclei', 'katana', 'ffuf', 'gobuster', 'nikto', 'sqlmap', 'nmap',
    'semgrep', 'gitleaks', 'trufflehog', 'bandit', 'enum4linux', 'smbmap',
    'responder', 'crackmapexec', 'arjun', 'wafw00f', 'whatweb', 'dnsrecon',
    'rustscan', 'trivy', 'checkov'
  ]
  console.log('\nOther Kali Security & Pentest Tools on System:')
  for (const bin of otherFamousTools) {
    const found = await checkBin(bin)
    console.log(` - ${bin.padEnd(15)} : ${found ? '✅ INSTALLED' : '❌ NOT FOUND'}`)
  }
}

main().catch(console.error)
